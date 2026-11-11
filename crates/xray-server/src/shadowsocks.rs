//! Inbound Shadowsocks proxy handler supporting AEAD ciphers for TCP and UDP.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use xray_config::Network;
use xray_proxy::shadowsocks::aead2017::UdpSession;
use xray_proxy::shadowsocks2022::ServerUdpSession;
use xray_routing::{Target, TargetAddr};

use crate::config::{ShadowsocksMethod, ShadowsocksUser};
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query};
use crate::stats;
use crate::vless::{read_first, Activity, Context, Host, RouteRequest};

pub async fn serve_tcp<S>(stream: S, ctx: &Context, peer: SocketAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let users = ctx
        .ss_users
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if users.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no shadowsocks users configured",
        ));
    }
    // The handshake index counts only users of the inbound's kind.
    let users = same_kind_users(users);
    let (mut client_r, mut client_w, user_idx, target, mut early) = match &users[0].method {
        ShadowsocksMethod::Ss2022(_) => {
            let methods: Vec<Arc<xray_proxy::shadowsocks2022::Method>> = users
                .iter()
                .filter_map(|u| match &u.method {
                    ShadowsocksMethod::Ss2022(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            let (server_stream, idx, target, early) = timeout(
                crate::policy::get().handshake,
                xray_proxy::shadowsocks2022::ServerStream::handshake_methods_with_pool(
                    stream,
                    &methods,
                    Some(&ctx.ss2022_salt_pool),
                ),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shadowsocks handshake timeout"))?
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("shadowsocks 2022 auth: {e}"),
                )
            })?;
            let (r, w) = tokio::io::split(server_stream);
            let r: Box<dyn AsyncRead + Unpin + Send> = Box::new(r);
            let w: Box<dyn AsyncWrite + Unpin + Send> = Box::new(w);
            (r, w, idx, target, early)
        }
        ShadowsocksMethod::Aead2017(_) => {
            let methods: Vec<Arc<xray_proxy::shadowsocks::aead2017::Method>> = users
                .iter()
                .filter_map(|u| match &u.method {
                    ShadowsocksMethod::Aead2017(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            let (server_stream, idx, target, early) = timeout(
                crate::policy::get().handshake,
                xray_proxy::shadowsocks::aead2017::ServerStream::handshake_methods(
                    stream, &methods,
                ),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shadowsocks handshake timeout"))?
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("shadowsocks auth: {e}"))
            })?;
            let (r, w) = tokio::io::split(server_stream);
            let r: Box<dyn AsyncRead + Unpin + Send> = Box::new(r);
            let w: Box<dyn AsyncWrite + Unpin + Send> = Box::new(w);
            (r, w, idx, target, early)
        }
    };

    let (email, level) = users
        .get(user_idx)
        .map(|u| (u.email.as_str(), u.level))
        .unwrap_or_default();
    let user_policy = crate::policy::for_level(level);
    let _online = stats::get().connect(email, level, peer.ip());

    if early.is_empty() && (ctx.router.needs_sniff() || ctx.sniffing.enabled()) {
        read_first(&mut client_r, &mut early).await;
    }
    let (mut host, port) = target_to_host_port(&target);
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email,
        peer,
        network: Network::Tcp,
        host: &host,
        port,
        sniffing: &ctx.sniffing,
    };
    let Some(decision) = route.allow(&ctx.router, &early).await else {
        return Ok(());
    };
    // Only blackhole's http response gets here; connect plays it back.
    ctx.sniffing.override_host(&early, &mut host);

    let mut outbound_stream = outbound::connect(&ctx.router, &decision, &host, port).await?;
    let traffic = stats::get().traffic(&ctx.tag, email, level, &decision.tag);
    if !early.is_empty() {
        outbound_stream.write_all(&early).await?;
        traffic.up(early.len());
    }

    let (mut target_r, mut target_w) = tokio::io::split(outbound_stream);

    let activity = Activity::new();
    crate::vless::relay_policy(
        crate::vless::copy_buf(
            &mut client_r,
            &mut target_w,
            &activity,
            |n| traffic.up(n),
            user_policy.buffer_size,
        ),
        crate::vless::copy_buf(
            &mut target_r,
            &mut client_w,
            &activity,
            |n| traffic.down(n),
            user_policy.buffer_size,
        ),
        &activity,
        user_policy,
    )
    .await
}

type UdpPacket = (Target, Vec<u8>);

struct UdpSessionEntry {
    id: u64,
    tx: mpsc::Sender<UdpPacket>,
}

/// Peer address, user (its key's identity) and 2022 client session ID (0 for
/// 2017): another user, or another session, from the same address never
/// lands in or replaces this one.
type SessionKey = (SocketAddr, usize, u64);
type SessionsMap = Arc<Mutex<HashMap<SessionKey, UdpSessionEntry>>>;

// Replay state outlives the per-peer session: the timestamp window is 30 s.
const REPLAY_KEEP: Duration = Duration::from_secs(120);
type ReplayMap = Arc<std::sync::Mutex<HashMap<(usize, u64), (Instant, ServerUdpSession)>>>;

struct UdpInit2022 {
    peer: SocketAddr,
    user: ShadowsocksUser,
    target: Target,
    payload: Vec<u8>,
    client_id: u64,
}

fn same_kind_users(users: Vec<ShadowsocksUser>) -> Vec<ShadowsocksUser> {
    let is_2022 = users
        .first()
        .is_some_and(|u| matches!(u.method, ShadowsocksMethod::Ss2022(_)));
    users
        .into_iter()
        .filter(|u| matches!(u.method, ShadowsocksMethod::Ss2022(_)) == is_2022)
        .collect()
}

async fn remove_session(sessions: &SessionsMap, key: SessionKey, id: u64) {
    let mut sessions = sessions.lock().await;
    if sessions.get(&key).is_some_and(|e| e.id == id) {
        sessions.remove(&key);
    }
}

#[derive(Clone)]
pub struct ShadowsocksUdpHandler {
    socket: Arc<UdpSocket>,
    ctx: Arc<Context>,
    sessions: SessionsMap,
    replay: ReplayMap,
    next_id: Arc<AtomicU64>,
}

impl ShadowsocksUdpHandler {
    pub fn new(socket: Arc<UdpSocket>, ctx: Arc<Context>) -> Self {
        Self {
            socket,
            ctx,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            replay: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn run(self) {
        let is_2022 = {
            let users = self
                .ctx
                .ss_users
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            users
                .first()
                .is_some_and(|u| matches!(u.method, ShadowsocksMethod::Ss2022(_)))
        };
        if is_2022 {
            self.run_2022().await;
        } else {
            self.run_2017().await;
        }
    }

    async fn run_2022(self) {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log::warn(format!("shadowsocks 2022 udp recv error: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let users = same_kind_users(
                self.ctx
                    .ss_users
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            );
            let methods: Vec<Arc<xray_proxy::shadowsocks2022::Method>> = users
                .iter()
                .filter_map(|u| match &u.method {
                    ShadowsocksMethod::Ss2022(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            let Ok((user_idx, target, payload, client_id, packet_id)) =
                ServerUdpSession::decode_request(&methods, &buf[..n])
            else {
                continue;
            };
            let Some(user) = users.get(user_idx).cloned() else {
                continue;
            };
            let ShadowsocksMethod::Ss2022(method) = &user.method else {
                continue;
            };
            let user_key = Arc::as_ptr(method) as usize;
            if !self.check_replay(user_key, client_id, packet_id, method) {
                continue;
            }

            let key = (peer, user_key, client_id);
            let mut sessions = self.sessions.lock().await;
            let mut packet = (target, payload);
            if let Some(entry) = sessions.get(&key) {
                // A full queue drops the datagram rather than stalling every session.
                match entry.tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    Err(mpsc::error::TrySendError::Closed(p)) => packet = p,
                }
                sessions.remove(&key);
            }
            let (target, payload) = packet;

            let (tx, rx) = mpsc::channel(128);
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            sessions.insert(key, UdpSessionEntry { id, tx });
            drop(sessions);

            let init = UdpInit2022 {
                peer,
                user,
                target,
                payload,
                client_id,
            };
            let handler = self.clone();
            tokio::spawn(async move {
                if let Err(e) = Box::pin(handler.serve_udp_session_2022(init, rx)).await {
                    log::debug(format!("shadowsocks 2022 udp session {peer} ended: {e}"));
                }
                remove_session(&handler.sessions, key, id).await;
            });
        }
    }

    fn check_replay(
        &self,
        user_key: usize,
        client_id: u64,
        packet_id: u64,
        method: &Arc<xray_proxy::shadowsocks2022::Method>,
    ) -> bool {
        let now = Instant::now();
        let mut map = self
            .replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !map.contains_key(&(user_key, client_id)) {
            if map.len() >= 256 {
                map.retain(|_, (seen, _)| now.duration_since(*seen) < REPLAY_KEEP);
            }
            let Ok(session) = ServerUdpSession::new(method.clone(), client_id) else {
                return false;
            };
            map.insert((user_key, client_id), (now, session));
        }
        let Some((seen, session)) = map.get_mut(&(user_key, client_id)) else {
            return false;
        };
        *seen = now;
        session.check_replay(packet_id)
    }

    async fn serve_udp_session_2022(
        &self,
        init: UdpInit2022,
        mut rx: mpsc::Receiver<UdpPacket>,
    ) -> io::Result<()> {
        let user_method = match &init.user.method {
            ShadowsocksMethod::Ss2022(m) => m.clone(),
            _ => return Ok(()),
        };
        let server_session = ServerUdpSession::new(user_method, init.client_id)?;

        let user_policy = crate::policy::for_level(init.user.level);
        let _online = stats::get().connect(&init.user.email, init.user.level, init.peer.ip());

        let (host, port) = target_to_host_port(&init.target);
        let route = RouteRequest {
            ctx_tag: &self.ctx.tag,
            inbound_port: self.ctx.port,
            email: &init.user.email,
            peer: init.peer,
            network: Network::Udp,
            host: &host,
            port,
            sniffing: &self.ctx.sniffing,
        };
        let Some(decision) = route.allow(&self.ctx.router, &init.payload).await else {
            return Ok(());
        };
        if let Action::Block(_) = decision.action {
            return Ok(());
        }
        let cone = ConeUdp::open(self.ctx.router.clone(), &decision).await?;
        let traffic = stats::get().traffic(
            &self.ctx.tag,
            &init.user.email,
            init.user.level,
            &decision.tag,
        );
        let activity = Activity::new();
        if let Ok(target) = cone.target(&host, port).await {
            if let Err(e) = cone.send_to(&init.payload, target).await {
                log::debug(format!("shadowsocks 2022 udp send error: {e}"));
            }
            traffic.up(init.payload.len());
        }

        let session_down = Mutex::new(server_session);

        let up = async {
            let proc_cell = std::sync::OnceLock::new();
            while let Some((target, payload)) = rx.recv().await {
                activity.touch();
                let (host, port) = target_to_host_port(&target);
                let query = Query {
                    inbound: &self.ctx.tag,
                    inbound_port: self.ctx.port,
                    user: &init.user.email,
                    source: init.peer,
                    network: Network::Udp,
                    domain: match &host {
                        Host::Domain(d) => Some(d.as_str()),
                        Host::Ip(_) => None,
                    },
                    ip: match &host {
                        Host::Ip(ip) => Some(*ip),
                        Host::Domain(_) => None,
                    },
                    port,
                    protocol: None,
                    attributes: None,
                    local_ip: None,
                    vless_route: None,
                    process_info: Some(&proc_cell),
                };
                if self.ctx.router.route(&query).await.tag != decision.tag {
                    log::debug(
                        "shadowsocks udp: packet dropped, its route differs from the session",
                    );
                    continue;
                }
                if let Ok(addr) = cone.target(&host, port).await {
                    let _ = cone.send_to(&payload, addr).await;
                    traffic.up(payload.len());
                }
            }
            Ok(())
        };
        let down = async {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, from) = cone.recv_from(&mut buf).await?;
                activity.touch();
                let target = Target::new(
                    TargetAddr::Ip(from.ip()),
                    from.port(),
                    xray_routing::Network::Udp,
                );
                if let Ok(wire) = session_down
                    .lock()
                    .await
                    .encode_response(&target, &buf[..n])
                {
                    let _ = self.socket.send_to(&wire, init.peer).await;
                    traffic.down(n);
                }
            }
        };
        Box::pin(crate::vless::relay_policy(up, down, &activity, user_policy)).await
    }

    async fn run_2017(self) {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log::warn(format!("shadowsocks udp recv error: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let users = same_kind_users(
                self.ctx
                    .ss_users
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            );
            let mut matched = None;
            for user in &users {
                let ShadowsocksMethod::Aead2017(m) = &user.method else {
                    continue;
                };
                let mut session = UdpSession::new(m.clone());
                if let Ok((target, payload)) = session.decode(&buf[..n]) {
                    matched = Some((user.clone(), target, payload));
                    break;
                }
            }
            let Some((user, target, payload)) = matched else {
                continue;
            };

            let ShadowsocksMethod::Aead2017(m) = &user.method else {
                continue;
            };
            let key = (peer, Arc::as_ptr(m) as usize, 0);
            let mut sessions = self.sessions.lock().await;
            let mut packet = (target, payload);
            if let Some(entry) = sessions.get(&key) {
                // A full queue drops the datagram rather than stalling every session.
                match entry.tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    Err(mpsc::error::TrySendError::Closed(p)) => packet = p,
                }
                sessions.remove(&key);
            }
            let (target, payload) = packet;

            let (tx, rx) = mpsc::channel(128);
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            sessions.insert(key, UdpSessionEntry { id, tx });
            drop(sessions);

            let handler = self.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Box::pin(handler.serve_udp_session_2017(peer, user, target, payload, rx)).await
                {
                    log::debug(format!("shadowsocks udp session {peer} ended: {e}"));
                }
                remove_session(&handler.sessions, key, id).await;
            });
        }
    }

    async fn serve_udp_session_2017(
        &self,
        peer: SocketAddr,
        user: ShadowsocksUser,
        initial_target: Target,
        initial_payload: Vec<u8>,
        mut rx: mpsc::Receiver<UdpPacket>,
    ) -> io::Result<()> {
        let method = match &user.method {
            ShadowsocksMethod::Aead2017(m) => m.clone(),
            _ => return Ok(()),
        };
        let user_policy = crate::policy::for_level(user.level);
        let _online = stats::get().connect(&user.email, user.level, peer.ip());

        let (host, port) = target_to_host_port(&initial_target);
        let route = RouteRequest {
            ctx_tag: &self.ctx.tag,
            inbound_port: self.ctx.port,
            email: &user.email,
            peer,
            network: Network::Udp,
            host: &host,
            port,
            sniffing: &self.ctx.sniffing,
        };
        let Some(decision) = route.allow(&self.ctx.router, &initial_payload).await else {
            return Ok(());
        };
        if let Action::Block(_) = decision.action {
            return Ok(());
        }
        let cone = ConeUdp::open(self.ctx.router.clone(), &decision).await?;
        let traffic = stats::get().traffic(&self.ctx.tag, &user.email, user.level, &decision.tag);
        let activity = Activity::new();
        if let Ok(target) = cone.target(&host, port).await {
            if let Err(e) = cone.send_to(&initial_payload, target).await {
                log::debug(format!("shadowsocks udp send error: {e}"));
            }
            traffic.up(initial_payload.len());
        }

        let up = async {
            let proc_cell = std::sync::OnceLock::new();
            while let Some((target, payload)) = rx.recv().await {
                activity.touch();
                let (host, port) = target_to_host_port(&target);
                let query = Query {
                    inbound: &self.ctx.tag,
                    inbound_port: self.ctx.port,
                    user: &user.email,
                    source: peer,
                    network: Network::Udp,
                    domain: match &host {
                        Host::Domain(d) => Some(d.as_str()),
                        Host::Ip(_) => None,
                    },
                    ip: match &host {
                        Host::Ip(ip) => Some(*ip),
                        Host::Domain(_) => None,
                    },
                    port,
                    protocol: None,
                    attributes: None,
                    local_ip: None,
                    vless_route: None,
                    process_info: Some(&proc_cell),
                };
                if self.ctx.router.route(&query).await.tag != decision.tag {
                    log::debug(
                        "shadowsocks udp: packet dropped, its route differs from the session",
                    );
                    continue;
                }
                if let Ok(addr) = cone.target(&host, port).await {
                    let _ = cone.send_to(&payload, addr).await;
                    traffic.up(payload.len());
                }
            }
            Ok(())
        };
        let down = async {
            let mut session = UdpSession::new(method.clone());
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, from) = cone.recv_from(&mut buf).await?;
                activity.touch();
                let target = Target::new(
                    TargetAddr::Ip(from.ip()),
                    from.port(),
                    xray_routing::Network::Udp,
                );
                if let Ok(wire) = session.encode(&target, &buf[..n]) {
                    let _ = self.socket.send_to(&wire, peer).await;
                    traffic.down(n);
                }
            }
        };
        Box::pin(crate::vless::relay_policy(up, down, &activity, user_policy)).await
    }
}

fn target_to_host_port(target: &Target) -> (Host, u16) {
    let host = match &target.addr {
        TargetAddr::Ip(ip) => Host::Ip(*ip),
        TargetAddr::Domain(d) => Host::Domain(d.clone()),
    };
    (host, target.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use xray_proxy::shadowsocks2022::{
        ClientStream as ClientStream2022, Method as Method2022, SaltPool,
        ServerStream as ServerStream2022,
    };
    use xray_routing::{Network, Target, TargetAddr};

    #[tokio::test]
    async fn test_ss2022_replayed_first_packet_rejected() {
        let method = Arc::new(
            Method2022::new("2022-blake3-aes-128-gcm", "YXNkZmFzZGZhc2RmYXNkZg==").unwrap(),
        );
        let methods = vec![method.clone()];
        let salt_pool = Mutex::new(SaltPool::default_ss2022());

        let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp);

        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut client = ClientStream2022::new(client_io, method.clone(), &target).unwrap();

        let client_task = tokio::spawn(async move {
            client.write_all(b"initial payload").await.unwrap();
            client.flush().await.unwrap();
        });

        // Capture client handshake bytes
        let mut client_bytes = vec![0u8; 4096];
        let n = server_io.read(&mut client_bytes).await.unwrap();
        client_bytes.truncate(n);
        drop(client_task);

        // First handshake succeeds
        let mut first = std::io::Cursor::new(client_bytes.clone());
        let res1 =
            ServerStream2022::handshake_methods_with_pool(&mut first, &methods, Some(&salt_pool))
                .await;
        assert!(res1.is_ok(), "First handshake must succeed");

        // Replayed handshake with exact same salt and packet must fail
        let mut second = std::io::Cursor::new(client_bytes);
        let res2 =
            ServerStream2022::handshake_methods_with_pool(&mut second, &methods, Some(&salt_pool))
                .await;
        let err = match res2 {
            Err(e) => e,
            Ok(_) => panic!("Replayed handshake must be rejected"),
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("repeated salt"),
            "Error message should mention repeated salt: {err_msg}"
        );
    }
}
