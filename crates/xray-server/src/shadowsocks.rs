//! Inbound Shadowsocks proxy handler supporting AEAD ciphers for TCP and UDP.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use xray_config::Network;
use xray_proxy::shadowsocks::aead2017::UdpSession;
use xray_routing::{Target, TargetAddr};

use crate::config::{ShadowsocksMethod, ShadowsocksUser};
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query};
use crate::stats;
use crate::vless::{copy, read_first, relay, Activity, Context, Host, RouteRequest};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve_tcp<S>(
    stream: S,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let users = ctx.ss_users.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    if users.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no shadowsocks users configured",
        ));
    }
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
                HANDSHAKE_TIMEOUT,
                xray_proxy::shadowsocks2022::ServerStream::handshake_methods(stream, &methods),
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
                HANDSHAKE_TIMEOUT,
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

    let email = users
        .get(user_idx)
        .map(|u| u.email.as_str())
        .unwrap_or_default();
    let _online = stats::get().connect(email, peer.ip());

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
    if let Action::Block(_) = decision.action {
        return Ok(());
    }
    ctx.sniffing.override_host(&early, &mut host);

    let mut outbound_stream = outbound::connect(&ctx.router, &decision, &host, port).await?;
    let traffic = stats::get().traffic(&ctx.tag, email, &decision.tag);
    if !early.is_empty() {
        outbound_stream.write_all(&early).await?;
        traffic.up(early.len());
    }

    let (mut target_r, mut target_w) = tokio::io::split(outbound_stream);

    let activity = Activity::new();
    relay(
        copy(&mut client_r, &mut target_w, &activity, |n| traffic.up(n)),
        copy(&mut target_r, &mut client_w, &activity, |n| traffic.down(n)),
        &activity,
    )
    .await
}

type SessionsMap = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

struct UdpInit2022 {
    peer: SocketAddr,
    user: ShadowsocksUser,
    target: Target,
    payload: Vec<u8>,
    client_id: u64,
    packet_id: u64,
}

#[derive(Clone)]
pub struct ShadowsocksUdpHandler {
    socket: Arc<UdpSocket>,
    ctx: Arc<Context>,
    sessions: SessionsMap,
}

impl ShadowsocksUdpHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        ctx: Arc<Context>,
    ) -> Self {
        Self {
            socket,
            ctx,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn run(self) {
        let is_2022 = {
            let users = self.ctx.ss_users.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            users.first().is_some_and(|u| matches!(u.method, ShadowsocksMethod::Ss2022(_)))
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
            let users = self.ctx.ss_users.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            let methods: Vec<Arc<xray_proxy::shadowsocks2022::Method>> = users
                .iter()
                .filter_map(|u| match &u.method {
                    ShadowsocksMethod::Ss2022(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            let mut sessions = self.sessions.lock().await;
            let packet = buf[..n].to_vec();
            let packet = if let Some(tx) = sessions.get(&peer) {
                // A full queue drops the datagram rather than stalling every session.
                match tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    Err(mpsc::error::TrySendError::Closed(packet)) => {
                        sessions.remove(&peer);
                        packet
                    }
                }
            } else {
                packet
            };

            let Ok((user_idx, target, payload, client_id, packet_id)) =
                xray_proxy::shadowsocks2022::ServerUdpSession::decode_request(&methods, &packet)
            else {
                continue;
            };

            let Some(user) = users.get(user_idx).cloned() else {
                continue;
            };

            let (tx, rx) = mpsc::channel(128);
            sessions.insert(peer, tx);
            drop(sessions);

            let init = UdpInit2022 {
                peer,
                user,
                target,
                payload,
                client_id,
                packet_id,
            };
            let handler = self.clone();
            tokio::spawn(async move {
                if let Err(e) = handler.serve_udp_session_2022(init, rx).await {
                    log::debug(format!("shadowsocks 2022 udp session {peer} ended: {e}"));
                }
                handler.sessions.lock().await.remove(&peer);
            });
        }
    }

    async fn serve_udp_session_2022(
        &self,
        init: UdpInit2022,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> io::Result<()> {
        let user_method = match &init.user.method {
            ShadowsocksMethod::Ss2022(m) => m.clone(),
            _ => return Ok(()),
        };
        let mut server_session = xray_proxy::shadowsocks2022::ServerUdpSession::new(
            user_method.clone(),
            init.client_id,
        )?;
        if !server_session.check_replay(init.packet_id) {
            return Ok(());
        }

        let _online = stats::get().connect(&init.user.email, init.peer.ip());

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
        let traffic = stats::get().traffic(&self.ctx.tag, &init.user.email, &decision.tag);
        let activity = Activity::new();
        if let Ok(target) = cone.target(&host, port).await {
            cone.send_to(&init.payload, target).await?;
            traffic.up(init.payload.len());
        }

        let session_lock = Arc::new(Mutex::new(server_session));
        let session_up = session_lock.clone();
        let session_down = session_lock.clone();

        let up = async {
            let methods = [user_method];
            while let Some(packet) = rx.recv().await {
                activity.touch();
                let Ok((_idx, target, payload, cid, pid)) =
                    xray_proxy::shadowsocks2022::ServerUdpSession::decode_request(&methods, &packet)
                else {
                    continue;
                };
                if cid != init.client_id {
                    continue;
                }
                if !session_up.lock().await.check_replay(pid) {
                    continue;
                }
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
                };
                if self.ctx.router.route(&query).await.tag != decision.tag {
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
                if let Ok(wire) = session_down.lock().await.encode_response(&target, &buf[..n]) {
                    let _ = self.socket.send_to(&wire, init.peer).await;
                    traffic.down(n);
                }
            }
        };
        relay(up, down, &activity).await
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
            let users = self.ctx.ss_users.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            let methods: Vec<Arc<xray_proxy::shadowsocks::aead2017::Method>> = users
                .iter()
                .filter_map(|u| match &u.method {
                    ShadowsocksMethod::Aead2017(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            let mut sessions = self.sessions.lock().await;
            let packet = buf[..n].to_vec();
            let packet = if let Some(tx) = sessions.get(&peer) {
                // A full queue drops the datagram rather than stalling every session.
                match tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    Err(mpsc::error::TrySendError::Closed(packet)) => {
                        sessions.remove(&peer);
                        packet
                    }
                }
            } else {
                packet
            };

            // Find matching user for new session
            let mut matched = None;
            for (idx, m) in methods.iter().enumerate() {
                let mut session = UdpSession::new(m.clone());
                if let Ok((target, payload)) = session.decode(&packet) {
                    if let Some(user) = users.get(idx).cloned() {
                        matched = Some((idx, user, target, payload));
                        break;
                    }
                }
            }

            let Some((_user_idx, user, target, payload)) = matched else {
                continue;
            };

            let (tx, rx) = mpsc::channel(128);
            sessions.insert(peer, tx);
            drop(sessions);

            let handler = self.clone();
            tokio::spawn(async move {
                if let Err(e) = handler
                    .serve_udp_session_2017(peer, user, target, payload, rx)
                    .await
                {
                    log::debug(format!("shadowsocks udp session {peer} ended: {e}"));
                }
                handler.sessions.lock().await.remove(&peer);
            });
        }
    }

    async fn serve_udp_session_2017(
        &self,
        peer: SocketAddr,
        user: ShadowsocksUser,
        initial_target: Target,
        initial_payload: Vec<u8>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> io::Result<()> {
        let method = match &user.method {
            ShadowsocksMethod::Aead2017(m) => m.clone(),
            _ => return Ok(()),
        };
        let _online = stats::get().connect(&user.email, peer.ip());

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
        let traffic = stats::get().traffic(&self.ctx.tag, &user.email, &decision.tag);
        let activity = Activity::new();
        if let Ok(target) = cone.target(&host, port).await {
            cone.send_to(&initial_payload, target).await?;
            traffic.up(initial_payload.len());
        }

        let up = async {
            let mut session = UdpSession::new(method.clone());
            while let Some(packet) = rx.recv().await {
                activity.touch();
                let Ok((target, payload)) = session.decode(&packet) else {
                    continue;
                };
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
                };
                if self.ctx.router.route(&query).await.tag != decision.tag {
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
        relay(up, down, &activity).await
    }
}

fn target_to_host_port(target: &Target) -> (Host, u16) {
    let host = match &target.addr {
        TargetAddr::Ip(ip) => Host::Ip(*ip),
        TargetAddr::Domain(d) => Host::Domain(d.clone()),
    };
    (host, target.port)
}
