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
use xray_proxy::shadowsocks::aead2017::{Method, ServerStream, UdpSession};
use xray_routing::{Target, TargetAddr};

use crate::config::ShadowsocksUser;
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query};
use crate::stats;
use crate::vless::{copy, read_first, relay, Activity, Context, Host, RouteRequest, Sniffing};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve_tcp<S>(
    stream: S,
    users: Arc<Vec<ShadowsocksUser>>,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let methods: Vec<Arc<Method>> = users.iter().map(|u| u.method.clone()).collect();
    let (mut server_stream, user_idx, target, mut early) = timeout(
        HANDSHAKE_TIMEOUT,
        ServerStream::handshake_methods(stream, &methods),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shadowsocks handshake timeout"))?
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("shadowsocks auth: {e}")))?;

    let email = users
        .get(user_idx)
        .map(|u| u.email.as_str())
        .unwrap_or_default();
    let _online = stats::get().connect(email, peer.ip());

    if early.is_empty() && (ctx.router.needs_sniff() || ctx.sniffing.enabled()) {
        read_first(&mut server_stream, &mut early).await;
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
        sniffing: ctx.sniffing,
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

    let (mut client_r, mut client_w) = tokio::io::split(server_stream);
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

#[derive(Clone)]
pub struct ShadowsocksUdpHandler {
    socket: Arc<UdpSocket>,
    users: Arc<Vec<ShadowsocksUser>>,
    ctx: Arc<Context>,
    sessions: SessionsMap,
}

impl ShadowsocksUdpHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        users: Arc<Vec<ShadowsocksUser>>,
        ctx: Arc<Context>,
    ) -> Self {
        Self {
            socket,
            users,
            ctx,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn run(self) {
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
            for (idx, u) in self.users.iter().enumerate() {
                let mut session = UdpSession::new(u.method.clone());
                if let Ok((target, payload)) = session.decode(&packet) {
                    matched = Some((idx, u.clone(), target, payload));
                    break;
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
                    .serve_udp_session(peer, user, target, payload, rx)
                    .await
                {
                    log::debug(format!("shadowsocks udp session {peer} ended: {e}"));
                }
                handler.sessions.lock().await.remove(&peer);
            });
        }
    }

    async fn serve_udp_session(
        &self,
        peer: SocketAddr,
        user: ShadowsocksUser,
        initial_target: Target,
        initial_payload: Vec<u8>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> io::Result<()> {
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
            sniffing: Sniffing::default(),
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
            let mut session = UdpSession::new(user.method.clone());
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
            let mut session = UdpSession::new(user.method.clone());
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
