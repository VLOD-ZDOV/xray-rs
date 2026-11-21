//! Inbound dokodemo-door (port forwarding) handler for TCP and UDP.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use xray_config::Network;

use crate::config::DokodemoSettings;
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::Action;
use crate::stats;
use crate::tproxy_udp;
use crate::vless::{copy_buf, read_first, relay_policy, Activity, Context, Host, RouteRequest};

impl DokodemoSettings {
    // Xray falls back to localhost and the listening port when they are not configured.
    fn fallback_target(&self, listen_port: u16) -> (Host, u16) {
        (
            self.address
                .clone()
                .unwrap_or(Host::Ip(std::net::Ipv4Addr::LOCALHOST.into())),
            self.port.unwrap_or(listen_port),
        )
    }

    /// The destination for one connection, including Xray's `portMap`, which
    /// overrides either half of it by the connection's local port and only
    /// applies without `followRedirect`.
    fn target_for(&self, ctx_port: u16, original: Option<SocketAddr>) -> (Host, u16) {
        if self.follow_redirect {
            return match original {
                Some(addr) => (Host::Ip(addr.ip().to_canonical()), addr.port()),
                None => self.fallback_target(ctx_port),
            };
        }
        let (mut host, mut port) = self.fallback_target(ctx_port);
        let local_port = original.map_or(ctx_port, |addr| addr.port());
        if let Some((mapped_host, mapped_port)) = self.port_map.get(&local_port) {
            if let Some(mapped_host) = mapped_host {
                host = mapped_host.clone();
            }
            if let Some(mapped_port) = mapped_port {
                port = *mapped_port;
            }
        }
        (host, port)
    }
}

pub async fn serve_tcp<S>(
    mut stream: S,
    settings: &DokodemoSettings,
    ctx: &Context,
    peer: SocketAddr,
    original: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (host, port) = settings.target_for(ctx.port, original);

    if port == ctx.port && matches!(&host, Host::Ip(ip) if ip.is_loopback()) {
        crate::log::info!("loopback connection detected from {}", log::mask(peer));
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "loopback connection detected",
        ));
    }

    let mut early = Vec::new();
    if ctx.router.needs_sniff() || ctx.sniffing.enabled() {
        read_first(&mut stream, &mut early).await;
    }

    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: "",
        peer,
        network: Network::Tcp,
        host: &host,
        port,
        sniffing: &ctx.sniffing,
        vless_route: None,
    };
    let Some(decision) = route.allow(&ctx.router, &early).await else {
        return Ok(());
    };
    // Only blackhole's http response gets here; connect plays it back.

    let mut route_host = host.clone();
    ctx.sniffing.override_host(&early, &mut route_host);

    let policy = crate::policy::for_level(settings.user_level);
    let target_stream = outbound::connect(&ctx.router, &decision, &route_host, port).await?;
    let traffic = stats::get().traffic(&ctx.tag, "", settings.user_level, &decision.tag);
    let (mut client_r, mut client_w) = tokio::io::split(stream);
    let (mut target_r, mut target_w) = tokio::io::split(target_stream);

    if !early.is_empty() {
        target_w.write_all(&early).await?;
        target_w.flush().await?;
        traffic.up(early.len());
    }

    let activity = Activity::new();
    relay_policy(
        copy_buf(
            &mut client_r,
            &mut target_w,
            &activity,
            |n| traffic.up(n),
            policy.buffer_size,
        ),
        copy_buf(
            &mut target_r,
            &mut client_w,
            &activity,
            |n| traffic.down(n),
            policy.buffer_size,
        ),
        &activity,
        policy,
    )
    .await
}

const MAX_UDP_SESSIONS: usize = 4096;

type SessionsMap = Arc<Mutex<HashMap<(SocketAddr, Option<SocketAddr>), mpsc::Sender<Bytes>>>>;

#[derive(Clone)]
pub struct DokodemoUdpHandler {
    socket: Arc<UdpSocket>,
    settings: Arc<DokodemoSettings>,
    ctx: Arc<Context>,
    sessions: SessionsMap,
    /// The socket mark when the socket is a TPROXY one.
    tproxy: Option<u32>,
}

impl DokodemoUdpHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        settings: Arc<DokodemoSettings>,
        ctx: Arc<Context>,
        tproxy: Option<u32>,
    ) -> Self {
        Self {
            socket,
            settings,
            ctx,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tproxy,
        }
    }

    pub async fn run(self) {
        let mut buf = vec![0u8; 65535];
        loop {
            let received = match self.tproxy {
                Some(_) => tproxy_udp::recv(&self.socket, &mut buf).await,
                None => self
                    .socket
                    .recv_from(&mut buf)
                    .await
                    .map(|(n, peer)| (n, peer, None)),
            };
            let (n, peer, original) = match received {
                Ok(res) => res,
                Err(e) => {
                    crate::log::warn!("dokodemo udp recv error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let original = original.filter(|_| self.settings.follow_redirect);
            let key = (peer, original);
            let mut sessions = self.sessions.lock().await;
            let packet = Bytes::copy_from_slice(&buf[..n]);
            let packet = if let Some(tx) = sessions.get(&key) {
                match tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    Err(mpsc::error::TrySendError::Closed(packet)) => {
                        sessions.remove(&key);
                        packet
                    }
                }
            } else {
                packet
            };

            if sessions.len() >= MAX_UDP_SESSIONS {
                continue;
            }
            let (tx, rx) = mpsc::channel(128);
            sessions.insert(key, tx.clone());
            drop(sessions);

            let (host, port) = self.settings.target_for(self.ctx.port, original);
            let reply = match (self.tproxy, original) {
                (Some(mark), Some(original)) => Reply::Forged {
                    original,
                    mark,
                    sockets: HashMap::new(),
                },
                _ => Reply::Inbound(Arc::downgrade(&self.socket)),
            };
            let ctx = self.ctx.clone();
            let map = self.sessions.clone();
            let level = self.settings.user_level;
            tokio::spawn(async move {
                if let Err(e) =
                    serve_udp_session(reply, ctx, peer, (host, port), packet, rx, level).await
                {
                    crate::log::debug!("dokodemo udp session {} ended: {e}", log::mask(peer));
                }
                let mut map = map.lock().await;
                if map.get(&key).is_some_and(|cur| cur.same_channel(&tx)) {
                    map.remove(&key);
                }
            });
        }
    }
}

/// Where replies go out from.
enum Reply {
    /// The inbound socket, held weakly so that removing the inbound frees the port.
    Inbound(Weak<UdpSocket>),
    /// TPROXY: sockets bound to each answering address, as Xray's FakeUDP.
    Forged {
        original: SocketAddr,
        mark: u32,
        sockets: HashMap<SocketAddr, Arc<UdpSocket>>,
    },
}

// A session normally hears from one address; cap the forged sockets per session.
const MAX_REPLY_SOCKETS: usize = 64;

impl Reply {
    async fn send(&mut self, data: &[u8], from: SocketAddr, peer: SocketAddr) -> io::Result<()> {
        match self {
            Self::Inbound(socket) => {
                let Some(socket) = socket.upgrade() else {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "inbound removed"));
                };
                let _ = socket.send_to(data, peer).await;
            }
            Self::Forged {
                original,
                mark,
                sockets,
            } => {
                let from = tproxy_udp::canonical(from);
                let from = if from.ip().is_unspecified() || from.is_ipv4() != peer.is_ipv4() {
                    *original
                } else {
                    from
                };
                if !sockets.contains_key(original) {
                    let socket = Arc::new(tproxy_udp::reply_socket(*original, *mark)?);
                    sockets.insert(*original, socket);
                }
                if !sockets.contains_key(&from) && sockets.len() < MAX_REPLY_SOCKETS {
                    // An address that cannot be bound (a local one in use) answers as the original.
                    let socket = match tproxy_udp::reply_socket(from, *mark) {
                        Ok(socket) => Arc::new(socket),
                        Err(e) => {
                            crate::log::debug!("tproxy udp reply from {from}: {e}");
                            sockets[original].clone()
                        }
                    };
                    sockets.insert(from, socket);
                }
                let socket = sockets.get(&from).unwrap_or(&sockets[original]);
                let _ = socket.send_to(data, peer).await;
            }
        }
        Ok(())
    }
}

async fn serve_udp_session(
    mut reply: Reply,
    ctx: Arc<Context>,
    peer: SocketAddr,
    (host, port): (Host, u16),
    initial_payload: Bytes,
    mut rx: mpsc::Receiver<Bytes>,
    level: u32,
) -> io::Result<()> {
    let policy = crate::policy::for_level(level);
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: "",
        peer,
        network: Network::Udp,
        host: &host,
        port,
        sniffing: &ctx.sniffing,
        vless_route: None,
    };
    let Some(decision) = route.allow(&ctx.router, &initial_payload).await else {
        return Ok(());
    };
    if let Action::Block(_) = decision.action {
        return Ok(());
    }
    let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
    let traffic = stats::get().traffic(&ctx.tag, "", level, &decision.tag);
    let activity = Activity::new();
    // The destination is fixed, so resolve it once per session instead of per packet.
    let mut resolved = cone.target(&host, port).await.ok();
    if let Some(target) = resolved {
        cone.send_to(&initial_payload, target).await?;
        traffic.up(initial_payload.len());
    }

    let up = Box::pin(async {
        while let Some(packet) = rx.recv().await {
            activity.touch();
            if resolved.is_none() {
                resolved = cone.target(&host, port).await.ok();
            }
            if let Some(addr) = resolved {
                let _ = cone.send_to(&packet, addr).await;
                traffic.up(packet.len());
            }
        }
        Ok(())
    });
    let down = Box::pin(async {
        let mut pooled = crate::vless::PooledBuffer::acquire(65535);
        let buf = &mut pooled.buf;
        loop {
            let (n, from) = cone.recv_from(buf).await?;
            activity.touch();
            reply.send(&buf[..n], from, peer).await?;
            traffic.down(n);
        }
    });
    relay_policy(up, down, &activity, policy).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DokodemoPortMap;

    fn settings(follow_redirect: bool, port_map: DokodemoPortMap) -> DokodemoSettings {
        DokodemoSettings {
            address: Some(Host::Domain("target.example".into())),
            port: Some(53),
            follow_redirect,
            port_map,
            user_level: 0,
            tcp: true,
        }
    }

    #[test]
    fn port_map_overrides_each_half_by_local_port() {
        let mut map = DokodemoPortMap::new();
        map.insert(
            15353,
            (Some(Host::Ip("8.8.8.8".parse().unwrap())), Some(5353)),
        );
        map.insert(16000, (None, Some(5300)));
        let settings = settings(false, map);

        assert_eq!(
            settings.target_for(15353, None),
            (Host::Ip("8.8.8.8".parse().unwrap()), 5353)
        );
        assert_eq!(
            settings.target_for(16000, None),
            (Host::Domain("target.example".into()), 5300)
        );
        assert_eq!(
            settings.target_for(17000, None),
            (Host::Domain("target.example".into()), 53)
        );
    }

    #[test]
    fn follow_redirect_ignores_port_map() {
        let mut map = DokodemoPortMap::new();
        map.insert(
            443,
            (Some(Host::Ip("8.8.8.8".parse().unwrap())), Some(5353)),
        );
        let settings = settings(true, map);
        let original = Some("192.0.2.7:443".parse().unwrap());
        assert_eq!(
            settings.target_for(15353, original),
            (Host::Ip("192.0.2.7".parse().unwrap()), 443)
        );
    }
}
