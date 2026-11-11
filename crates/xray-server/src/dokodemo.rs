//! Inbound dokodemo-door (port forwarding) handler for TCP and UDP.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use xray_config::Network;

use crate::config::DokodemoSettings;
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::Action;
use crate::stats;
use crate::vless::{copy, read_first, relay, Activity, Context, Host, RouteRequest};

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
    let redirected = original.filter(|_| settings.follow_redirect);
    let (host, port) = match redirected {
        Some(addr) => (Host::Ip(addr.ip().to_canonical()), addr.port()),
        None => settings.fallback_target(ctx.port),
    };

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
    };
    let Some(decision) = route.allow(&ctx.router, &early).await else {
        return Ok(());
    };
    // Only blackhole's http response gets here; connect plays it back.

    let mut route_host = host.clone();
    ctx.sniffing.override_host(&early, &mut route_host);

    let target_stream = outbound::connect(&ctx.router, &decision, &route_host, port).await?;
    let traffic = stats::get().traffic(&ctx.tag, "", 0, &decision.tag);
    let (mut client_r, mut client_w) = tokio::io::split(stream);
    let (mut target_r, mut target_w) = tokio::io::split(target_stream);

    if !early.is_empty() {
        target_w.write_all(&early).await?;
        traffic.up(early.len());
    }

    let activity = Activity::new();
    relay(
        copy(&mut client_r, &mut target_w, &activity, |n| traffic.up(n)),
        copy(&mut target_r, &mut client_w, &activity, |n| traffic.down(n)),
        &activity,
    )
    .await
}

const MAX_UDP_SESSIONS: usize = 4096;

type SessionsMap = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

#[derive(Clone)]
pub struct DokodemoUdpHandler {
    socket: Arc<UdpSocket>,
    settings: Arc<DokodemoSettings>,
    ctx: Arc<Context>,
    sessions: SessionsMap,
}

impl DokodemoUdpHandler {
    pub fn new(socket: Arc<UdpSocket>, settings: Arc<DokodemoSettings>, ctx: Arc<Context>) -> Self {
        Self {
            socket,
            settings,
            ctx,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn run(self) {
        let (host, port) = self.settings.fallback_target(self.ctx.port);

        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log::warn(format!("dokodemo udp recv error: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let mut sessions = self.sessions.lock().await;
            let packet = buf[..n].to_vec();
            let packet = if let Some(tx) = sessions.get(&peer) {
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

            if sessions.len() >= MAX_UDP_SESSIONS {
                continue;
            }
            let (tx, rx) = mpsc::channel(128);
            sessions.insert(peer, tx.clone());
            drop(sessions);

            // Sessions hold the socket weakly so that removing the inbound frees the port.
            let socket = Arc::downgrade(&self.socket);
            let ctx = self.ctx.clone();
            let map = self.sessions.clone();
            let target_host = host.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    serve_udp_session(socket, ctx, peer, target_host, port, packet, rx).await
                {
                    log::debug(format!(
                        "dokodemo udp session {} ended: {e}",
                        log::mask(peer)
                    ));
                }
                let mut map = map.lock().await;
                if map.get(&peer).is_some_and(|cur| cur.same_channel(&tx)) {
                    map.remove(&peer);
                }
            });
        }
    }
}

async fn serve_udp_session(
    socket: Weak<UdpSocket>,
    ctx: Arc<Context>,
    peer: SocketAddr,
    host: Host,
    port: u16,
    initial_payload: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: "",
        peer,
        network: Network::Udp,
        host: &host,
        port,
        sniffing: &ctx.sniffing,
    };
    let Some(decision) = route.allow(&ctx.router, &initial_payload).await else {
        return Ok(());
    };
    if let Action::Block(_) = decision.action {
        return Ok(());
    }
    let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
    let traffic = stats::get().traffic(&ctx.tag, "", 0, &decision.tag);
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
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, _from) = cone.recv_from(&mut buf).await?;
            activity.touch();
            let Some(socket) = socket.upgrade() else {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "inbound removed"));
            };
            let _ = socket.send_to(&buf[..n], peer).await;
            traffic.down(n);
        }
    });
    relay(up, down, &activity).await
}
