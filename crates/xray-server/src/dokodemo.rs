//! Inbound dokodemo-door (port forwarding) handler for TCP and UDP.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use xray_config::Network;

use crate::config::DokodemoSettings;
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query};
use crate::stats;
use crate::vless::{copy, read_first, relay, Activity, Context, Host, RouteRequest};

pub async fn serve_tcp<S>(
    mut stream: S,
    settings: &DokodemoSettings,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = settings
        .address
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dokodemo address missing"))?;
    let port = settings
        .port
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dokodemo port missing"))?;

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
    if let Action::Block(_) = decision.action {
        return Ok(());
    }

    let mut route_host = host.clone();
    ctx.sniffing.override_host(&early, &mut route_host);

    let target_stream = outbound::connect(&ctx.router, &decision, &route_host, port).await?;
    let traffic = stats::get().traffic(&ctx.tag, "", &decision.tag);
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
        let (host, port) = match (&self.settings.address, self.settings.port) {
            (Some(h), Some(p)) => (h.clone(), p),
            _ => {
                log::warn("dokodemo udp missing address or port");
                return;
            }
        };

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

            let (tx, rx) = mpsc::channel(128);
            sessions.insert(peer, tx);
            drop(sessions);

            let handler = self.clone();
            let target_host = host.clone();
            tokio::spawn(async move {
                if let Err(e) = handler
                    .serve_udp_session(peer, target_host, port, packet, rx)
                    .await
                {
                    log::debug(format!("dokodemo udp session {peer} ended: {e}"));
                }
                handler.sessions.lock().await.remove(&peer);
            });
        }
    }

    async fn serve_udp_session(
        &self,
        peer: SocketAddr,
        host: Host,
        port: u16,
        initial_payload: Vec<u8>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> io::Result<()> {
        let route = RouteRequest {
            ctx_tag: &self.ctx.tag,
            inbound_port: self.ctx.port,
            email: "",
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
        let traffic = stats::get().traffic(&self.ctx.tag, "", &decision.tag);
        let activity = Activity::new();
        if let Ok(target) = cone.target(&host, port).await {
            cone.send_to(&initial_payload, target).await?;
            traffic.up(initial_payload.len());
        }

        let up = async {
            while let Some(packet) = rx.recv().await {
                activity.touch();
                let query = Query {
                    inbound: &self.ctx.tag,
                    inbound_port: self.ctx.port,
                    user: "",
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
                };
                if self.ctx.router.route(&query).await.tag != decision.tag {
                    continue;
                }
                if let Ok(addr) = cone.target(&host, port).await {
                    let _ = cone.send_to(&packet, addr).await;
                    traffic.up(packet.len());
                }
            }
            Ok(())
        };
        let down = async {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, _from) = cone.recv_from(&mut buf).await?;
                activity.touch();
                let _ = self.socket.send_to(&buf[..n], peer).await;
                traffic.down(n);
            }
        };
        relay(up, down, &activity).await
    }
}
