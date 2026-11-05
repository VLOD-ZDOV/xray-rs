//! Inbound VMess protocol handler (AEAD).

use std::io;
use std::net::SocketAddr;
use std::sync::PoisonError;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use xray_config::Network;
use xray_proxy::vmess::server::{self, ServerHandshake, ServerStream, ServerUser};
use xray_routing::TargetAddr;

use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, BlockAction};
use crate::stats;
use crate::vless::{copy, read_first, relay, Activity, Context, Host, RouteRequest, CONN_IDLE};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve<R, W>(
    mut uplink: R,
    downlink: W,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let server_users: Vec<ServerUser> = {
        let users = ctx.users.read().unwrap_or_else(PoisonError::into_inner);
        users
            .iter()
            .map(|u| ServerUser::new(&u.id, u.email.clone()))
            .collect()
    };

    let hs_res = timeout(
        HANDSHAKE_TIMEOUT,
        server::handshake(&mut uplink, &server_users),
    )
    .await;
    let hs: ServerHandshake = match hs_res {
        Ok(Ok(hs)) => hs,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "vmess handshake timeout",
            ));
        }
    };

    let user_email = server_users[hs.user_index].email.clone();
    let _online = stats::get().connect(&user_email, peer.ip());

    let host = match &hs.target.addr {
        TargetAddr::Ip(ip) => Host::Ip(*ip),
        TargetAddr::Domain(d) => match d.parse() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(d.clone()),
        },
    };
    let port = hs.target.port;

    let (mut server_r, mut server_w) =
        ServerStream::<()>::split_from_handshake(uplink, downlink, &hs);

    let network = match hs.network {
        xray_routing::Network::Tcp => Network::Tcp,
        xray_routing::Network::Udp => Network::Udp,
    };

    let mut early = Vec::new();
    if network == Network::Tcp && (ctx.router.needs_sniff() || ctx.sniffing.enabled()) {
        read_first(&mut server_r, &mut early).await;
    }

    let mut route_host = host.clone();
    ctx.sniffing.override_host(&early, &mut route_host);

    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: &user_email,
        peer,
        network,
        host: &route_host,
        port,
        sniffing: ctx.sniffing,
    };

    let Some(decision) = route.allow(&ctx.router, &early).await else {
        return Ok(());
    };

    if let Action::Block(BlockAction::Http403) = decision.action {
        if network == Network::Tcp {
            server_w
                .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=600\r\nContent-Length: 0\r\n\r\n")
                .await?;
            server_w.flush().await?;
        }
        return Ok(());
    }
    if let Action::Block(_) = decision.action {
        return Ok(());
    }

    let traffic = stats::get().traffic(&ctx.tag, &user_email, &decision.tag);

    match network {
        Network::Tcp => {
            let target_stream =
                outbound::connect(&ctx.router, &decision, &route_host, port).await?;
            let (mut target_r, mut target_w) = tokio::io::split(target_stream);

            if !early.is_empty() {
                target_w.write_all(&early).await?;
                traffic.up(early.len());
            }

            let activity = Activity::new();
            relay(
                copy(&mut server_r, &mut target_w, &activity, |n| traffic.up(n)),
                copy(&mut target_r, &mut server_w, &activity, |n| traffic.down(n)),
                &activity,
            )
            .await
        }
        Network::Udp => {
            let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
            let activity = Activity::new();
            let target_addr = cone.target(&route_host, port).await?;

            let up = async {
                let mut packet = vec![0u8; 65535];
                loop {
                    activity.touch();
                    let n = timeout(CONN_IDLE, server_r.read(&mut packet))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                    if n == 0 {
                        break;
                    }
                    cone.send_to(&packet[..n], target_addr).await?;
                    traffic.up(n);
                }
                Ok::<(), io::Error>(())
            };

            let down = async {
                let mut buf = vec![0u8; 65535];
                loop {
                    activity.touch();
                    let (n, _from) = timeout(CONN_IDLE, cone.recv_from(&mut buf))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                    server_w.write_all(&buf[..n]).await?;
                    server_w.flush().await?;
                    traffic.down(n);
                }
            };

            relay(up, down, &activity).await
        }
    }
}
