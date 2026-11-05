//! Inbound SOCKS5 and HTTP CONNECT proxy handlers.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use xray_config::Network;
use xray_proxy::inbound::{
    encode_socks5_udp_datagram, negotiate_socks5, parse_http_connect_request,
    parse_socks5_request_message, parse_socks5_udp_datagram, write_socks5_command_not_supported,
    write_socks5_failure, write_socks5_success, write_socks5_success_with_bind, SocksCommand,
    SocksInboundAuth,
};
use xray_routing::{Target, TargetAddr};

use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query};
use crate::stats;
use crate::vless::{copy, relay, Activity, Context, Host, RouteRequest, CONN_IDLE};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve_socks<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
    udp_enabled: bool,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let auth_user = timeout(HANDSHAKE_TIMEOUT, negotiate_socks5(&mut stream, auth))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks handshake timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("socks auth: {e}")))?;

    let email = auth_user
        .as_ref()
        .map(|u| u.as_str().to_owned())
        .unwrap_or_default();
    let _online = stats::get().connect(&email, peer.ip());

    let req = timeout(HANDSHAKE_TIMEOUT, parse_socks5_request_message(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks request timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("socks request: {e}")))?;

    match req.command {
        SocksCommand::Connect => {
            let (host, port) = target_to_host_port(&req.target);
            let route = RouteRequest {
                ctx_tag: &ctx.tag,
                inbound_port: ctx.port,
                email: &email,
                peer,
                network: Network::Tcp,
                host: &host,
                port,
            };
            let Some(decision) = route.allow(&ctx.router, &[]).await else {
                let _ = write_socks5_failure(&mut stream).await;
                return Ok(());
            };
            if let Action::Block(_) = decision.action {
                let _ = write_socks5_failure(&mut stream).await;
                return Ok(());
            }

            let outbound_stream =
                match outbound::connect(&ctx.router, &decision, &host, port).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = write_socks5_failure(&mut stream).await;
                        return Err(e);
                    }
                };

            write_socks5_success(&mut stream)
                .await
                .map_err(|e| io::Error::other(format!("{e}")))?;
            stream.flush().await?;

            let traffic = stats::get().traffic(&ctx.tag, &email, &decision.tag);
            let (mut uplink, mut downlink) = tokio::io::split(stream);
            let (mut target_r, mut target_w) = tokio::io::split(outbound_stream);

            let activity = Activity::new();
            relay(
                copy(&mut uplink, &mut target_w, &activity, |n| traffic.up(n)),
                copy(&mut target_r, &mut downlink, &activity, |n| traffic.down(n)),
                &activity,
            )
            .await
        }
        SocksCommand::UdpAssociate => {
            if !udp_enabled {
                let _ = write_socks5_command_not_supported(&mut stream).await;
                return Ok(());
            }

            let udp_relay = UdpSocket::bind("127.0.0.1:0").await?;
            let relay_addr = udp_relay.local_addr()?;

            write_socks5_success_with_bind(&mut stream, relay_addr)
                .await
                .map_err(|e| io::Error::other(format!("{e}")))?;
            stream.flush().await?;

            let query = Query {
                inbound: &ctx.tag,
                inbound_port: ctx.port,
                user: &email,
                source: peer,
                network: Network::Udp,
                domain: None,
                ip: None,
                port: 0,
                protocol: None,
            };
            let decision = ctx.router.route(&query).await;
            let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
            let traffic = stats::get().traffic(&ctx.tag, &email, &decision.tag);
            let activity = Activity::new();

            // SOCKS UDP relay session
            let client_udp_addr: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
                std::sync::Arc::new(tokio::sync::Mutex::new(None));
            let client_addr_c = client_udp_addr.clone();

            let up = async {
                let mut buf = vec![0u8; 65535];
                loop {
                    activity.touch();
                    let (n, from) = timeout(CONN_IDLE, udp_relay.recv_from(&mut buf))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                    *client_addr_c.lock().await = Some(from);

                    if let Ok(datagram) = parse_socks5_udp_datagram(&buf[..n]) {
                        let (host, port) = target_to_host_port(&datagram.target);
                        if let Ok(target_addr) = cone.target(&host, port).await {
                            let _ = cone.send_to(&datagram.payload, target_addr).await;
                            traffic.up(datagram.payload.len());
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };

            let down = async {
                let mut buf = vec![0u8; 65535];
                loop {
                    activity.touch();
                    let (n, from) = timeout(CONN_IDLE, cone.recv_from(&mut buf))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                    let to_client = *client_udp_addr.lock().await;
                    if let Some(c_addr) = to_client {
                        let target = Target::new(
                            TargetAddr::Ip(from.ip()),
                            from.port(),
                            xray_routing::Network::Udp,
                        );
                        if let Ok(wire) = encode_socks5_udp_datagram(&target, &buf[..n]) {
                            let _ = udp_relay.send_to(&wire, c_addr).await;
                            traffic.down(n);
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };

            let tcp_keepalive = async {
                let mut discard = [0u8; 1];
                let _ = stream.read(&mut discard).await;
                Ok::<(), io::Error>(())
            };

            tokio::select! {
                r = up => r,
                r = down => r,
                _ = tcp_keepalive => Ok(()),
            }
        }
    }
}

pub async fn serve_http<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let req = timeout(HANDSHAKE_TIMEOUT, parse_http_connect_request(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "http connect timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("http connect: {e}")))?;

    if !auth.admits_http_basic(req.proxy_authorization.as_deref().map(|v| v.as_slice())) {
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n")
            .await?;
        stream.flush().await?;
        return Ok(());
    }

    let user = auth
        .http_basic_user(req.proxy_authorization.as_deref().map(|v| v.as_slice()))
        .flatten();
    let email = user
        .as_ref()
        .map(|u| u.as_str().to_owned())
        .unwrap_or_default();
    let _online = stats::get().connect(&email, peer.ip());

    let (host, port) = target_to_host_port(&req.target);
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: &email,
        peer,
        network: Network::Tcp,
        host: &host,
        port,
    };

    let Some(decision) = route.allow(&ctx.router, &[]).await else {
        stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        stream.flush().await?;
        return Ok(());
    };
    if let Action::Block(_) = decision.action {
        stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        stream.flush().await?;
        return Ok(());
    }

    let outbound_stream = match outbound::connect(&ctx.router, &decision, &host, port).await {
        Ok(s) => s,
        Err(_) => {
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            stream.flush().await?;
            return Ok(());
        }
    };

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    stream.flush().await?;

    let traffic = stats::get().traffic(&ctx.tag, &email, &decision.tag);
    let (mut uplink, mut downlink) = tokio::io::split(stream);
    let (mut target_r, mut target_w) = tokio::io::split(outbound_stream);

    let activity = Activity::new();
    relay(
        copy(&mut uplink, &mut target_w, &activity, |n| traffic.up(n)),
        copy(&mut target_r, &mut downlink, &activity, |n| traffic.down(n)),
        &activity,
    )
    .await
}

fn target_to_host_port(target: &Target) -> (Host, u16) {
    let host = match &target.addr {
        TargetAddr::Ip(ip) => Host::Ip(*ip),
        TargetAddr::Domain(d) => Host::Domain(d.clone()),
    };
    (host, target.port)
}
