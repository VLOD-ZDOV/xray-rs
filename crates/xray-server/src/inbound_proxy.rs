//! Inbound SOCKS5 and HTTP CONNECT proxy handlers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use xray_config::Network;
use xray_proxy::inbound::{
    copy_body_chunked, copy_body_length, encode_socks5_udp_datagram, negotiate_socks5,
    parse_socks4_connect, parse_socks5_request_message, parse_socks5_udp_datagram,
    read_http_request_head, read_http_response, write_socks5_command_not_supported,
    write_socks5_success, write_socks5_success_with_bind, HttpBody, HttpInboundAccounts,
    PlainHttpError, PlainHttpRequest, SocksCommand, SocksInboundAuth, SOCKS4_GRANTED,
    SOCKS4_REJECTED, SOCKS4_VERSION,
};
use xray_routing::{Target, TargetAddr};

use crate::httpupgrade::PrefixedStream;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query};
use crate::vless::{
    copy, host_label, read_first, relay, Activity, Context, Host, RouteRequest, CONN_IDLE,
};
use crate::{log, stats};

/// Xray's SOCKS inbound (also named `mixed`): the first byte picks SOCKS 5,
/// SOCKS 4/4a, or HTTP on the same port.
pub async fn serve_socks<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
    udp_enabled: bool,
    ctx: &Context,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut first = [0u8; 1];
    timeout(
        crate::policy::get().handshake,
        stream.read_exact(&mut first),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks handshake timeout"))??;
    match first[0] {
        SOCKS4_VERSION => serve_socks4(stream, auth, ctx, peer).await,
        5 => {
            let stream = PrefixedStream::new(stream, first.to_vec());
            serve_socks5(stream, auth, udp_enabled, ctx, peer, local).await
        }
        _ => serve_http(PrefixedStream::new(stream, first.to_vec()), auth, ctx, peer).await,
    }
}

async fn serve_socks4<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if matches!(auth, SocksInboundAuth::Password(_)) {
        stream.write_all(&SOCKS4_REJECTED).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks 4 is not allowed when auth is required.",
        ));
    }
    let request = timeout(
        crate::policy::get().handshake,
        parse_socks4_connect(&mut stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks handshake timeout"))?;
    let target = match request {
        Ok(target) => target,
        Err(e) => {
            stream.write_all(&SOCKS4_REJECTED).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("socks4: {e}"),
            ));
        }
    };
    stream.write_all(&SOCKS4_GRANTED).await?;
    stream.flush().await?;
    let _online = stats::get().connect("", 0, peer.ip());
    let (host, port) = target_to_host_port(&target);
    relay_tcp(stream, ctx, "", peer, host, port, Vec::new()).await
}

async fn serve_socks5<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
    udp_enabled: bool,
    ctx: &Context,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let auth_user = timeout(
        crate::policy::get().handshake,
        negotiate_socks5(&mut stream, auth),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks handshake timeout"))?
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("socks auth: {e}")))?;

    let email = auth_user
        .as_ref()
        .map(|u| u.as_str().to_owned())
        .unwrap_or_default();
    let _online = stats::get().connect(&email, 0, peer.ip());

    let req = timeout(
        crate::policy::get().handshake,
        parse_socks5_request_message(&mut stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks request timeout"))?
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("socks request: {e}")))?;

    match req.command {
        SocksCommand::Connect => {
            // Like Xray, reply before dialing: the first payload is needed for routing.
            write_socks5_success(&mut stream)
                .await
                .map_err(|e| io::Error::other(format!("{e}")))?;
            stream.flush().await?;
            let (host, port) = target_to_host_port(&req.target);
            relay_tcp(stream, ctx, &email, peer, host, port, Vec::new()).await
        }
        SocksCommand::UdpAssociate => {
            if !udp_enabled {
                let _ = write_socks5_command_not_supported(&mut stream).await;
                return Ok(());
            }
            let relay_ip = local.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |a| a.ip().to_canonical());
            let udp_relay = UdpSocket::bind((relay_ip, 0)).await?;
            write_socks5_success_with_bind(&mut stream, udp_relay.local_addr()?)
                .await
                .map_err(|e| io::Error::other(format!("{e}")))?;
            stream.flush().await?;

            // The association lives as long as its TCP connection.
            let tcp_closed = async {
                let mut discard = [0u8; 1];
                let _ = stream.read(&mut discard).await;
                Ok(())
            };
            tokio::select! {
                r = relay_udp(&udp_relay, ctx, &email, peer) => r,
                r = tcp_closed => r,
            }
        }
    }
}

/// Relays a SOCKS UDP association. The first datagram picks the outbound, like a
/// VLESS UDP session; later datagrams routed elsewhere are dropped.
async fn relay_udp(
    udp_relay: &UdpSocket,
    ctx: &Context,
    email: &str,
    peer: SocketAddr,
) -> io::Result<()> {
    let mut buf = vec![0u8; 65535];
    let (first, client) = loop {
        let (n, from) = timeout(CONN_IDLE, udp_relay.recv_from(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
        if from.ip().to_canonical() != peer.ip().to_canonical() {
            continue;
        }
        if let Ok(datagram) = parse_socks5_udp_datagram(&buf[..n]) {
            break (datagram, from);
        }
    };
    let (host, port) = target_to_host_port(&first.target);
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email,
        peer,
        network: Network::Udp,
        host: &host,
        port,
        sniffing: &ctx.sniffing,
    };
    let Some(decision) = route.allow(&ctx.router, &first.payload).await else {
        return Ok(());
    };
    if let Action::Block(_) = decision.action {
        return Ok(());
    }
    let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
    let traffic = stats::get().traffic(&ctx.tag, email, 0, &decision.tag);
    let activity = Activity::new();
    if let Ok(target) = cone.target(&host, port).await {
        cone.send_to(&first.payload, target).await?;
        traffic.up(first.payload.len());
    }

    let up = Box::pin(async {
        loop {
            let (n, from) = udp_relay.recv_from(&mut buf).await?;
            if from != client {
                continue;
            }
            activity.touch();
            let Ok(datagram) = parse_socks5_udp_datagram(&buf[..n]) else {
                continue;
            };
            let (host, port) = target_to_host_port(&datagram.target);
            let (domain, ip) = match &host {
                Host::Domain(name) => (Some(name.as_str()), None),
                Host::Ip(ip) => (None, Some(*ip)),
            };
            let query = Query {
                inbound: &ctx.tag,
                inbound_port: ctx.port,
                user: email,
                source: peer,
                network: Network::Udp,
                domain,
                ip,
                port,
                protocol: None,
                attributes: None,
                local_ip: None,
                vless_route: None,
            };
            if ctx.router.route(&query).await.tag != decision.tag {
                log::debug(format!(
                    "socks udp to {}:{port} dropped: routed off the session outbound",
                    host_label(&host)
                ));
                continue;
            }
            if let Ok(target) = cone.target(&host, port).await {
                let _ = cone.send_to(&datagram.payload, target).await;
                traffic.up(datagram.payload.len());
            }
        }
    });
    let down = Box::pin(async {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = cone.recv_from(&mut buf).await?;
            activity.touch();
            let target = Target::new(
                TargetAddr::Ip(from.ip()),
                from.port(),
                xray_routing::Network::Udp,
            );
            if let Ok(wire) = encode_socks5_udp_datagram(&target, &buf[..n]) {
                let _ = udp_relay.send_to(&wire, client).await;
                traffic.down(n);
            }
        }
    });
    relay(up, down, &activity).await
}

/// Waits for the first payload, routes it and relays a proxied TCP connection.
async fn relay_tcp<S>(
    stream: S,
    ctx: &Context,
    email: &str,
    peer: SocketAddr,
    mut host: Host,
    port: u16,
    mut early: Vec<u8>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut uplink, mut downlink) = tokio::io::split(stream);
    if early.is_empty() && (ctx.router.needs_sniff() || ctx.sniffing.enabled()) {
        read_first(&mut uplink, &mut early).await;
    }
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
    let target = outbound::connect(&ctx.router, &decision, &host, port).await?;
    let traffic = stats::get().traffic(&ctx.tag, email, 0, &decision.tag);
    let (mut target_r, mut target_w) = tokio::io::split(target);
    if !early.is_empty() {
        target_w.write_all(&early).await?;
        traffic.up(early.len());
    }
    let activity = Activity::new();
    relay(
        copy(&mut uplink, &mut target_w, &activity, |n| traffic.up(n)),
        copy(&mut target_r, &mut downlink, &activity, |n| traffic.down(n)),
        &activity,
    )
    .await
}

const HTTP_CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const HTTP_PROXY_AUTH_REQUIRED: &[u8] =
    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
const HTTP_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_SERVICE_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n";

/// Xray's HTTP server: `CONNECT` is answered before routing; other requests
/// are forwarded one by one, each routed on its own, and the connection takes
/// another request after a response of known length when the client sent
/// `Proxy-Connection: keep-alive`.
pub async fn serve_http<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let accounts = HttpInboundAccounts::from(auth);
    loop {
        let head = timeout(
            crate::policy::get().handshake,
            read_http_request_head(&mut stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "http request timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("http request: {e}")))?;
        let proxy_authorization = head.proxy_authorization.as_deref().map(|v| v.as_slice());
        let Some(user) = accounts.basic_user(proxy_authorization) else {
            stream.write_all(HTTP_PROXY_AUTH_REQUIRED).await?;
            stream.flush().await?;
            return Ok(());
        };
        let email = user
            .as_ref()
            .map(|u| u.as_str().to_owned())
            .unwrap_or_default();
        let _online = stats::get().connect(&email, 0, peer.ip());

        if let Some(target) = head.connect_target() {
            let target = target.map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("http request: {e}"))
            })?;
            stream.write_all(HTTP_CONNECT_ESTABLISHED).await?;
            stream.flush().await?;
            let (host, port) = target_to_host_port(&target);
            return relay_tcp(stream, ctx, &email, peer, host, port, Vec::new()).await;
        }
        let request = match PlainHttpRequest::new(&head) {
            Ok(request) => request,
            Err(PlainHttpError::NoHost) => {
                stream.write_all(HTTP_BAD_REQUEST).await?;
                stream.flush().await?;
                return Ok(());
            }
            Err(PlainHttpError::Malformed) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "http request: malformed",
                ))
            }
        };
        let reusable = forward_plain(&mut stream, &request, ctx, &email, peer).await?;
        if !(reusable && request.keep_alive) {
            return Ok(());
        }
    }
}

/// Sends one request on with `Connection: close` and its response back, and
/// tells whether the client connection can take another: when the response's
/// length was known and every byte went through.
async fn forward_plain<S>(
    stream: &mut S,
    request: &PlainHttpRequest,
    ctx: &Context,
    email: &str,
    peer: SocketAddr,
) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let forwarded = request.forwarded_head();
    let (host, port) = target_to_host_port(&request.destination);
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email,
        peer,
        network: Network::Tcp,
        host: &host,
        port,
        sniffing: &crate::vless::Sniffing::default(),
    };
    let Some(decision) = route.allow(&ctx.router, &forwarded).await else {
        stream.write_all(HTTP_SERVICE_UNAVAILABLE).await?;
        return Ok(false);
    };
    let target: Box<dyn outbound::Stream> = match decision.action {
        // Xray reads the blackhole's `http` answer back like any response.
        Action::Block(_) => Box::new(tokio::io::join(
            crate::routing::BLACKHOLE_HTTP_RESPONSE,
            tokio::io::sink(),
        )),
        _ => match outbound::connect(&ctx.router, &decision, &host, port).await {
            Ok(target) => target,
            Err(e) => {
                log::info(format!("http forward to {}:{port}: {e}", host_label(&host)));
                stream.write_all(HTTP_SERVICE_UNAVAILABLE).await?;
                return Ok(false);
            }
        },
    };
    let traffic = stats::get().traffic(&ctx.tag, email, 0, &decision.tag);
    let activity = Activity::new();
    let (target_r, mut target_w) = tokio::io::split(Touch {
        inner: target,
        activity: &activity,
    });
    let mut target_r = tokio::io::BufReader::new(target_r);
    let (mut client_r, mut client_w) = tokio::io::split(stream);

    let upload = async {
        target_w.write_all(&forwarded).await?;
        traffic.up(forwarded.len());
        let body = match request.body {
            HttpBody::Length(length) => {
                copy_body_length(&mut client_r, &mut target_w, length).await?;
                length
            }
            HttpBody::Chunked => copy_body_chunked(&mut client_r, &mut target_w).await?,
            HttpBody::None | HttpBody::UntilClose => 0,
        };
        traffic.up(body as usize);
        target_w.flush().await
    };
    let download = async {
        let Ok(response) = read_http_response(&mut target_r, &request.method).await else {
            client_w.write_all(HTTP_SERVICE_UNAVAILABLE).await?;
            return Ok(false);
        };
        if let Some(informational) = &response.informational {
            client_w.write_all(informational).await?;
        }
        let head = response.head;
        let client_head = head.client_head(&request.method);
        client_w.write_all(&client_head).await?;
        let body = match head.body {
            HttpBody::Length(length) => {
                copy_body_length(&mut target_r, &mut client_w, length).await?;
                length
            }
            HttpBody::Chunked => copy_body_chunked(&mut target_r, &mut client_w).await?,
            HttpBody::UntilClose => tokio::io::copy(&mut target_r, &mut client_w).await?,
            HttpBody::None => 0,
        };
        traffic.down(client_head.len() + body as usize);
        client_w.flush().await?;
        io::Result::Ok(head.keeps_alive())
    };
    let policy = crate::policy::get();
    tokio::select! {
        (uploaded, downloaded) = async { tokio::join!(upload, download) } => {
            Ok(uploaded.is_ok() && downloaded.unwrap_or(false))
        }
        () = crate::vless::idle_for(&activity, policy.conn_idle) => Ok(false),
    }
}

/// Marks activity whenever bytes move to or from the target.
struct Touch<'a, S> {
    inner: S,
    activity: &'a Activity,
}

impl<S: AsyncRead + Unpin> AsyncRead for Touch<'_, S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let filled = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > filled {
            self.activity.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Touch<'_, S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(poll, std::task::Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn target_to_host_port(target: &Target) -> (Host, u16) {
    let host = match &target.addr {
        TargetAddr::Ip(ip) => Host::Ip(*ip),
        TargetAddr::Domain(d) => Host::Domain(d.clone()),
    };
    (host, target.port)
}
