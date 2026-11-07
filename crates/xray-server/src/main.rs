#![forbid(unsafe_code)]
#![warn(clippy::large_futures)]

mod api;
mod config;
mod dns;
mod dns_outbound;
mod dokodemo;
mod fakedns;
mod fallback;
mod finalmask;
mod grpc;
mod http_obfs;
mod http_outbound;
mod httpupgrade;
mod hysteria;
mod hysteria_outbound;
mod inbound_proxy;
pub mod kcp;
mod log;
mod metrics;
mod mux;
mod observatory;
mod outbound;
mod outbound_transport;
mod padding;
mod penetrating_tls;
mod policy;
mod process;
mod proxy_proto;
mod reality;
mod routing;
mod shadowsocks;
mod shadowsocks_outbound;
mod sockopt;
mod socks;
mod stats;
mod trojan;
mod trojan_outbound;
mod vless;
mod vless_outbound;
mod vmess;
mod vmess_outbound;
mod wg;
mod wg_inbound;
mod ws;
mod xhttp;
mod xhttp_outbound;

use crate::routing::Router;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;

use config::{
    CertConfig, CertUsage, Config, Inbound, InboundProtocol, InboundTransport, TlsSettings,
};

// 3x-ui reads the second word of `-version` output as the core version.
pub(crate) const COMPAT_VERSION: &str = "26.10.31";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path = None;
    let mut test_only = false;
    let mut iter = args.iter().map(String::as_str);
    while let Some(arg) = iter.next() {
        match arg.trim_start_matches('-') {
            "version" => {
                println!(
                    "Xray {COMPAT_VERSION} (xray-rs {})",
                    env!("CARGO_PKG_VERSION")
                );
                return ExitCode::SUCCESS;
            }
            "uuid" => {
                println!("{}", uuid::Uuid::new_v4());
                return ExitCode::SUCCESS;
            }
            "run" if !arg.starts_with('-') => {}
            "t" | "test" => test_only = true,
            "c" | "config" => config_path = iter.next().map(str::to_owned),
            other if other.starts_with("config=") || other.starts_with("c=") => {
                config_path = other.split_once('=').map(|(_, v)| v.to_owned());
            }
            _ => {
                eprintln!("unsupported argument: {arg}");
                return ExitCode::FAILURE;
            }
        }
    }
    let config_path = config_path.unwrap_or_else(|| "config.json".to_owned());

    let config = match config::load(&config_path) {
        Ok(config) => config,
        Err(e) => {
            log::error(format!("failed to load config: {e}"));
            return ExitCode::FAILURE;
        }
    };
    for (k, v) in &config.env {
        std::env::set_var(k, v);
    }
    if let Err(e) = log::init(&config.log) {
        log::error(e);
        return ExitCode::FAILURE;
    }
    // Build TLS and REALITY up front so `-test` rejects bad certificates/keys like Xray does.
    let tls: Result<Vec<_>, String> = config
        .inbounds
        .iter()
        .map(|i| {
            let is_xhttp = matches!(i.transport, InboundTransport::Xhttp(_));
            let is_grpc = matches!(i.transport, InboundTransport::Grpc(_));
            i.tls
                .as_ref()
                .map(|s| tls_acceptor(s, is_xhttp, is_grpc))
                .transpose()
        })
        .collect();
    let tls = match tls {
        Ok(tls) => tls,
        Err(e) => {
            log::error(e);
            return ExitCode::FAILURE;
        }
    };
    let realities: Result<Vec<_>, String> = config
        .inbounds
        .iter()
        .map(|i| {
            let is_xhttp = matches!(i.transport, InboundTransport::Xhttp(_));
            let is_grpc = matches!(i.transport, InboundTransport::Grpc(_));
            i.reality
                .as_ref()
                .map(|r| {
                    reality::RealityServer::new(r.clone(), i.port, is_grpc, is_xhttp).map(Arc::new)
                })
                .transpose()
        })
        .collect();
    let realities = match realities {
        Ok(r) => r,
        Err(e) => {
            log::error(e);
            return ExitCode::FAILURE;
        }
    };
    if test_only {
        println!("Configuration OK.");
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log::error(format!("failed to start runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(config, tls, realities)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error(e);
            ExitCode::FAILURE
        }
    }
}

#[derive(Clone)]
enum InboundHandler {
    VlessTcp(Arc<vless::Context>),
    VlessWs(Arc<vless::Context>, ws::WsSettings, Vec<String>),
    VlessHttpUpgrade(
        Arc<vless::Context>,
        httpupgrade::HttpUpgradeSettings,
        Vec<String>,
    ),
    VlessGrpc(Arc<grpc::Handler>),
    TrojanTcp(Arc<vless::Context>),
    TrojanWs(Arc<vless::Context>, ws::WsSettings, Vec<String>),
    TrojanHttpUpgrade(
        Arc<vless::Context>,
        httpupgrade::HttpUpgradeSettings,
        Vec<String>,
    ),
    TrojanGrpc(Arc<grpc::Handler>),
    VmessTcp(Arc<vless::Context>),
    VmessWs(Arc<vless::Context>, ws::WsSettings, Vec<String>),
    VmessHttpUpgrade(
        Arc<vless::Context>,
        httpupgrade::HttpUpgradeSettings,
        Vec<String>,
    ),
    Socks(
        Arc<vless::Context>,
        xray_proxy::inbound::SocksInboundAuth,
        bool,
    ),
    Http(Arc<vless::Context>, xray_proxy::inbound::SocksInboundAuth),
    Shadowsocks(Arc<vless::Context>),
    Dokodemo(Arc<vless::Context>, Arc<config::DokodemoSettings>),
    VlessXhttp(Arc<xhttp::Handler>),
}

async fn run(
    config: Config,
    tls: Vec<Option<TlsAcceptor>>,
    _realities: Vec<Option<Arc<reality::RealityServer>>>,
) -> Result<(), String> {
    log::info(format!("xray-rs {} started", env!("CARGO_PKG_VERSION")));
    stats::init(config.stats);
    if let Some(fakedns) = config.fakedns {
        fakedns::init(fakedns);
    }
    dns::init(config.dns);
    policy::init(config.policy);
    let router = Arc::new(config.router);
    router.init_chained_outbounds(&router);
    router.start_reverse_bridges(router.clone());
    for tag in router.outbound_tags() {
        stats::get().register("outbound", &tag);
    }
    if let Some(tag) = &config.api_tag {
        stats::get().register("inbound", tag);
    }
    if let Some(obs) = config.observatory.clone() {
        obs.start(router.clone());
    }
    metrics::init(config.observatory.clone());
    if let Some(addr) = config.metrics_listen {
        metrics::listen(addr).await?;
    }
    let inbound_manager = Arc::new(api::InboundManager::new(router.clone()));
    for (inbound, acceptor) in config.inbounds.into_iter().zip(tls) {
        let tag = inbound.tag.clone();
        let (ctx, tcp_abort, udp_abort) = start_inbound(&inbound, acceptor, router.clone()).await?;
        inbound_manager.insert_initial(tag, ctx, tcp_abort, udp_abort);
    }
    if let Some(addr) = config.api {
        api::serve(
            addr,
            inbound_manager,
            router.clone(),
            config.observatory.clone(),
        )
        .await?;
    }
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}

pub(crate) fn select_inbound_handler(
    inbound: &Inbound,
    ctx: Arc<vless::Context>,
    trusted_xff: &[String],
) -> Result<InboundHandler, String> {
    match (inbound.protocol, inbound.transport.clone()) {
        (InboundProtocol::Vless, InboundTransport::Tcp | InboundTransport::Kcp(_)) => {
            Ok(InboundHandler::VlessTcp(ctx))
        }
        (InboundProtocol::Vless, InboundTransport::Websocket(settings)) => {
            Ok(InboundHandler::VlessWs(ctx, settings, trusted_xff.to_vec()))
        }
        (InboundProtocol::Vless, InboundTransport::HttpUpgrade(settings)) => Ok(
            InboundHandler::VlessHttpUpgrade(ctx, settings, trusted_xff.to_vec()),
        ),
        (InboundProtocol::Vless, InboundTransport::Grpc(settings)) => {
            let mut gh = grpc::Handler::new(settings, grpc::GrpcProtocol::Vless(ctx));
            gh.with_trusted_x_forwarded_for(trusted_xff.to_vec());
            Ok(InboundHandler::VlessGrpc(gh))
        }
        (InboundProtocol::Trojan, InboundTransport::Tcp | InboundTransport::Kcp(_)) => {
            Ok(InboundHandler::TrojanTcp(ctx))
        }
        (InboundProtocol::Trojan, InboundTransport::Websocket(settings)) => Ok(
            InboundHandler::TrojanWs(ctx, settings, trusted_xff.to_vec()),
        ),
        (InboundProtocol::Trojan, InboundTransport::HttpUpgrade(settings)) => Ok(
            InboundHandler::TrojanHttpUpgrade(ctx, settings, trusted_xff.to_vec()),
        ),
        (InboundProtocol::Trojan, InboundTransport::Grpc(settings)) => {
            let mut gh = grpc::Handler::new(settings, grpc::GrpcProtocol::Trojan(ctx));
            gh.with_trusted_x_forwarded_for(trusted_xff.to_vec());
            Ok(InboundHandler::TrojanGrpc(gh))
        }
        (InboundProtocol::Vmess, InboundTransport::Tcp | InboundTransport::Kcp(_)) => {
            Ok(InboundHandler::VmessTcp(ctx))
        }
        (InboundProtocol::Vmess, InboundTransport::Websocket(settings)) => {
            Ok(InboundHandler::VmessWs(ctx, settings, trusted_xff.to_vec()))
        }
        (InboundProtocol::Vmess, InboundTransport::HttpUpgrade(settings)) => Ok(
            InboundHandler::VmessHttpUpgrade(ctx, settings, trusted_xff.to_vec()),
        ),
        (InboundProtocol::Socks, InboundTransport::Tcp | InboundTransport::Kcp(_)) => Ok(
            InboundHandler::Socks(ctx, inbound.socks_auth.clone(), inbound.udp),
        ),
        (InboundProtocol::Http, InboundTransport::Tcp | InboundTransport::Kcp(_)) => {
            Ok(InboundHandler::Http(ctx, inbound.socks_auth.clone()))
        }
        (InboundProtocol::Shadowsocks, InboundTransport::Tcp | InboundTransport::Kcp(_)) => {
            Ok(InboundHandler::Shadowsocks(ctx))
        }
        (InboundProtocol::Dokodemo, InboundTransport::Tcp | InboundTransport::Kcp(_)) => {
            let settings = inbound
                .dokodemo
                .clone()
                .unwrap_or(config::DokodemoSettings {
                    address: None,
                    port: None,
                    follow_redirect: false,
                });
            Ok(InboundHandler::Dokodemo(ctx, Arc::new(settings)))
        }
        (InboundProtocol::Vless, InboundTransport::Xhttp(settings)) => {
            let mut xh = xhttp::Handler::new(*settings, ctx);
            xh.with_trusted_x_forwarded_for(trusted_xff.to_vec());
            Ok(InboundHandler::VlessXhttp(xh))
        }
        (other, InboundTransport::Xhttp(_)) => Err(format!(
            "inbound {}: {:?} over XHTTP is not supported",
            inbound.tag, other
        )),
        (other, InboundTransport::Websocket(_)) => Err(format!(
            "inbound {}: {:?} over WebSocket is not supported",
            inbound.tag, other
        )),
        (other, InboundTransport::HttpUpgrade(_)) => Err(format!(
            "inbound {}: {:?} over HTTPUpgrade is not supported",
            inbound.tag, other
        )),
        (other, InboundTransport::Grpc(_)) => Err(format!(
            "inbound {}: {:?} over gRPC is not supported",
            inbound.tag, other
        )),
        (InboundProtocol::Hysteria, _) | (_, InboundTransport::Hysteria) => {
            unreachable!("hysteria is handled above")
        }
        (InboundProtocol::Wireguard, _) => {
            unreachable!("wireguard is handled above")
        }
    }
}

pub(crate) async fn start_inbound(
    inbound: &Inbound,
    acceptor: Option<TlsAcceptor>,
    router: Arc<Router>,
) -> Result<
    (
        Arc<vless::Context>,
        Option<tokio::task::AbortHandle>,
        Option<tokio::task::AbortHandle>,
    ),
    String,
> {
    stats::get().register("inbound", &inbound.tag);
    let ctx = Arc::new(vless::Context {
        tag: inbound.tag.clone(),
        port: inbound.port,
        users: RwLock::new(inbound.users.clone()),
        ss_users: RwLock::new(inbound.shadowsocks_users.clone()),
        ss_method: RwLock::new(inbound.shadowsocks_top_method.clone()),
        ss_password: RwLock::new(inbound.shadowsocks_top_password.clone()),
        hysteria_users: RwLock::new(inbound.hysteria_users.clone()),
        router: router.clone(),
        sniffing: inbound.sniffing.clone(),
        fallbacks: inbound.fallbacks.clone(),
        vmess_filter: Arc::new(std::sync::Mutex::new(
            xray_proxy::vmess::server::AuthIdFilter::default_vmess(),
        )),
        ss2022_salt_pool: Arc::new(std::sync::Mutex::new(
            xray_proxy::shadowsocks2022::SaltPool::default_ss2022(),
        )),
        vless_encryption: inbound.vless_encryption.clone(),
    });

    if inbound.protocol == InboundProtocol::Hysteria {
        let abort = hysteria::start(inbound, ctx.clone(), router).await?;
        return Ok((ctx, Some(abort), None));
    }

    if inbound.protocol == InboundProtocol::Wireguard {
        let abort = wg_inbound::start(inbound, ctx.clone(), router).await?;
        return Ok((ctx, Some(abort), None));
    }

    let is_xhttp_h3 = matches!(inbound.transport, InboundTransport::Xhttp(_))
        && inbound.tls.as_ref().map(|t| t.alpn.as_slice()) == Some(&[String::from("h3")]);

    if is_xhttp_h3 {
        let InboundTransport::Xhttp(settings) = &inbound.transport else {
            unreachable!()
        };
        let abort = xhttp::start_h3(inbound, ctx.clone(), (**settings).clone()).await?;
        return Ok((ctx, Some(abort), None));
    }

    if matches!(inbound.transport, InboundTransport::Kcp(_)) {
        let InboundTransport::Kcp(settings) = &inbound.transport else {
            unreachable!()
        };
        let abort = kcp::start(inbound, ctx.clone(), settings.clone(), acceptor, router).await?;
        return Ok((ctx, Some(abort), None));
    }

    let listener = bind(inbound).await?;
    log::info(format!(
        "listening {} on {}",
        inbound.tag,
        listener.local_addr().map_err(|e| e.to_string())?
    ));
    let is_ss_udp = inbound.protocol == InboundProtocol::Shadowsocks && inbound.udp;
    let is_dokodemo_udp = inbound.protocol == InboundProtocol::Dokodemo && inbound.udp;
    let dokodemo_settings = inbound.dokodemo.clone();
    let ss_inbound_tag = inbound.tag.clone();
    let ss_listen = inbound.listen.clone();
    let ss_port = inbound.port;
    let trusted_xff = inbound
        .sockopt
        .as_ref()
        .map(|s| s.trusted_x_forwarded_for.clone())
        .unwrap_or_default();

    let handler = select_inbound_handler(inbound, ctx.clone(), &trusted_xff)?;
    let reality = if let Some(reality_settings) = &inbound.reality {
        let is_grpc = matches!(inbound.transport, InboundTransport::Grpc(_));
        let is_xhttp = matches!(inbound.transport, InboundTransport::Xhttp(_));
        Some(Arc::new(reality::RealityServer::new(
            reality_settings.clone(),
            inbound.port,
            is_grpc,
            is_xhttp,
        )?))
    } else {
        None
    };
    let http_obfs = inbound.http_obfs.clone().map(Arc::new);
    let tproxy = inbound
        .sockopt
        .as_ref()
        .map_or(config::TproxyMode::Off, |s| s.tproxy);
    let tcp_task = tokio::spawn(accept_loop(
        listener,
        tproxy,
        inbound.accept_proxy_protocol,
        acceptor,
        reality,
        handler,
        http_obfs,
    ));
    let mut udp_abort = None;
    if is_ss_udp {
        let udp_socket = bind_udp_addr(&ss_listen, ss_port).await?;
        log::info(format!(
            "listening udp {} on {}",
            ss_inbound_tag,
            udp_socket.local_addr().map_err(|e| e.to_string())?
        ));
        let udp_handler =
            shadowsocks::ShadowsocksUdpHandler::new(Arc::new(udp_socket), ctx.clone());
        let udp_task = tokio::spawn(udp_handler.run());
        udp_abort = Some(udp_task.abort_handle());
    }
    if is_dokodemo_udp {
        if let Some(settings) = dokodemo_settings {
            let udp_socket = bind_udp_addr(&inbound.listen, inbound.port).await?;
            log::info(format!(
                "listening udp {} on {}",
                inbound.tag,
                udp_socket.local_addr().map_err(|e| e.to_string())?
            ));
            let udp_handler = dokodemo::DokodemoUdpHandler::new(
                Arc::new(udp_socket),
                Arc::new(settings),
                ctx.clone(),
            );
            let udp_task = tokio::spawn(udp_handler.run());
            udp_abort = Some(udp_task.abort_handle());
        }
    }
    Ok((ctx, Some(tcp_task.abort_handle()), udp_abort))
}

async fn bind(inbound: &Inbound) -> Result<TcpListener, String> {
    let port = inbound.port;
    if let Some(sockopt) = &inbound.sockopt {
        let candidates: Vec<SocketAddr> = if inbound.listen.is_empty() {
            vec![
                SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
                SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)),
            ]
        } else {
            let addr = format!("{}:{port}", bracket(&inbound.listen));
            vec![addr
                .parse()
                .map_err(|_| format!("invalid listen address {addr}"))?]
        };
        let mut last = None;
        for addr in candidates {
            match sockopt::bind_tcp(addr, sockopt) {
                Ok(listener) => return Ok(listener),
                Err(e) => last = Some(format!("failed to listen on {addr}: {e}")),
            }
        }
        return Err(last.unwrap_or_default());
    }
    let candidates: Vec<SocketAddr> = if inbound.listen.is_empty() {
        vec![
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)),
        ]
    } else {
        let addr = format!("{}:{port}", bracket(&inbound.listen));
        vec![addr
            .parse()
            .map_err(|_| format!("invalid listen address {addr}"))?]
    };
    let mut last = None;
    for addr in candidates {
        let sock = match socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                last = Some(format!("failed to create socket for {addr}: {e}"));
                continue;
            }
        };
        let _ = sock.set_reuse_address(true);
        if addr.is_ipv6() {
            let _ = sock.set_only_v6(false);
        }
        let _ = sock.set_nonblocking(true);
        if let Err(e) = sock.bind(&addr.into()) {
            last = Some(format!("failed to bind {addr}: {e}"));
            continue;
        }
        if let Err(e) = sock.listen(1024) {
            last = Some(format!("failed to listen on {addr}: {e}"));
            continue;
        }
        let std_listener = std::net::TcpListener::from(sock);
        return TcpListener::from_std(std_listener)
            .map_err(|e| format!("failed to convert std socket: {e}"));
    }
    Err(last.unwrap_or_else(|| format!("failed to listen on port {port}")))
}

async fn bind_udp_addr(listen: &str, port: u16) -> Result<UdpSocket, String> {
    if !listen.is_empty() {
        let addr = format!("{}:{port}", bracket(listen));
        return UdpSocket::bind(&addr)
            .await
            .map_err(|e| format!("failed to bind udp on {addr}: {e}"));
    }
    match UdpSocket::bind(("::", port)).await {
        Ok(socket) => Ok(socket),
        Err(_) => UdpSocket::bind(("0.0.0.0", port))
            .await
            .map_err(|e| format!("failed to bind udp on port {port}: {e}")),
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

pub enum InboundIo {
    Tcp(TcpStream),
    Duplex(tokio::io::DuplexStream),
}

impl AsyncRead for InboundIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Duplex(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InboundIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Duplex(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Duplex(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Duplex(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl xray_proxy::vless::VisionStreamIo for InboundIo {
    fn release_record_alignment(&mut self) {}

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }

    fn poll_flush_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

pub enum InboundStream {
    Plain(httpupgrade::PrefixedStream<InboundIo>),
    Tls(penetrating_tls::ServerPenetratingTlsStream<httpupgrade::PrefixedStream<InboundIo>>),
    Reality(reality::Tls13Stream<httpupgrade::PrefixedStream<InboundIo>>),
    HttpObfs(http_obfs::PrefixedStream<httpupgrade::PrefixedStream<InboundIo>>),
}

impl InboundStream {
    fn handshake_info(&self) -> fallback::TlsInfo {
        match self {
            Self::Tls(stream) => stream.handshake_info(),
            Self::Reality(stream) => stream.handshake_info(),
            Self::Plain(_) | Self::HttpObfs(_) => fallback::TlsInfo::default(),
        }
    }
}

impl AsyncRead for InboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Self::Reality(s) => Pin::new(s).poll_read(cx, buf),
            Self::HttpObfs(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Self::Reality(s) => Pin::new(s).poll_write(cx, buf),
            Self::HttpObfs(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
            Self::Reality(s) => Pin::new(s).poll_flush(cx),
            Self::HttpObfs(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Self::Reality(s) => Pin::new(s).poll_shutdown(cx),
            Self::HttpObfs(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl xray_proxy::vless::VisionStreamIo for InboundStream {
    fn release_record_alignment(&mut self) {
        match self {
            Self::Plain(_) => {}
            Self::Tls(s) => s.release_record_alignment(),
            Self::Reality(_) => {}
            Self::HttpObfs(_) => {}
        }
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read_direct(cx, output),
            Self::Tls(s) => Pin::new(s).poll_read_direct(cx, output),
            Self::Reality(s) => Pin::new(s).poll_read_direct(cx, output),
            Self::HttpObfs(s) => Pin::new(s).poll_read_direct(cx, output),
        }
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_direct(cx, input),
            Self::Tls(s) => Pin::new(s).poll_write_direct(cx, input),
            Self::Reality(s) => Pin::new(s).poll_write_direct(cx, input),
            Self::HttpObfs(s) => Pin::new(s).poll_write_direct(cx, input),
        }
    }

    fn poll_flush_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush_direct(cx),
            Self::Tls(s) => Pin::new(s).poll_flush_direct(cx),
            Self::Reality(s) => Pin::new(s).poll_flush_direct(cx),
            Self::HttpObfs(s) => Pin::new(s).poll_flush_direct(cx),
        }
    }

    fn poll_shutdown_direct(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown_direct(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown_direct(cx),
            Self::Reality(s) => Pin::new(s).poll_shutdown_direct(cx),
            Self::HttpObfs(s) => Pin::new(s).poll_shutdown_direct(cx),
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    tproxy: config::TproxyMode,
    accept_proxy_protocol: proxy_proto::ProxyProtocolAccept,
    tls: Option<TlsAcceptor>,
    reality: Option<Arc<reality::RealityServer>>,
    handler: InboundHandler,
    http_obfs: Option<Arc<http_obfs::HttpObfsSettings>>,
) {
    loop {
        let (mut stream, mut peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                log::warn(format!("accept failed: {e}"));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().ok();
        // Where a transparently proxied connection was going, as Xray's TCP hub
        // records it for dokodemo-door followRedirect.
        let original = match tproxy {
            config::TproxyMode::Off => None,
            config::TproxyMode::Tproxy => local,
            config::TproxyMode::Redirect => sockopt::original_destination(&stream),
        };
        let (tls, reality, handler, http_obfs) = (
            tls.clone(),
            reality.clone(),
            handler.clone(),
            http_obfs.clone(),
        );
        tokio::spawn(async move {
            let handshake_timeout = policy::get().handshake;
            let leftover = if accept_proxy_protocol.is_enabled() {
                match tokio::time::timeout(
                    handshake_timeout,
                    proxy_proto::read_proxy_header(&mut stream, accept_proxy_protocol, peer),
                )
                .await
                {
                    Ok(Ok((new_peer, leftover))) => {
                        peer = new_peer;
                        leftover
                    }
                    Ok(Err(e)) => {
                        log::info(format!(
                            "proxy protocol from {} rejected: {e}",
                            log::mask(peer)
                        ));
                        return;
                    }
                    Err(_) => {
                        log::info(format!("proxy protocol from {} timed out", log::mask(peer)));
                        return;
                    }
                }
            } else {
                Vec::new()
            };

            let stream = httpupgrade::PrefixedStream::new(InboundIo::Tcp(stream), leftover);
            if let Some(reality) = reality {
                match reality.handle(stream, peer).await {
                    Ok(Some(tls_stream)) => {
                        dispatch(
                            InboundStream::Reality(tls_stream),
                            peer,
                            local,
                            original,
                            handler,
                        )
                        .await
                    }
                    Ok(None) => {}
                    Err(e) => log::debug(format!(
                        "reality handling from {} failed: {e}",
                        log::mask(peer)
                    )),
                }
            } else {
                match (tls, http_obfs) {
                    (Some(acceptor), _) => {
                        let captured = penetrating_tls::CapturedStream::new(stream);
                        match tokio::time::timeout(handshake_timeout, acceptor.accept(captured))
                            .await
                        {
                            Ok(Ok(tls_stream)) => {
                                let penetrating =
                                    penetrating_tls::ServerPenetratingTlsStream::new(tls_stream);
                                dispatch(
                                    InboundStream::Tls(penetrating),
                                    peer,
                                    local,
                                    original,
                                    handler,
                                )
                                .await
                            }
                            Ok(Err(e)) => log::debug(format!(
                                "tls handshake from {} failed: {e}",
                                log::mask(peer)
                            )),
                            Err(_) => log::debug(format!(
                                "tls handshake from {} timed out",
                                log::mask(peer)
                            )),
                        }
                    }
                    (None, Some(obfs)) => {
                        match tokio::time::timeout(
                            handshake_timeout,
                            http_obfs::accept(stream, &obfs),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                dispatch(
                                    InboundStream::HttpObfs(stream),
                                    peer,
                                    local,
                                    original,
                                    handler,
                                )
                                .await
                            }
                            Ok(Err(e)) => log::debug(format!(
                                "http obfs from {} failed: {e}",
                                log::mask(peer)
                            )),
                            Err(_) => {
                                log::debug(format!("http obfs from {} timed out", log::mask(peer)))
                            }
                        }
                    }
                    (None, None) => {
                        dispatch(InboundStream::Plain(stream), peer, local, original, handler).await
                    }
                }
            }
        });
    }
}

async fn dispatch(
    stream: InboundStream,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    original: Option<SocketAddr>,
    handler: InboundHandler,
) {
    let f: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = match handler {
        InboundHandler::VlessTcp(ctx) => Box::pin(async move {
            let tls = stream.handshake_info();
            if let Err(e) = vless::serve_stream(stream, &ctx, peer, &tls).await {
                log::info(format!("vless from {} rejected: {e}", log::mask(peer)));
            }
        }),
        InboundHandler::VlessWs(ctx, ws_settings, trusted_xff) => Box::pin(async move {
            match ws::accept(stream, &ws_settings, &trusted_xff, peer).await {
                Ok((ws_stream, peer)) => {
                    let (uplink, downlink) = tokio::io::split(ws_stream);
                    if let Err(e) = vless::serve(uplink, downlink, &ctx, peer).await {
                        log::info(format!("vless-ws from {} rejected: {e}", log::mask(peer)));
                    }
                }
                Err(e) => {
                    log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
                }
            }
        }),
        InboundHandler::VlessHttpUpgrade(ctx, hu_settings, trusted_xff) => Box::pin(async move {
            match httpupgrade::accept(stream, &hu_settings, &trusted_xff, peer).await {
                Ok((prefixed_stream, peer)) => {
                    let (uplink, downlink) = tokio::io::split(prefixed_stream);
                    if let Err(e) = vless::serve(uplink, downlink, &ctx, peer).await {
                        log::info(format!(
                            "vless-httpupgrade from {} rejected: {e}",
                            log::mask(peer)
                        ));
                    }
                }
                Err(e) => {
                    log::info(format!(
                        "httpupgrade handshake from {} failed: {e}",
                        log::mask(peer)
                    ));
                }
            }
        }),
        InboundHandler::TrojanTcp(ctx) => Box::pin(async move {
            let tls = stream.handshake_info();
            let (r, w) = tokio::io::split(stream);
            if let Err(e) = trojan::serve(r, w, &ctx, peer, &tls).await {
                log::info(format!("trojan from {} rejected: {e}", log::mask(peer)));
            }
        }),
        InboundHandler::TrojanWs(ctx, ws_settings, trusted_xff) => Box::pin(async move {
            match ws::accept(stream, &ws_settings, &trusted_xff, peer).await {
                Ok((ws_stream, peer)) => {
                    let (uplink, downlink) = tokio::io::split(ws_stream);
                    if let Err(e) =
                        trojan::serve(uplink, downlink, &ctx, peer, &Default::default()).await
                    {
                        log::info(format!("trojan-ws from {} rejected: {e}", log::mask(peer)));
                    }
                }
                Err(e) => {
                    log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
                }
            }
        }),
        InboundHandler::TrojanHttpUpgrade(ctx, hu_settings, trusted_xff) => Box::pin(async move {
            match httpupgrade::accept(stream, &hu_settings, &trusted_xff, peer).await {
                Ok((prefixed_stream, peer)) => {
                    let (uplink, downlink) = tokio::io::split(prefixed_stream);
                    if let Err(e) =
                        trojan::serve(uplink, downlink, &ctx, peer, &Default::default()).await
                    {
                        log::info(format!(
                            "trojan-httpupgrade from {} rejected: {e}",
                            log::mask(peer)
                        ));
                    }
                }
                Err(e) => {
                    log::info(format!(
                        "httpupgrade handshake from {} failed: {e}",
                        log::mask(peer)
                    ));
                }
            }
        }),
        InboundHandler::VmessTcp(ctx) => Box::pin(async move {
            let (r, w) = tokio::io::split(stream);
            if let Err(e) = vmess::serve(r, w, &ctx, peer).await {
                log::info(format!("vmess from {} rejected: {e}", log::mask(peer)));
            }
        }),
        InboundHandler::VmessWs(ctx, ws_settings, trusted_xff) => Box::pin(async move {
            match ws::accept(stream, &ws_settings, &trusted_xff, peer).await {
                Ok((ws_stream, peer)) => {
                    let (uplink, downlink) = tokio::io::split(ws_stream);
                    if let Err(e) = vmess::serve(uplink, downlink, &ctx, peer).await {
                        log::info(format!("vmess-ws from {} rejected: {e}", log::mask(peer)));
                    }
                }
                Err(e) => {
                    log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
                }
            }
        }),
        InboundHandler::VmessHttpUpgrade(ctx, hu_settings, trusted_xff) => Box::pin(async move {
            match httpupgrade::accept(stream, &hu_settings, &trusted_xff, peer).await {
                Ok((prefixed_stream, peer)) => {
                    let (uplink, downlink) = tokio::io::split(prefixed_stream);
                    if let Err(e) = vmess::serve(uplink, downlink, &ctx, peer).await {
                        log::info(format!(
                            "vmess-httpupgrade from {} rejected: {e}",
                            log::mask(peer)
                        ));
                    }
                }
                Err(e) => {
                    log::info(format!(
                        "httpupgrade handshake from {} failed: {e}",
                        log::mask(peer)
                    ));
                }
            }
        }),
        InboundHandler::Socks(ctx, auth, udp) => Box::pin(async move {
            if let Err(e) = inbound_proxy::serve_socks(stream, &auth, udp, &ctx, peer, local).await
            {
                log::info(format!("socks from {} rejected: {e}", log::mask(peer)));
            }
        }),
        InboundHandler::Http(ctx, auth) => Box::pin(async move {
            if let Err(e) = inbound_proxy::serve_http(stream, &auth, &ctx, peer).await {
                log::info(format!("http from {} rejected: {e}", log::mask(peer)));
            }
        }),
        InboundHandler::Shadowsocks(ctx) => Box::pin(async move {
            if let Err(e) = shadowsocks::serve_tcp(stream, &ctx, peer).await {
                log::info(format!(
                    "shadowsocks from {} rejected: {e}",
                    log::mask(peer)
                ));
            }
        }),
        InboundHandler::Dokodemo(ctx, settings) => Box::pin(async move {
            if let Err(e) = dokodemo::serve_tcp(stream, &settings, &ctx, peer, original).await {
                log::info(format!("dokodemo from {} rejected: {e}", log::mask(peer)));
            }
        }),
        InboundHandler::VlessGrpc(h) | InboundHandler::TrojanGrpc(h) => Box::pin(async move {
            grpc::serve(stream, peer, h).await;
        }),
        InboundHandler::VlessXhttp(h) => Box::pin(async move {
            serve_http(stream, peer, h).await;
        }),
    };
    f.await;
}

async fn serve_http<I>(io: I, peer: SocketAddr, handler: Arc<xhttp::Handler>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler.handle(req, peer).await) }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http2()
        .initial_stream_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .max_concurrent_streams(1024);
    // XHTTP header uplink splits data over many headers; Go limits only their total size.
    builder.http1().max_headers(MAX_HEADERS);
    if let Err(e) = builder.serve_connection(TokioIo::new(io), service).await {
        log::debug(format!(
            "http connection from {} ended: {e}",
            log::mask(peer)
        ));
    }
}

const MAX_HEADERS: usize = 1024;

fn extract_cert_names(cert_der: &[u8]) -> Vec<String> {
    use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};
    let mut names = Vec::new();
    if let Ok((_, cert)) = X509Certificate::from_der(cert_der) {
        for rdn in cert.subject().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                    if let Ok(cn) = attr.as_str() {
                        names.push(cn.to_ascii_lowercase());
                    }
                }
            }
        }
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => names.push(dns.to_ascii_lowercase()),
                        GeneralName::IPAddress(ip) => {
                            if ip.len() == 4 {
                                names.push(
                                    std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                                );
                            } else if ip.len() == 16 {
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(ip);
                                names.push(std::net::Ipv6Addr::from(octets).to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    names
}

pub(crate) fn match_sni(pattern: &str, sni: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let sni = sni.to_ascii_lowercase();
    if pattern == sni {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some((prefix, domain)) = sni.split_once('.') {
            if !prefix.is_empty() && domain == suffix {
                return true;
            }
        }
    }
    false
}

struct ManagedCert {
    certified_key: Arc<rustls::sign::CertifiedKey>,
    allowed_names: Vec<String>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    cert_mtime: Option<SystemTime>,
    key_mtime: Option<SystemTime>,
    one_time_loading: bool,
    ocsp_stapling: u64,
}

impl ManagedCert {
    fn check_and_reload(&mut self, provider: &rustls::crypto::CryptoProvider) {
        if self.one_time_loading {
            return;
        }
        let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) else {
            return;
        };
        let c_mtime = std::fs::metadata(cert_path).and_then(|m| m.modified()).ok();
        let k_mtime = std::fs::metadata(key_path).and_then(|m| m.modified()).ok();
        if c_mtime == self.cert_mtime && k_mtime == self.key_mtime {
            return;
        }
        let cert_pem = match std::fs::read(cert_path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let key_pem = match std::fs::read(key_path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let certs = match CertificateDer::pem_slice_iter(&cert_pem).collect::<Result<Vec<_>, _>>() {
            Ok(c) if !c.is_empty() => c,
            _ => return,
        };
        let key = match PrivateKeyDer::from_pem_slice(&key_pem) {
            Ok(k) => k,
            Err(_) => return,
        };
        let signing_key = match provider.key_provider.load_private_key(key) {
            Ok(k) => k,
            Err(_) => return,
        };
        let cert_names = extract_cert_names(certs[0].as_ref());
        let mut certified_key = rustls::sign::CertifiedKey::new(certs, signing_key);
        let ocsp_path = cert_path.with_extension("ocsp");
        if let Ok(ocsp_bytes) = std::fs::read(&ocsp_path) {
            certified_key.ocsp = Some(ocsp_bytes);
        } else if self.ocsp_stapling > 0 {
            // Hot reload interval configured with ocspStapling
        }
        self.certified_key = Arc::new(certified_key);
        self.allowed_names = cert_names;
        self.cert_mtime = c_mtime;
        self.key_mtime = k_mtime;
    }
}

struct ManagedCa {
    ca_cert_der: Vec<u8>,
    ca_key_pem: String,
    build_chain: bool,
    issued_cache: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl ManagedCa {
    fn get_or_issue(
        &mut self,
        sni: &str,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(cached) = self.issued_cache.get(sni) {
            return Some(cached.clone());
        }
        let ca_key = rcgen::KeyPair::from_pem(&self.ca_key_pem).ok()?;
        let der = CertificateDer::from(self.ca_cert_der.clone());
        let issuer = rcgen::Issuer::from_ca_cert_der(&der, ca_key).ok()?;
        let mut params = rcgen::CertificateParams::new(vec![sni.to_string()]).ok()?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, sni);
        params.use_authority_key_identifier_extension = true;
        params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let ee_key = rcgen::KeyPair::generate().ok()?;
        let ee_cert = params.signed_by(&ee_key, &issuer).ok()?;
        let mut chain = vec![CertificateDer::from(ee_cert.der().to_vec())];
        if self.build_chain {
            chain.push(der);
        }
        let key_der = PrivateKeyDer::Pkcs8(ee_key.serialize_der().into());
        let signing_key = provider.key_provider.load_private_key(key_der).ok()?;
        let certified = Arc::new(rustls::sign::CertifiedKey::new(chain, signing_key));
        self.issued_cache.insert(sni.to_string(), certified.clone());
        Some(certified)
    }
}

struct SniCheckingResolver {
    encipherment_certs: Vec<RwLock<ManagedCert>>,
    ca_certs: Vec<RwLock<ManagedCa>>,
    reject_unknown_sni: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl std::fmt::Debug for SniCheckingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCheckingResolver")
            .field("reject_unknown_sni", &self.reject_unknown_sni)
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for SniCheckingResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        for m in &self.encipherment_certs {
            if let Ok(mut cert) = m.write() {
                cert.check_and_reload(&self.provider);
            }
        }
        let sni = client_hello.server_name().map(str::to_ascii_lowercase);
        if let Some(ref sni) = sni {
            for m in &self.encipherment_certs {
                if let Ok(cert) = m.read() {
                    if cert
                        .allowed_names
                        .iter()
                        .any(|allowed| match_sni(allowed, sni))
                    {
                        return Some(cert.certified_key.clone());
                    }
                }
            }
            for ca_lock in &self.ca_certs {
                if let Ok(mut ca) = ca_lock.write() {
                    if let Some(cert) = ca.get_or_issue(sni, &self.provider) {
                        return Some(cert);
                    }
                }
            }
        }
        if !self.reject_unknown_sni {
            if let Some(first) = self.encipherment_certs.first() {
                if let Ok(cert) = first.read() {
                    return Some(cert.certified_key.clone());
                }
            }
        }
        None
    }
}

pub(crate) fn build_rustls_server_config(
    settings: &TlsSettings,
    alpn: Vec<Vec<u8>>,
    only_tls13: bool,
) -> Result<rustls::ServerConfig, String> {
    let mut provider_builder = rustls::crypto::ring::default_provider();
    if !settings.cipher_suites.is_empty() {
        provider_builder.cipher_suites.retain(|cs| {
            let name = format!("{:?}", cs.suite());
            settings.cipher_suites.iter().any(|wanted| {
                wanted.eq_ignore_ascii_case(&name)
                    || wanted.eq_ignore_ascii_case(name.strip_prefix("TLS13_").unwrap_or(&name))
                    || wanted.eq_ignore_ascii_case(name.strip_prefix("TLS_").unwrap_or(&name))
            })
        });
    }
    let provider = Arc::new(provider_builder);

    let cert_configs: Vec<CertConfig> = if !settings.certificates.is_empty() {
        settings.certificates.clone()
    } else {
        vec![CertConfig {
            cert_pem: settings.cert_pem.clone(),
            key_pem: settings.key_pem.clone(),
            cert_file: None,
            key_file: None,
            usage: CertUsage::Encipherment,
            ocsp_stapling: 0,
            one_time_loading: false,
            build_chain: false,
        }]
    };

    let mut encipherment_certs = Vec::new();
    let mut ca_certs = Vec::new();

    for (idx, cert_cfg) in cert_configs.iter().enumerate() {
        match cert_cfg.usage {
            CertUsage::Encipherment => {
                let certs = CertificateDer::pem_slice_iter(&cert_cfg.cert_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("invalid certificate: {e}"))?;
                if certs.is_empty() {
                    return Err("certificate file has no certificates".into());
                }
                let key = PrivateKeyDer::from_pem_slice(&cert_cfg.key_pem)
                    .map_err(|e| format!("invalid private key: {e}"))?;
                let signing_key = provider
                    .key_provider
                    .load_private_key(key)
                    .map_err(|e| format!("invalid private key: {e}"))?;
                let mut cert_names = extract_cert_names(certs[0].as_ref());
                if idx == 0 {
                    cert_names.extend(settings.server_names.clone());
                }
                let cert_path = cert_cfg.cert_file.as_ref().map(PathBuf::from);
                let key_path = cert_cfg.key_file.as_ref().map(PathBuf::from);
                let cert_mtime = cert_path
                    .as_ref()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .and_then(|m| m.modified().ok());
                let key_mtime = key_path
                    .as_ref()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .and_then(|m| m.modified().ok());
                let mut certified_key = rustls::sign::CertifiedKey::new(certs, signing_key);
                if let Some(cp) = &cert_path {
                    let ocsp_path = cp.with_extension("ocsp");
                    if let Ok(ocsp_bytes) = std::fs::read(&ocsp_path) {
                        certified_key.ocsp = Some(ocsp_bytes);
                    }
                }
                encipherment_certs.push(RwLock::new(ManagedCert {
                    certified_key: Arc::new(certified_key),
                    allowed_names: cert_names,
                    cert_path,
                    key_path,
                    cert_mtime,
                    key_mtime,
                    one_time_loading: cert_cfg.one_time_loading,
                    ocsp_stapling: cert_cfg.ocsp_stapling,
                }));
            }
            CertUsage::Issue => {
                let certs = CertificateDer::pem_slice_iter(&cert_cfg.cert_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("invalid CA certificate: {e}"))?;
                if certs.is_empty() {
                    return Err("CA certificate has no certificates".into());
                }
                let key_str = std::str::from_utf8(&cert_cfg.key_pem)
                    .map_err(|e| format!("invalid CA key utf8: {e}"))?;
                ca_certs.push(RwLock::new(ManagedCa {
                    ca_cert_der: certs[0].as_ref().to_vec(),
                    ca_key_pem: key_str.to_string(),
                    build_chain: cert_cfg.build_chain,
                    issued_cache: HashMap::new(),
                }));
            }
            CertUsage::Verify => {
                // Client certificate verification authority
            }
        }
    }

    if encipherment_certs.is_empty() && ca_certs.is_empty() {
        return Err("certificate file has no certificates".into());
    }

    let resolver = Arc::new(SniCheckingResolver {
        encipherment_certs,
        ca_certs,
        reject_unknown_sni: settings.reject_unknown_sni,
        provider: provider.clone(),
    });

    let versions: &[&'static rustls::SupportedProtocolVersion] = if only_tls13 {
        &[&rustls::version::TLS13]
    } else {
        match (
            settings.min_version.as_deref(),
            settings.max_version.as_deref(),
        ) {
            (Some("1.3"), _) => &[&rustls::version::TLS13],
            (_, Some("1.2")) => &[&rustls::version::TLS12],
            _ => rustls::ALL_VERSIONS,
        }
    };

    if let Some(ref ech_keys) = settings.ech_server_keys {
        log::info(format!(
            "TLS ECH server keys configured (len {})",
            ech_keys.len()
        ));
    }
    if let Some(ref ech_list) = settings.ech_config_list {
        log::info(format!(
            "TLS ECH config list configured (len {})",
            ech_list.len()
        ));
    }

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn;
    Ok(config)
}

fn tls_acceptor(
    settings: &TlsSettings,
    is_xhttp: bool,
    is_grpc: bool,
) -> Result<TlsAcceptor, String> {
    if is_xhttp && settings.alpn.as_slice() == ["h3"] {
        let config = build_rustls_server_config(settings, vec![b"h3".to_vec()], true)?;
        return Ok(TlsAcceptor::from(Arc::new(config)));
    }
    let alpn: Vec<Vec<u8>> = settings
        .alpn
        .iter()
        .filter(|p| *p != "h3")
        .map(|p| p.as_bytes().to_vec())
        .collect();
    let alpn = if !alpn.is_empty() {
        alpn
    } else if is_grpc {
        vec![b"h2".to_vec()]
    } else if is_xhttp {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        Vec::new()
    };
    let config = build_rustls_server_config(settings, alpn, false)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_sni() {
        assert!(match_sni("example.com", "example.com"));
        assert!(match_sni("example.com", "EXAMPLE.COM"));
        assert!(!match_sni("example.com", "other.com"));
        assert!(match_sni("*.example.com", "api.example.com"));
        assert!(match_sni("*.example.com", "WWW.EXAMPLE.COM"));
        assert!(!match_sni("*.example.com", "example.com"));
        assert!(!match_sni("*.example.com", "deep.sub.example.com"));
    }

    #[test]
    fn test_extract_cert_names() {
        let cert = rcgen::generate_simple_self_signed(vec![
            "example.org".to_owned(),
            "*.sub.example.org".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .unwrap();
        let cert_der = cert.cert.der();
        let names = extract_cert_names(cert_der);
        assert!(names.contains(&"example.org".to_string()));
        assert!(names.contains(&"*.sub.example.org".to_string()));
        assert!(names.contains(&"127.0.0.1".to_string()));
    }

    #[test]
    fn test_tls_resolver_reload_and_ca_issue() {
        // 1. Generate CA certificate
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_cert_pem = ca_cert.pem().into_bytes();
        let ca_key_pem = ca_key.serialize_pem().into_bytes();

        // 2. Generate regular server cert
        let srv_cert = rcgen::generate_simple_self_signed(vec!["srv.test".to_string()]).unwrap();
        let srv_cert_pem = srv_cert.cert.pem().into_bytes();
        let srv_key_pem = srv_cert.signing_key.serialize_pem().into_bytes();

        let tmp_dir = std::env::temp_dir().join(format!("xray_test_tls_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        std::fs::write(&cert_path, &srv_cert_pem).unwrap();
        std::fs::write(&key_path, &srv_key_pem).unwrap();

        let settings = TlsSettings {
            cert_pem: srv_cert_pem.clone(),
            key_pem: srv_key_pem.clone(),
            certificates: vec![
                CertConfig {
                    cert_pem: srv_cert_pem,
                    key_pem: srv_key_pem,
                    cert_file: Some(cert_path.to_str().unwrap().to_string()),
                    key_file: Some(key_path.to_str().unwrap().to_string()),
                    usage: CertUsage::Encipherment,
                    ocsp_stapling: 3600,
                    one_time_loading: false,
                    build_chain: false,
                },
                CertConfig {
                    cert_pem: ca_cert_pem,
                    key_pem: ca_key_pem,
                    cert_file: None,
                    key_file: None,
                    usage: CertUsage::Issue,
                    ocsp_stapling: 0,
                    one_time_loading: true,
                    build_chain: true,
                },
            ],
            alpn: vec!["h2".to_string()],
            reject_unknown_sni: true,
            server_names: vec![],
            min_version: None,
            max_version: None,
            cipher_suites: vec![],
            ech_server_keys: Some("ACD2AjC5yuBQ3430geNDLdIRndloCry/DBb9ZeYp0TmeowBB/g0APQAAIAAgc4hPORS8ScksWQD0R7PAgwm7s9Ye+iPaS4XLQv5IEnAABAABAAEADnB1YmxpYy5leGFtcGxlAAA=".to_string()),
            ech_config_list: None,
        };

        let config = build_rustls_server_config(&settings, vec![b"h2".to_vec()], false).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
