#![forbid(unsafe_code)]

mod api;
mod config;
mod dns_outbound;
mod dokodemo;
mod fallback;
mod grpc;
mod http_obfs;
mod http_outbound;
mod httpupgrade;
mod inbound_proxy;
mod log;
mod mux;
mod outbound;
mod outbound_transport;
mod padding;
mod proxy_proto;
mod reality;
mod routing;
mod shadowsocks;
mod shadowsocks_outbound;
mod socks;
mod stats;
mod trojan;
mod trojan_outbound;
mod vless;
mod vless_outbound;
mod vmess;
mod vmess_outbound;
mod wg;
mod ws;
mod xhttp;

use crate::routing::Router;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

use config::{Config, Inbound, InboundProtocol, InboundTransport, TlsSettings};

// 3x-ui reads the second word of `-version` output as the core version.
const COMPAT_VERSION: &str = "26.10.31";

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
            "test" => test_only = true,
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
                .map(|r| reality::RealityServer::new(r.clone(), i.port, is_grpc, is_xhttp).map(Arc::new))
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
    VlessWs(Arc<vless::Context>, ws::WsSettings),
    VlessHttpUpgrade(Arc<vless::Context>, httpupgrade::HttpUpgradeSettings),
    VlessGrpc(Arc<grpc::Handler>),
    TrojanTcp(Arc<vless::Context>),
    TrojanWs(Arc<vless::Context>, ws::WsSettings),
    TrojanHttpUpgrade(Arc<vless::Context>, httpupgrade::HttpUpgradeSettings),
    TrojanGrpc(Arc<grpc::Handler>),
    VmessTcp(Arc<vless::Context>),
    VmessWs(Arc<vless::Context>, ws::WsSettings),
    VmessHttpUpgrade(Arc<vless::Context>, httpupgrade::HttpUpgradeSettings),
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
    let router = Arc::new(config.router);
    let inbound_manager = Arc::new(api::InboundManager::new(router.clone()));
    for (inbound, acceptor) in config.inbounds.into_iter().zip(tls) {
        let tag = inbound.tag.clone();
        let (ctx, tcp_abort, udp_abort) = start_inbound(&inbound, acceptor, router.clone()).await?;
        inbound_manager.insert_initial(tag, ctx, tcp_abort, udp_abort);
    }
    if let Some(addr) = config.api {
        api::serve(addr, inbound_manager, router.clone()).await?;
    }
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
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
    let listener = bind(inbound).await?;
    log::info(format!(
        "listening {} on {}",
        inbound.tag,
        listener.local_addr().map_err(|e| e.to_string())?
    ));
    let ctx = Arc::new(vless::Context {
        tag: inbound.tag.clone(),
        port: inbound.port,
        users: RwLock::new(inbound.users.clone()),
        ss_users: RwLock::new(inbound.shadowsocks_users.clone()),
        ss_method: RwLock::new(inbound.shadowsocks_top_method.clone()),
        ss_password: RwLock::new(inbound.shadowsocks_top_password.clone()),
        router: router.clone(),
        sniffing: inbound.sniffing.clone(),
        fallbacks: inbound.fallbacks.clone(),
    });
    let is_ss_udp = inbound.protocol == InboundProtocol::Shadowsocks && inbound.udp;
    let is_dokodemo_udp = inbound.protocol == InboundProtocol::Dokodemo && inbound.udp;
    let dokodemo_settings = inbound.dokodemo.clone();
    let ss_inbound_tag = inbound.tag.clone();
    let ss_listen = inbound.listen.clone();
    let ss_port = inbound.port;

    let handler = match (inbound.protocol, inbound.transport.clone()) {
        (InboundProtocol::Vless, InboundTransport::Tcp) => InboundHandler::VlessTcp(ctx.clone()),
        (InboundProtocol::Vless, InboundTransport::Websocket(settings)) => {
            InboundHandler::VlessWs(ctx.clone(), settings)
        }
        (InboundProtocol::Vless, InboundTransport::HttpUpgrade(settings)) => {
            InboundHandler::VlessHttpUpgrade(ctx.clone(), settings)
        }
        (InboundProtocol::Vless, InboundTransport::Grpc(settings)) => InboundHandler::VlessGrpc(
            grpc::Handler::new(settings, grpc::GrpcProtocol::Vless(ctx.clone())),
        ),
        (InboundProtocol::Trojan, InboundTransport::Tcp) => InboundHandler::TrojanTcp(ctx.clone()),
        (InboundProtocol::Trojan, InboundTransport::Websocket(settings)) => {
            InboundHandler::TrojanWs(ctx.clone(), settings)
        }
        (InboundProtocol::Trojan, InboundTransport::HttpUpgrade(settings)) => {
            InboundHandler::TrojanHttpUpgrade(ctx.clone(), settings)
        }
        (InboundProtocol::Trojan, InboundTransport::Grpc(settings)) => InboundHandler::TrojanGrpc(
            grpc::Handler::new(settings, grpc::GrpcProtocol::Trojan(ctx.clone())),
        ),
        (InboundProtocol::Vmess, InboundTransport::Tcp) => InboundHandler::VmessTcp(ctx.clone()),
        (InboundProtocol::Vmess, InboundTransport::Websocket(settings)) => {
            InboundHandler::VmessWs(ctx.clone(), settings)
        }
        (InboundProtocol::Vmess, InboundTransport::HttpUpgrade(settings)) => {
            InboundHandler::VmessHttpUpgrade(ctx.clone(), settings)
        }
        (InboundProtocol::Socks, InboundTransport::Tcp) => {
            InboundHandler::Socks(ctx.clone(), inbound.socks_auth.clone(), inbound.udp)
        }
        (InboundProtocol::Http, InboundTransport::Tcp) => {
            InboundHandler::Http(ctx.clone(), inbound.socks_auth.clone())
        }
        (InboundProtocol::Shadowsocks, InboundTransport::Tcp) => {
            InboundHandler::Shadowsocks(ctx.clone())
        }
        (InboundProtocol::Dokodemo, InboundTransport::Tcp) => {
            let settings = inbound.dokodemo.clone().unwrap_or(config::DokodemoSettings {
                address: None,
                port: None,
                follow_redirect: false,
            });
            InboundHandler::Dokodemo(ctx.clone(), Arc::new(settings))
        }
        (InboundProtocol::Vless, InboundTransport::Xhttp(settings)) => {
            InboundHandler::VlessXhttp(xhttp::Handler::new(*settings, ctx.clone()))
        }
        (other, InboundTransport::Xhttp(_)) => {
            return Err(format!(
                "inbound {}: {:?} over XHTTP is not supported",
                inbound.tag, other
            ));
        }
        (other, InboundTransport::Websocket(_)) => {
            return Err(format!(
                "inbound {}: {:?} over WebSocket is not supported",
                inbound.tag, other
            ));
        }
        (other, InboundTransport::HttpUpgrade(_)) => {
            return Err(format!(
                "inbound {}: {:?} over HTTPUpgrade is not supported",
                inbound.tag, other
            ));
        }
        (other, InboundTransport::Grpc(_)) => {
            return Err(format!(
                "inbound {}: {:?} over gRPC is not supported",
                inbound.tag, other
            ));
        }
    };
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
    let tcp_task = tokio::spawn(accept_loop(
        listener,
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
    if !inbound.listen.is_empty() {
        let addr = format!("{}:{port}", bracket(&inbound.listen));
        return TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("failed to listen on {addr}: {e}"));
    }
    match TcpListener::bind(("::", port)).await {
        Ok(listener) => Ok(listener),
        Err(_) => TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| format!("failed to listen on port {port}: {e}")),
    }
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

async fn accept_loop(
    listener: TcpListener,
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
        let (tls, reality, handler, http_obfs) = (tls.clone(), reality.clone(), handler.clone(), http_obfs.clone());
        tokio::spawn(async move {
            let leftover = if accept_proxy_protocol.is_enabled() {
                match proxy_proto::read_proxy_header(&mut stream, accept_proxy_protocol, peer).await {
                    Ok((new_peer, leftover)) => {
                        peer = new_peer;
                        leftover
                    }
                    Err(e) => {
                        log::info(format!("proxy protocol from {} rejected: {e}", log::mask(peer)));
                        return;
                    }
                }
            } else {
                Vec::new()
            };

            let stream = httpupgrade::PrefixedStream::new(stream, leftover);
            if let Some(reality) = reality {
                match reality.handle(stream, peer).await {
                    Ok(Some(tls_stream)) => dispatch(tls_stream, peer, local, handler).await,
                    Ok(None) => {}
                    Err(e) => log::debug(format!("reality handling from {} failed: {e}", log::mask(peer))),
                }
            } else {
                match (tls, http_obfs) {
                    (Some(acceptor), _) => match acceptor.accept(stream).await {
                        Ok(stream) => dispatch(stream, peer, local, handler).await,
                        Err(e) => log::debug(format!(
                            "tls handshake from {} failed: {e}",
                            log::mask(peer)
                        )),
                    },
                    (None, Some(obfs)) => match http_obfs::accept(stream, &obfs).await {
                        Ok(stream) => dispatch(stream, peer, local, handler).await,
                        Err(e) => log::debug(format!(
                            "http obfs from {} failed: {e}",
                            log::mask(peer)
                        )),
                    },
                    (None, None) => dispatch(stream, peer, local, handler).await,
                }
            }
        });
    }
}

async fn dispatch<I>(
    stream: I,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    handler: InboundHandler,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match handler {
        InboundHandler::VlessTcp(ctx) => {
            let (r, w) = tokio::io::split(stream);
            if let Err(e) = vless::serve(r, w, &ctx, peer).await {
                log::info(format!("vless from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::VlessWs(ctx, ws_settings) => match ws::accept(stream, &ws_settings).await {
            Ok(ws_stream) => {
                let (uplink, downlink) = tokio::io::split(ws_stream);
                if let Err(e) = vless::serve(uplink, downlink, &ctx, peer).await {
                    log::info(format!("vless-ws from {} rejected: {e}", log::mask(peer)));
                }
            }
            Err(e) => {
                log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
            }
        },
        InboundHandler::VlessHttpUpgrade(ctx, hu_settings) => {
            match httpupgrade::accept(stream, &hu_settings).await {
                Ok(prefixed_stream) => {
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
        }
        InboundHandler::TrojanTcp(ctx) => {
            let (r, w) = tokio::io::split(stream);
            if let Err(e) = trojan::serve(r, w, &ctx, peer).await {
                log::info(format!("trojan from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::TrojanWs(ctx, ws_settings) => {
            match ws::accept(stream, &ws_settings).await {
                Ok(ws_stream) => {
                    let (uplink, downlink) = tokio::io::split(ws_stream);
                    if let Err(e) = trojan::serve(uplink, downlink, &ctx, peer).await {
                        log::info(format!("trojan-ws from {} rejected: {e}", log::mask(peer)));
                    }
                }
                Err(e) => {
                    log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
                }
            }
        }
        InboundHandler::TrojanHttpUpgrade(ctx, hu_settings) => {
            match httpupgrade::accept(stream, &hu_settings).await {
                Ok(prefixed_stream) => {
                    let (uplink, downlink) = tokio::io::split(prefixed_stream);
                    if let Err(e) = trojan::serve(uplink, downlink, &ctx, peer).await {
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
        }
        InboundHandler::VmessTcp(ctx) => {
            let (r, w) = tokio::io::split(stream);
            if let Err(e) = vmess::serve(r, w, &ctx, peer).await {
                log::info(format!("vmess from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::VmessWs(ctx, ws_settings) => match ws::accept(stream, &ws_settings).await {
            Ok(ws_stream) => {
                let (uplink, downlink) = tokio::io::split(ws_stream);
                if let Err(e) = vmess::serve(uplink, downlink, &ctx, peer).await {
                    log::info(format!("vmess-ws from {} rejected: {e}", log::mask(peer)));
                }
            }
            Err(e) => {
                log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
            }
        },
        InboundHandler::VmessHttpUpgrade(ctx, hu_settings) => {
            match httpupgrade::accept(stream, &hu_settings).await {
                Ok(prefixed_stream) => {
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
        }
        InboundHandler::Socks(ctx, auth, udp) => {
            if let Err(e) = inbound_proxy::serve_socks(stream, &auth, udp, &ctx, peer, local).await
            {
                log::info(format!("socks from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::Http(ctx, auth) => {
            if let Err(e) = inbound_proxy::serve_http(stream, &auth, &ctx, peer).await {
                log::info(format!("http from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::Shadowsocks(ctx) => {
            if let Err(e) = shadowsocks::serve_tcp(stream, &ctx, peer).await {
                log::info(format!(
                    "shadowsocks from {} rejected: {e}",
                    log::mask(peer)
                ));
            }
        }
        InboundHandler::Dokodemo(ctx, settings) => {
            if let Err(e) = dokodemo::serve_tcp(stream, &settings, &ctx, peer).await {
                log::info(format!("dokodemo from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::VlessGrpc(h) | InboundHandler::TrojanGrpc(h) => {
            grpc::serve(stream, peer, h).await;
        }
        InboundHandler::VlessXhttp(h) => {
            serve_http(stream, peer, h).await;
        }
    }
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

#[derive(Debug)]
struct SniCheckingResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
    allowed_names: Vec<String>,
    reject_unknown_sni: bool,
}

impl rustls::server::ResolvesServerCert for SniCheckingResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if !self.reject_unknown_sni {
            return Some(self.certified_key.clone());
        }
        let sni = client_hello.server_name()?;
        let sni_lower = sni.to_ascii_lowercase();
        if self
            .allowed_names
            .iter()
            .any(|allowed| match_sni(allowed, &sni_lower))
        {
            Some(self.certified_key.clone())
        } else {
            None
        }
    }
}

fn tls_acceptor(
    settings: &TlsSettings,
    is_xhttp: bool,
    is_grpc: bool,
) -> Result<TlsAcceptor, String> {
    let certs = CertificateDer::pem_slice_iter(&settings.cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate: {e}"))?;
    if certs.is_empty() {
        return Err("certificate file has no certificates".into());
    }
    let key = PrivateKeyDer::from_pem_slice(&settings.key_pem)
        .map_err(|e| format!("invalid private key: {e}"))?;
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
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("invalid private key: {e}"))?;
    let cert_names = extract_cert_names(certs[0].as_ref());
    let mut allowed_names = settings.server_names.clone();
    allowed_names.extend(cert_names);

    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key));
    let resolver = Arc::new(SniCheckingResolver {
        certified_key,
        allowed_names,
        reject_unknown_sni: settings.reject_unknown_sni,
    });

    let versions: &[&'static rustls::SupportedProtocolVersion] =
        match (settings.min_version.as_deref(), settings.max_version.as_deref()) {
            (Some("1.3"), _) => &[&rustls::version::TLS13],
            (_, Some("1.2")) => &[&rustls::version::TLS12],
            _ => rustls::ALL_VERSIONS,
        };

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let alpn: Vec<Vec<u8>> = settings
        .alpn
        .iter()
        .filter(|p| *p != "h3")
        .map(|p| p.as_bytes().to_vec())
        .collect();
    config.alpn_protocols = if !alpn.is_empty() {
        alpn
    } else if is_grpc {
        vec![b"h2".to_vec()]
    } else if is_xhttp {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        Vec::new()
    };
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
}
