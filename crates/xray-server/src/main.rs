#![forbid(unsafe_code)]

mod api;
mod config;
mod inbound_proxy;
mod log;
mod mux;
mod outbound;
mod padding;
mod routing;
mod socks;
mod stats;
mod trojan;
mod vless;
mod wg;
mod ws;
mod xhttp;

use std::collections::HashMap;
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
use tokio::net::TcpListener;
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
                    "Xray {COMPAT_VERSION} (xray-server {}, VLESS/XHTTP only)",
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
    // Build TLS up front so `-test` rejects bad certificates like Xray does.
    let tls: Result<Vec<_>, String> = config
        .inbounds
        .iter()
        .map(|i| {
            let is_xhttp = matches!(i.transport, InboundTransport::Xhttp(_));
            i.tls.as_ref().map(|s| tls_acceptor(s, is_xhttp)).transpose()
        })
        .collect();
    let tls = match tls {
        Ok(tls) => tls,
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
    match runtime.block_on(run(config, tls)) {
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
    TrojanTcp(Arc<vless::Context>),
    TrojanWs(Arc<vless::Context>, ws::WsSettings),
    Socks(Arc<vless::Context>, xray_proxy::inbound::SocksInboundAuth, bool),
    Http(Arc<vless::Context>, xray_proxy::inbound::SocksInboundAuth),
    VlessXhttp(Arc<xhttp::Handler>),
}

async fn run(config: Config, tls: Vec<Option<TlsAcceptor>>) -> Result<(), String> {
    log::info(format!("xray-server {} started", env!("CARGO_PKG_VERSION")));
    stats::init(config.stats);
    let router = Arc::new(config.router);
    let mut inbounds = HashMap::new();
    for (inbound, acceptor) in config.inbounds.into_iter().zip(tls) {
        let listener = bind(&inbound).await?;
        log::info(format!(
            "listening {} on {}",
            inbound.tag,
            listener.local_addr().map_err(|e| e.to_string())?
        ));
        let ctx = Arc::new(vless::Context {
            tag: inbound.tag.clone(),
            port: inbound.port,
            users: RwLock::new(inbound.users),
            router: router.clone(),
        });
        inbounds.insert(inbound.tag.clone(), ctx.clone());
        let handler = match (inbound.protocol, inbound.transport) {
            (InboundProtocol::Vless, InboundTransport::Tcp) => InboundHandler::VlessTcp(ctx),
            (InboundProtocol::Vless, InboundTransport::Websocket(settings)) => {
                InboundHandler::VlessWs(ctx, settings)
            }
            (InboundProtocol::Trojan, InboundTransport::Tcp) => InboundHandler::TrojanTcp(ctx),
            (InboundProtocol::Trojan, InboundTransport::Websocket(settings)) => {
                InboundHandler::TrojanWs(ctx, settings)
            }
            (InboundProtocol::Socks, InboundTransport::Tcp) => {
                InboundHandler::Socks(ctx, inbound.socks_auth, inbound.udp)
            }
            (InboundProtocol::Http, InboundTransport::Tcp) => {
                InboundHandler::Http(ctx, inbound.socks_auth)
            }
            (InboundProtocol::Vless, InboundTransport::Xhttp(settings)) => {
                InboundHandler::VlessXhttp(xhttp::Handler::new(*settings, ctx))
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
        };
        tokio::spawn(accept_loop(listener, acceptor, handler));
    }
    if let Some(addr) = config.api {
        api::serve(addr, inbounds).await?;
    }
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
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

fn bracket(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    handler: InboundHandler,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                log::warn(format!("accept failed: {e}"));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let (tls, handler) = (tls.clone(), handler.clone());
        tokio::spawn(async move {
            match tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(stream) => dispatch(stream, peer, handler).await,
                    Err(e) => log::debug(format!(
                        "tls handshake from {} failed: {e}",
                        log::mask(peer)
                    )),
                },
                None => dispatch(stream, peer, handler).await,
            }
        });
    }
}

async fn dispatch<I>(stream: I, peer: SocketAddr, handler: InboundHandler)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match handler {
        InboundHandler::VlessTcp(ctx) => {
            let (r, w) = tokio::io::split(stream);
            if let Err(e) = vless::serve(r, w, &ctx, peer).await {
                log::info(format!("vless from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::VlessWs(ctx, ws_settings) => {
            match ws::accept(stream, &ws_settings).await {
                Ok(ws_stream) => {
                    let (uplink, downlink) = tokio::io::split(ws_stream);
                    if let Err(e) = vless::serve(uplink, downlink, &ctx, peer).await {
                        log::info(format!("vless-ws from {} rejected: {e}", log::mask(peer)));
                    }
                }
                Err(e) => {
                    log::info(format!("ws handshake from {} failed: {e}", log::mask(peer)));
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
        InboundHandler::Socks(ctx, auth, udp) => {
            if let Err(e) = inbound_proxy::serve_socks(stream, &auth, udp, &ctx, peer).await {
                log::info(format!("socks from {} rejected: {e}", log::mask(peer)));
            }
        }
        InboundHandler::Http(ctx, auth) => {
            if let Err(e) = inbound_proxy::serve_http(stream, &auth, &ctx, peer).await {
                log::info(format!("http from {} rejected: {e}", log::mask(peer)));
            }
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

fn tls_acceptor(settings: &TlsSettings, is_xhttp: bool) -> Result<TlsAcceptor, String> {
    let certs = CertificateDer::pem_slice_iter(&settings.cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate: {e}"))?;
    if certs.is_empty() {
        return Err("certificate file has no certificates".into());
    }
    let key = PrivateKeyDer::from_pem_slice(&settings.key_pem)
        .map_err(|e| format!("invalid private key: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid certificate/key pair: {e}"))?;
    let alpn: Vec<Vec<u8>> = settings
        .alpn
        .iter()
        .filter(|p| *p != "h3")
        .map(|p| p.as_bytes().to_vec())
        .collect();
    config.alpn_protocols = if !alpn.is_empty() {
        alpn
    } else if is_xhttp {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        Vec::new()
    };
    Ok(TlsAcceptor::from(Arc::new(config)))
}
