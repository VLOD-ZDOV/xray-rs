//! Shared transport dialer and connector for outbounds (VLESS, VMess, Trojan, Shadowsocks, HTTP).

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use xray_routing::{Target, TargetAddr};
use xray_transport::stream::{
    resolve_user_agent, Authority, GrpcConfig, GrpcTransport, HttpUpgradeConfig, TransportLayer,
    WebSocketConfig, XhttpConnectTarget,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, HappyEyeballsConfig, RealityClientConfig,
    ResolvedTcpConnector, TlsClientConfig, TransportDialer, TransportError, TransportStream,
};

use crate::vless::{resolve_all, Host, CONNECT_TIMEOUT};

pub struct TransportStreamWrapper<S>(pub S);

impl<S: AsyncRead + AsyncWrite + Send + Unpin> AsyncRead for TransportStreamWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> AsyncWrite for TransportStreamWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> TransportStream for TransportStreamWrapper<S> {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

pub struct ChainedTcpConnector {
    pub router: Arc<crate::routing::Router>,
    pub proxy_tag: String,
}

#[async_trait::async_trait]
impl ResolvedTcpConnector for ChainedTcpConnector {
    async fn connect_resolved(
        &self,
        original_target: &Target,
        _candidates: &[std::net::SocketAddr],
        _happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let decision = self.router.decision_for_tag(&self.proxy_tag);
        let host = match &original_target.addr {
            TargetAddr::Ip(ip) => Host::Ip(*ip),
            TargetAddr::Domain(d) => Host::Domain(d.clone()),
        };
        let stream = crate::outbound::connect(&self.router, &decision, &host, original_target.port)
            .await
            .map_err(TransportError::Tcp)?;
        Ok(Box::new(TransportStreamWrapper(stream)))
    }
}

pub struct SendThroughConnector {
    pub send_through: crate::routing::SendThrough,
}

#[async_trait::async_trait]
impl ResolvedTcpConnector for SendThroughConnector {
    async fn connect_resolved(
        &self,
        original_target: &Target,
        candidates: &[std::net::SocketAddr],
        _happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let Some(addr) = candidates.first().copied() else {
            return Err(TransportError::NoResolvedAddress(
                format!("{:?}", original_target.addr),
                original_target.port,
            ));
        };
        let bind_ip = self.send_through.resolve_ip().unwrap_or(if addr.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        });
        let socket = if bind_ip.is_ipv4() {
            tokio::net::TcpSocket::new_v4().map_err(TransportError::Tcp)?
        } else {
            tokio::net::TcpSocket::new_v6().map_err(TransportError::Tcp)?
        };
        socket
            .bind(std::net::SocketAddr::new(bind_ip, 0))
            .map_err(TransportError::Tcp)?;
        let stream = socket.connect(addr).await.map_err(TransportError::Tcp)?;
        stream.set_nodelay(true).map_err(TransportError::Tcp)?;
        Ok(Box::new(stream))
    }
}

pub struct ServerConnector {
    pub tag: String,
    pub protocol: String,
    pub server: (Host, u16),
    pub dialer: std::sync::RwLock<TransportDialer>,
    pub connector: ConnectorConfig,
    pub transport: TransportLayer,
    pub download: Option<Arc<crate::xhttp_outbound::XhttpDownloadTarget>>,
}

impl fmt::Debug for ServerConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnector")
            .field("tag", &self.tag)
            .field("protocol", &self.protocol)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl ServerConnector {
    pub fn parse(tag: &str, protocol: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} ({protocol}): {m}");
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let (address, port) = if let Some(vnext) = settings
            .get("vnext")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
        {
            let addr = vnext
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing vnext address"))?;
            let p = vnext
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| err("invalid vnext port"))?;
            (addr.to_owned(), p)
        } else if let Some(server) = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
        {
            let addr = server
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing servers address"))?;
            let p = server
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| err("invalid servers port"))?;
            (addr.to_owned(), p)
        } else if let Some(addr) = settings.get("address").and_then(Value::as_str) {
            let p = settings
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| err("invalid port"))?;
            (addr.to_owned(), p)
        } else {
            return Err(err("missing server address and port in settings"));
        };

        let host = match address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(address),
        };

        let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
        let network = stream
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let security = stream
            .get("security")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let connector = match security {
            "" | "none" => ConnectorConfig::Tcp,
            "tls" => parse_tls(stream.get("tlsSettings").unwrap_or(&Value::Null), &host)?,
            "reality" => {
                parse_reality(stream.get("realitySettings").unwrap_or(&Value::Null), &host)?
            }
            other => {
                return Err(err(&format!(
                    "unsupported streamSettings.security {other:?}"
                )))
            }
        };

        let host_fallback = match &connector {
            ConnectorConfig::Tls(tls) if !tls.server_name.is_empty() => tls.server_name.clone(),
            ConnectorConfig::Reality(reality) if !reality.server_name.is_empty() => {
                reality.server_name.clone()
            }
            _ => match &host {
                Host::Domain(domain) => domain.clone(),
                Host::Ip(ip) => ip.to_string(),
            },
        };

        let mut download = None;
        let transport = match network {
            "" | "tcp" | "raw" => TransportLayer::Raw,
            "ws" | "websocket" => {
                let ws = stream.get("wsSettings").unwrap_or(&Value::Null);
                let path = ws
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/")
                    .to_owned();
                let ws_host = ws
                    .get("headers")
                    .and_then(|h| h.get("Host").or_else(|| h.get("host")))
                    .and_then(Value::as_str)
                    .or_else(|| ws.get("host").and_then(Value::as_str))
                    .map(str::to_owned)
                    .unwrap_or_else(|| host_fallback.clone());
                let mut headers = Vec::new();
                if let Some(obj) = ws.get("headers").and_then(Value::as_object) {
                    for (k, v) in obj {
                        if let Some(v_str) = v.as_str() {
                            headers.push((k.clone(), v_str.to_owned()));
                        }
                    }
                }
                TransportLayer::WebSocket(WebSocketConfig {
                    path,
                    host: ws_host,
                    headers,
                    early_data_bytes: 0,
                    heartbeat_period_secs: 0,
                })
            }
            "httpupgrade" => {
                let hu = stream.get("httpupgradeSettings").unwrap_or(&Value::Null);
                let path = hu
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/")
                    .to_owned();
                let hu_host = hu
                    .get("host")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        hu.get("headers")
                            .and_then(|h| h.get("Host").or_else(|| h.get("host")))
                            .and_then(Value::as_str)
                    })
                    .map(str::to_owned)
                    .unwrap_or_else(|| host_fallback.clone());
                let mut headers = Vec::new();
                if let Some(obj) = hu.get("headers").and_then(Value::as_object) {
                    for (k, v) in obj {
                        if let Some(v_str) = v.as_str() {
                            headers.push((k.clone(), v_str.to_owned()));
                        }
                    }
                }
                TransportLayer::HttpUpgrade(HttpUpgradeConfig {
                    path,
                    host: hu_host,
                    headers,
                })
            }
            "grpc" | "gun" => {
                let grpc = stream.get("grpcSettings").unwrap_or(&Value::Null);
                let service_name = grpc
                    .get("serviceName")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let multi_mode = grpc
                    .get("multiMode")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let authority_str = grpc
                    .get("authority")
                    .and_then(Value::as_str)
                    .filter(|a| !a.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| host_fallback.clone());
                let authority = authority_str
                    .parse::<Authority>()
                    .map_err(|e| err(&format!("invalid grpc authority {authority_str:?}: {e}")))?;
                let user_agent = resolve_user_agent(grpc.get("user_agent").and_then(Value::as_str))
                    .map_err(|e| err(&format!("invalid grpc user_agent: {e}")))?;
                let idle_timeout_secs = grpc
                    .get("idle_timeout")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                let health_check_timeout_secs = grpc
                    .get("health_check_timeout")
                    .and_then(Value::as_u64)
                    .unwrap_or(20) as u32;
                let permit_without_stream = grpc
                    .get("permit_without_stream")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let initial_windows_size = grpc
                    .get("initial_windows_size")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
                    service_name,
                    multi_mode,
                    authority,
                    user_agent,
                    idle_timeout_secs,
                    health_check_timeout_secs,
                    permit_without_stream,
                    initial_windows_size,
                }))
            }
            "xhttp" | "splithttp" => {
                let (tl, dl) = crate::xhttp_outbound::transport(stream, &host_fallback)
                    .map_err(|e| err(&e))?;
                download = dl;
                tl
            }
            other => {
                return Err(err(&format!(
                    "unsupported streamSettings.network {other:?}"
                )))
            }
        };

        let send_through = crate::routing::parse_send_through(outbound.get("sendThrough"))?;
        let _dialer_proxy = crate::routing::parse_dialer_proxy(outbound, tag)?;

        let mut dialer =
            TransportDialer::system().map_err(|e| err(&format!("dialer error: {e}")))?;
        if let Some(ref st) = send_through {
            dialer = dialer.with_resolved_tcp_connector(Arc::new(SendThroughConnector {
                send_through: st.clone(),
            }));
        }

        if let Some(tcp_fragment) = crate::finalmask::parse_finalmask_tcp_fragment(stream)? {
            dialer = dialer.with_tcp_fragment(tcp_fragment);
        }

        Ok(Self {
            tag: tag.to_owned(),
            protocol: protocol.to_owned(),
            server: (host, port),
            dialer: std::sync::RwLock::new(dialer),
            connector,
            transport,
            download,
        })
    }

    pub fn set_chained_connector(&self, connector: Arc<dyn ResolvedTcpConnector>) {
        let dialer = self
            .dialer
            .read()
            .unwrap()
            .clone()
            .with_resolved_tcp_connector(connector);
        *self.dialer.write().unwrap() = dialer;
    }

    pub async fn connect(&self) -> io::Result<BoxedTransportStream> {
        let candidates = resolve_all(&self.server.0, self.server.1).await?;
        if candidates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to resolve server address {:?}", self.server.0),
            ));
        }

        let target = Target::new(
            match &self.server.0 {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            self.server.1,
            xray_routing::Network::Tcp,
        );

        let dialer = self.dialer.read().unwrap().clone();
        timeout(CONNECT_TIMEOUT, async {
            if let (Some(down), TransportLayer::Xhttp(up)) = (&self.download, &self.transport) {
                let down_candidates = resolve_all(&down.server.0, down.server.1).await?;
                if down_candidates.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "failed to resolve download server address {:?}",
                            down.server.0
                        ),
                    ));
                }
                let down_target = Target::new(
                    match &down.server.0 {
                        Host::Ip(ip) => TargetAddr::Ip(*ip),
                        Host::Domain(d) => TargetAddr::Domain(d.clone()),
                    },
                    down.server.1,
                    xray_routing::Network::Tcp,
                );
                up.open_split_stream(
                    &dialer,
                    XhttpConnectTarget {
                        connector: &self.connector,
                        target: &target,
                        candidates: &candidates,
                        happy_eyeballs: None,
                    },
                    &down.transport,
                    XhttpConnectTarget {
                        connector: &down.connector,
                        target: &down_target,
                        candidates: &down_candidates,
                        happy_eyeballs: None,
                    },
                )
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))
            } else {
                dialer
                    .connect_stream(&self.connector, &self.transport, &target, &candidates, None)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "connect to {} outbound {:?} timed out",
                    self.protocol, self.tag
                ),
            )
        })?
    }
}

pub struct PrefixedStream<S> {
    prefix: io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix: io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if (this.prefix.position() as usize) < this.prefix.get_ref().len() {
            let available = &this.prefix.get_ref()[this.prefix.position() as usize..];
            let to_read = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_read]);
            this.prefix
                .set_position(this.prefix.position() + to_read as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) fn parse_tls(tls: &Value, host: &Host) -> Result<ConnectorConfig, String> {
    let server_name = tls
        .get("serverName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| match host {
            Host::Domain(d) => d.clone(),
            Host::Ip(ip) => ip.to_string(),
        });
    let mut pinned_peer_cert_sha256 = Vec::new();
    if let Some(pins) = tls.get("pinnedPeerCertSha256").and_then(Value::as_array) {
        for pin in pins.iter().filter_map(Value::as_str) {
            if let Ok(bytes) = decode_hex(pin) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    pinned_peer_cert_sha256.push(arr);
                }
            }
        }
    }
    if let Some(certs) = tls.get("certificates").and_then(Value::as_array) {
        for cert in certs {
            let usage = cert.get("usage").and_then(Value::as_str).unwrap_or("");
            if usage == "verify" || usage.is_empty() {
                if let Some(file) = cert.get("certificateFile").and_then(Value::as_str) {
                    if let Ok(content) = std::fs::read(file) {
                        for der in CertificateDer::pem_slice_iter(&content).flatten() {
                            use sha2::Digest;
                            let hash: [u8; 32] = sha2::Sha256::digest(&der).into();
                            pinned_peer_cert_sha256.push(hash);
                        }
                    }
                } else if let Some(cert_lines) = cert.get("certificate").and_then(Value::as_array) {
                    let pem = cert_lines
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n");
                    for der in CertificateDer::pem_slice_iter(pem.as_bytes()).flatten() {
                        use sha2::Digest;
                        let hash: [u8; 32] = sha2::Sha256::digest(&der).into();
                        pinned_peer_cert_sha256.push(hash);
                    }
                }
            }
        }
    }

    let allow_insecure = tls
        .get("allowInsecure")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && pinned_peer_cert_sha256.is_empty();

    let fingerprint = tls
        .get("fingerprint")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let alpn = tls
        .get("alpn")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    Ok(ConnectorConfig::Tls(TlsClientConfig {
        server_name,
        allow_insecure,
        pinned_peer_cert_sha256,
        verify_peer_cert_by_name: Vec::new(),
        alpn,
        fingerprint,
    }))
}

pub(crate) fn parse_reality(reality: &Value, host: &Host) -> Result<ConnectorConfig, String> {
    let server_name = reality
        .get("serverName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| match host {
            Host::Domain(d) => d.clone(),
            Host::Ip(ip) => ip.to_string(),
        });
    let fingerprint = reality
        .get("fingerprint")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("chrome")
        .to_owned();
    let public_key_str = reality
        .get("password")
        .filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        .or_else(|| reality.get("publicKey"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing reality publicKey".to_string())?;
    let public_key = decode_base64_32(public_key_str)?;
    let short_id_str = reality
        .get("shortId")
        .and_then(Value::as_str)
        .or_else(|| {
            reality
                .get("shortIds")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(Value::as_str)
        })
        .unwrap_or_default();
    let short_id = decode_hex(short_id_str)?;
    let spider_x = reality
        .get("spiderX")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    Ok(ConnectorConfig::Reality(RealityClientConfig {
        server_name,
        fingerprint,
        public_key,
        short_id,
        spider_x,
        mldsa65_verify: None,
    }))
}

fn decode_base64_32(s: &str) -> Result<[u8; 32], String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .map_err(|e| format!("invalid base64: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "publicKey must be 32 bytes".to_string())
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex string length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex character: {e}"))
        })
        .collect()
}
