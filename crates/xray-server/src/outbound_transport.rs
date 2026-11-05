//! Shared transport dialer and connector for outbounds (VLESS, VMess, Trojan, Shadowsocks, HTTP).

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use xray_routing::{Target, TargetAddr};
use xray_transport::stream::{
    resolve_user_agent, Authority, GrpcConfig, GrpcTransport, HttpUpgradeConfig, TransportLayer,
    WebSocketConfig,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, TlsClientConfig, TransportDialer,
};

use crate::vless::{resolve_all, Host, CONNECT_TIMEOUT};

pub struct ServerConnector {
    pub tag: String,
    pub protocol: String,
    pub server: (Host, u16),
    pub dialer: TransportDialer,
    pub connector: ConnectorConfig,
    pub transport: TransportLayer,
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
            other => {
                return Err(err(&format!(
                    "unsupported streamSettings.network {other:?}"
                )))
            }
        };

        let dialer = TransportDialer::system().map_err(|e| err(&format!("dialer error: {e}")))?;

        Ok(Self {
            tag: tag.to_owned(),
            protocol: protocol.to_owned(),
            server: (host, port),
            dialer,
            connector,
            transport,
        })
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

        timeout(
            CONNECT_TIMEOUT,
            self.dialer.connect_stream(
                &self.connector,
                &self.transport,
                &target,
                &candidates,
                None,
            ),
        )
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
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "connect to {} outbound {:?} failed: {e}",
                    self.protocol, self.tag
                ),
            )
        })
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

fn parse_tls(tls: &Value, host: &Host) -> Result<ConnectorConfig, String> {
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

fn parse_reality(reality: &Value, host: &Host) -> Result<ConnectorConfig, String> {
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
        .get("publicKey")
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
