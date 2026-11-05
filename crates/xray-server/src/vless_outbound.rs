//! VLESS outbound supporting TCP, UDP, and common transports (RAW, WebSocket, HTTPUpgrade, gRPC).

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use uuid::Uuid;
use xray_proxy::vless::{
    encode_request_header, encode_udp_packet, read_udp_packet, VlessCommand, VlessRequest,
    VlessResponseStream, VisionStream, VisionStreamIo, DEFAULT_VISION_SEED,
};
use xray_routing::{Target, TargetAddr};
use xray_transport::stream::{
    resolve_user_agent, Authority, GrpcConfig, GrpcTransport, HttpUpgradeConfig, TransportLayer,
    WebSocketConfig,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, TlsClientConfig, TransportDialer,
};

use crate::vless::{resolve, resolve_all, Host, CONNECT_TIMEOUT};

pub struct VisionTransportStream {
    inner: BoxedTransportStream,
}

impl VisionTransportStream {
    pub fn new(inner: BoxedTransportStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VisionTransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VisionTransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl VisionStreamIo for VisionTransportStream {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read_direct(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown_direct(cx)
    }
}

pub struct VlessOutbound {
    pub tag: String,
    pub server: (Host, u16),
    pub user_id: Uuid,
    pub flow: Option<String>,
    pub dialer: TransportDialer,
    pub connector: ConnectorConfig,
    pub transport: TransportLayer,
}

impl fmt::Debug for VlessOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VlessOutbound")
            .field("tag", &self.tag)
            .field("server", &self.server)
            .field("user_id", &"<redacted>")
            .field("flow", &self.flow)
            .field("connector", &self.connector)
            .field("transport", &self.transport)
            .finish()
    }
}

impl VlessOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (vless): {m}");
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let vnext = settings
            .get("vnext")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .unwrap_or(settings);
        let address = vnext
            .get("address")
            .or_else(|| settings.get("address"))
            .and_then(Value::as_str)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| err("missing server address"))?;
        let port = vnext
            .get("port")
            .or_else(|| settings.get("port"))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| err("invalid server port"))?;

        let host = match address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(address.to_owned()),
        };

        let user = vnext
            .get("users")
            .and_then(Value::as_array)
            .and_then(|u| u.first())
            .unwrap_or(vnext);
        let id_str = user
            .get("id")
            .or_else(|| settings.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| err("missing user id"))?;
        let user_id = Uuid::parse_str(id_str)
            .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id_str.as_bytes()));
        let flow = user
            .get("flow")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(str::to_owned);

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
            "reality" => parse_reality(
                stream.get("realitySettings").unwrap_or(&Value::Null),
                &host,
            )?,
            other => return Err(err(&format!("unsupported streamSettings.security {other:?}"))),
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
            other => return Err(err(&format!("unsupported streamSettings.network {other:?}"))),
        };

        let dialer = TransportDialer::system().map_err(|e| err(&format!("dialer error: {e}")))?;

        Ok(Self {
            tag: tag.to_owned(),
            server: (host, port),
            user_id,
            flow,
            dialer,
            connector,
            transport,
        })
    }

    async fn open_raw_stream(
        &self,
        host: &Host,
        port: u16,
        command: VlessCommand,
    ) -> io::Result<VlessResponseStream<VisionTransportStream>> {
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

        let carrier = timeout(
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
                format!("connect to vless outbound {:?} timed out", self.tag),
            )
        })?
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("connect to vless outbound {:?} failed: {e}", self.tag),
            )
        })?;

        let req_target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            match command {
                VlessCommand::Tcp => xray_routing::Network::Tcp,
                VlessCommand::Udp => xray_routing::Network::Udp,
                _ => xray_routing::Network::Tcp,
            },
        );

        let flow = if command == VlessCommand::Tcp {
            self.flow.clone()
        } else {
            None
        };

        let request = VlessRequest {
            user_id: self.user_id,
            command,
            target: req_target,
            flow,
        };

        let header = encode_request_header(&request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let mut carrier = carrier;
        carrier.write_all(&header).await?;
        carrier.flush().await?;

        Ok(VlessResponseStream::new(VisionTransportStream::new(carrier)))
    }

    pub async fn connect(
        &self,
        host: &Host,
        port: u16,
    ) -> io::Result<Box<dyn crate::outbound::Stream>> {
        let response_stream = self.open_raw_stream(host, port, VlessCommand::Tcp).await?;
        let is_vision = matches!(
            self.flow.as_deref(),
            Some("xtls-rprx-vision" | "xtls-rprx-vision-udp443")
        );
        if is_vision {
            let vision_stream = VisionStream::new(
                response_stream,
                *self.user_id.as_bytes(),
                DEFAULT_VISION_SEED,
            );
            Ok(Box::new(vision_stream))
        } else {
            Ok(Box::new(response_stream))
        }
    }

    pub async fn open_udp(&self, host: &Host, port: u16) -> io::Result<VlessUdpLink> {
        let stream = self.open_raw_stream(host, port, VlessCommand::Udp).await?;
        Ok(VlessUdpLink::new(stream))
    }

    pub fn open_cone_udp(self: &Arc<Self>) -> VlessConeUdp {
        VlessConeUdp::new(Arc::clone(self))
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        resolve(host, port).await
    }
}

pub struct VlessUdpLink {
    writer: Mutex<tokio::io::WriteHalf<VlessResponseStream<VisionTransportStream>>>,
    reader: Mutex<tokio::io::ReadHalf<VlessResponseStream<VisionTransportStream>>>,
}

impl VlessUdpLink {
    pub fn new(stream: VlessResponseStream<VisionTransportStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let packet = encode_udp_packet(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut writer = self.writer.lock().await;
        writer.write_all(&packet).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = self.reader.lock().await;
        match read_udp_packet(&mut *reader).await {
            Ok(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            Err(e) => Err(e),
        }
    }
}

type VlessFlow = (Arc<VlessUdpLink>, JoinHandle<()>);

pub struct VlessConeUdp {
    vless: Arc<VlessOutbound>,
    sessions: Mutex<HashMap<SocketAddr, VlessFlow>>,
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
}

impl VlessConeUdp {
    pub fn new(vless: Arc<VlessOutbound>) -> Self {
        let (tx, rx) = mpsc::channel(256);
        Self {
            vless,
            sessions: Mutex::new(HashMap::new()),
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        self.vless.udp_target(host, port).await
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        let mut sessions = self.sessions.lock().await;
        if sessions.get(&addr).is_none_or(|(_, task)| task.is_finished()) {
            let link = Arc::new(self.vless.open_udp(&Host::Ip(addr.ip()), addr.port()).await?);
            let (reader, tx) = (link.clone(), self.tx.clone());
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok(n) = reader.recv(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let packet = Bytes::copy_from_slice(&buf[..n]);
                    if tx.send((addr, packet)).await.is_err() {
                        break;
                    }
                }
            });
            if let Some((_, old)) = sessions.insert(addr, (link, task)) {
                old.abort();
            }
        }
        let link = sessions[&addr].0.clone();
        drop(sessions);
        link.send(data).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (from, packet) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);
        Ok((n, from))
    }

    pub fn abort_all(&mut self) {
        for (_, task) in self.sessions.get_mut().values() {
            task.abort();
        }
    }
}

impl Drop for VlessConeUdp {
    fn drop(&mut self) {
        self.abort_all();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn parses_vless_outbound_variants() {
        let nested = json!({
            "tag": "vless-tcp",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{
                        "id": "5055b881-2090-410e-b762-fe36e4f16b25",
                        "flow": "xtls-rprx-vision",
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "example.com",
                    "allowInsecure": true,
                    "fingerprint": "chrome",
                    "alpn": ["h2", "http/1.1"]
                }
            }
        });
        let out = VlessOutbound::parse("vless-tcp", &nested).unwrap();
        assert_eq!(out.tag, "vless-tcp");
        assert_eq!(out.server.1, 443);
        assert_eq!(out.flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(matches!(out.transport, TransportLayer::Raw));
        if let ConnectorConfig::Tls(tls) = &out.connector {
            assert_eq!(tls.server_name, "example.com");
            assert!(tls.allow_insecure);
            assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
            assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
        } else {
            panic!("expected tls connector");
        }

        let reality = json!({
            "settings": {
                "address": "1.2.3.4",
                "port": 8443,
                "id": "5055b881-2090-410e-b762-fe36e4f16b25"
            },
            "streamSettings": {
                "network": "ws",
                "security": "reality",
                "realitySettings": {
                    "serverName": "reality.example.com",
                    "publicKey": "dGVzdC1wdWJsaWMta2V5LTMyLWJ5dGVzLWxvbmctISE=",
                    "shortId": "0123456789abcdef",
                    "spiderX": "/api"
                },
                "wsSettings": {
                    "path": "/websocket",
                    "headers": {
                        "Host": "ws.example.com"
                    }
                }
            }
        });
        let out = VlessOutbound::parse("reality-ws", &reality).unwrap();
        assert!(matches!(out.transport, TransportLayer::WebSocket(_)));
        if let ConnectorConfig::Reality(r) = &out.connector {
            assert_eq!(r.server_name, "reality.example.com");
            assert_eq!(r.short_id, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
            assert_eq!(r.spider_x, "/api");
        } else {
            panic!("expected reality connector");
        }

        let grpc = json!({
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": 50051,
                    "users": [{"id": "5055b881-2090-410e-b762-fe36e4f16b25"}]
                }]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "GunService",
                    "multiMode": true,
                    "authority": "grpc.example.com"
                }
            }
        });
        let out = VlessOutbound::parse("grpc-out", &grpc).unwrap();
        assert!(matches!(out.transport, TransportLayer::Grpc(_)));
        assert!(matches!(out.connector, ConnectorConfig::Tcp));
    }

    #[tokio::test]
    async fn vless_tcp_outbound_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let user_id = Uuid::new_v4();
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 1 + 16 + 1];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0); // VLESS version 0
            assert_eq!(&head[1..17], user_id.as_bytes());
            assert_eq!(head[17], 0); // addons length 0
            let mut rest = [0u8; 1 + 2 + 1 + 4]; // cmd (1) + port (2) + addr_type (1) + ipv4 (4)
            socket.read_exact(&mut rest).await.unwrap();
            assert_eq!(rest[0], 1); // command TCP

            // Write VLESS response header: version 0, addons length 0
            socket.write_all(&[0, 0]).await.unwrap();

            // Echo payload
            let mut buf = [0u8; 128];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let config = json!({
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "id": user_id.to_string()
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        });

        let outbound = VlessOutbound::parse("vless-test", &config).unwrap();
        let mut stream = outbound
            .connect(&Host::Ip("1.2.3.4".parse().unwrap()), 80)
            .await
            .unwrap();

        stream.write_all(b"hello vless tcp").await.unwrap();
        let mut resp = [0u8; 15];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello vless tcp");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn vless_udp_outbound_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let user_id = Uuid::new_v4();
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 1 + 16 + 1];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0);
            assert_eq!(&head[1..17], user_id.as_bytes());
            assert_eq!(head[17], 0);
            let mut rest = [0u8; 1 + 2 + 1 + 4];
            socket.read_exact(&mut rest).await.unwrap();
            assert_eq!(rest[0], 2); // command UDP

            // VLESS response header: version 0, addons length 0
            socket.write_all(&[0, 0]).await.unwrap();

            // Read UDP packet: length-prefixed
            let len = socket.read_u16().await.unwrap();
            let mut payload = vec![0u8; len as usize];
            socket.read_exact(&mut payload).await.unwrap();

            // Echo packet back with length prefix
            socket.write_all(&(len.to_be_bytes())).await.unwrap();
            socket.write_all(&payload).await.unwrap();
        });

        let config = json!({
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "id": user_id.to_string()
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        });

        let outbound = VlessOutbound::parse("vless-udp-test", &config).unwrap();
        let link = outbound
            .open_udp(&Host::Ip("8.8.8.8".parse().unwrap()), 53)
            .await
            .unwrap();

        link.send(b"dns-query-packet").await.unwrap();
        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"dns-query-packet");

        server_task.await.unwrap();
    }
}
