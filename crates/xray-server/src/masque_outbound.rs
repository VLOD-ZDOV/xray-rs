//! MASQUE client outbound (proxy/masque and transport/masque).
//! Implements RFC 9484 (CONNECT-IP) over HTTP/2 and HTTP/3 with userspace smoltcp stack.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use xray_transport::{ConnectorConfig, TlsClientConfig, TlsConnector};
use xray_wireguard::{Client, Ip, Packet, TcpStream, UdpSession};

use crate::log;
use crate::masque_capsule::{
    decode_address_assign_value, decode_datagram_value, encode_datagram_capsule, first_assigned_ip,
    read_capsule, CAPSULE_ADDRESS_ASSIGN, CAPSULE_DATAGRAM,
};
use crate::masque_inbound::H2StreamReader;
use crate::vless::{resolve_all, Host};

const ESTABLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug)]
pub struct MasqueOutbound {
    pub tag: String,
    pub address: String,
    pub port: u16,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub tls_config: TlsClientConfig,
    pub alpn: Vec<String>,
    client: Mutex<Option<Client>>,
}

impl MasqueOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| m.to_string();
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let address = settings
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| err("MASQUE: \"address\" is not set"))?
            .to_owned();
        if address.is_empty() {
            return Err(err("MASQUE: \"address\" is not set"));
        }

        let port = match settings.get("port").and_then(Value::as_u64) {
            Some(p) if p > 0 && p <= u64::from(u16::MAX) => p as u16,
            Some(p) if p > u64::from(u16::MAX) => {
                return Err(format!("MASQUE: invalid \"port\" {p}"))
            }
            _ => return Err(err("MASQUE: \"port\" is not set")),
        };

        if let Some(dns) = settings.get("remoteDNS").and_then(Value::as_array) {
            for d in dns {
                if let Some(s) = d.as_str() {
                    if s.parse::<IpAddr>().is_err() {
                        return Err(format!("MASQUE: invalid \"remoteDNS\" {s}"));
                    }
                }
            }
        }

        let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
        let network = stream.get("network").and_then(Value::as_str).unwrap_or("");
        if network != "masque" {
            return Err("the masque transport can only be used by the masque outbound".into());
        }
        let security = stream.get("security").and_then(Value::as_str).unwrap_or("");
        if security != "tls" {
            return Err("MASQUE requires \"security\": \"tls\"".into());
        }

        let tls_val = stream.get("tlsSettings").unwrap_or(&Value::Null);
        let host = match address.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(address.clone()),
        };
        let tls_config = match crate::outbound_transport::parse_tls(tls_val, &host)? {
            ConnectorConfig::Tls(cfg) => cfg,
            _ => return Err("MASQUE requires TLS".to_string()),
        };
        let alpn = tls_config.alpn.clone();

        let masque_settings = stream.get("masqueSettings").unwrap_or(&Value::Null);
        if masque_settings.get("warp").is_some_and(|w| !w.is_null()) {
            return Err(err("MASQUE: \"warp\" in masqueSettings is not supported"));
        }
        if masque_settings.get("xmux").is_some_and(|w| !w.is_null()) {
            log::warn("MASQUE: masqueSettings \"xmux\" is not supported and is ignored");
        }
        let path = crate::masque_capsule::normalize_path(
            masque_settings
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )?;
        let host_override = masque_settings
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if !host_override.is_empty()
            && http::uri::Authority::try_from(host_override.as_str()).is_err()
        {
            return Err(format!("invalid \"host\": {host_override}"));
        }

        let user = masque_settings
            .get("user")
            .and_then(Value::as_str)
            .unwrap_or("");
        let pass = masque_settings
            .get("pass")
            .and_then(Value::as_str)
            .unwrap_or("");
        let has_creds = !user.is_empty() || !pass.is_empty();
        let mut headers = HashMap::new();
        if let Some(hdr_obj) = masque_settings.get("headers").and_then(Value::as_object) {
            for (k, v) in hdr_obj {
                if let Some(s) = v.as_str() {
                    match k.to_ascii_lowercase().as_str() {
                        "host" | "capsule-protocol" => {
                            return Err(format!("\"headers\" can't contain \"{k}\""));
                        }
                        "authorization" if has_creds => {
                            return Err(format!(
                                "\"headers\" can't contain \"{k}\" when \"user\" or \"pass\" is set"
                            ));
                        }
                        _ => {}
                    }
                    headers.insert(k.clone(), s.to_owned());
                }
            }
        }
        if has_creds {
            if user.contains(':') {
                return Err(format!("invalid \"user\": {user}"));
            }
            use base64::Engine;
            let cred = format!("{user}:{pass}");
            let b64 = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
            headers.insert("Authorization".to_string(), format!("Basic {b64}"));
        }

        Ok(Self {
            tag: tag.to_owned(),
            address,
            port,
            path,
            host: host_override,
            headers,
            tls_config,
            alpn,
            client: Mutex::new(None),
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<TcpStream> {
        let client = self.get_client().await?;
        let addrs = resolve_all(host, port).await?;
        let target = addrs
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "could not resolve host"))?;
        client.connect(target).await.map_err(crate::wg::to_io)
    }

    pub async fn open_udp(&self, target: SocketAddr) -> io::Result<UdpSession> {
        let client = self.get_client().await?;
        client.open_udp(target).await.map_err(crate::wg::to_io)
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        let addrs = resolve_all(host, port).await?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "could not resolve host"))
    }

    pub async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<()> {
        let session = self.open_udp(target).await?;
        session.send(bytes).await.map_err(crate::wg::to_io)
    }

    /// Xray's `authority()`: the host override, else the server name with
    /// IPv6 literals bracketed and the port left out for 443.
    fn authority(&self) -> String {
        if !self.host.is_empty() {
            return self.host.clone();
        }
        let name = self.tls_config.server_name.trim_matches(['[', ']']);
        let v6 = name.parse::<std::net::Ipv6Addr>().is_ok();
        match (self.port, v6) {
            (443, false) => name.to_owned(),
            (443, true) => format!("[{name}]"),
            (port, false) => format!("{name}:{port}"),
            (port, true) => format!("[{name}]:{port}"),
        }
    }

    async fn get_client(&self) -> io::Result<Client> {
        let mut guard = self.client.lock().await;
        if let Some(ref c) = *guard {
            if c.is_live() {
                return Ok(c.clone());
            }
        }

        let use_h2 =
            self.alpn.contains(&"h2".to_string()) && !self.alpn.contains(&"h3".to_string());
        let start = async {
            if use_h2 {
                self.start_h2_client().await
            } else {
                self.start_h3_client().await
            }
        };
        let client = tokio::time::timeout(ESTABLISH_TIMEOUT, start)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "MASQUE connection timed out")
            })??;

        *guard = Some(client.clone());
        Ok(client)
    }

    async fn start_h2_client(&self) -> io::Result<Client> {
        let host = match self.address.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(self.address.clone()),
        };
        let addrs = resolve_all(&host, self.port).await?;
        let target_addr = addrs.into_iter().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "could not resolve server address")
        })?;

        let tcp = tokio::net::TcpStream::connect(target_addr).await?;
        let connector = TlsConnector::system().map_err(io::Error::other)?;
        let mut tls_config = self.tls_config.clone();
        tls_config.alpn = vec!["h2".to_string()];
        let rustls_cfg = connector
            .client_config_for(&tls_config)
            .map_err(io::Error::other)?;

        let server_name = self.tls_config.server_name.clone();
        let pki_server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid server name: {e}"),
                )
            })?;

        let tls_stream = tokio_rustls::TlsConnector::from(rustls_cfg)
            .connect(pki_server_name, tcp)
            .await?;

        let (mut h2_client, h2_driver) = h2::client::Builder::new()
            .handshake(tls_stream)
            .await
            .map_err(io::Error::other)?;

        tokio::spawn(async move {
            let _ = h2_driver.await;
        });

        let mut req_builder = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{}{}", self.authority(), self.path))
            .header("Capsule-Protocol", "?1")
            .header("User-Agent", "Go-http-client/2.0")
            .extension(h2::ext::Protocol::from("connect-ip"));

        for (k, v) in &self.headers {
            req_builder = req_builder.header(k, v);
        }

        let req = req_builder.body(()).map_err(io::Error::other)?;
        let (response_fut, mut send_stream) = h2_client
            .send_request(req, false)
            .map_err(io::Error::other)?;
        let response = response_fut.await.map_err(io::Error::other)?;

        if response.status() != StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("MASQUE server returned status {}", response.status()),
            ));
        }

        let recv_stream = response.into_body();
        let mut reader = H2StreamReader::new(recv_stream);

        // Read initial ADDRESS_ASSIGN capsule
        let first_cap = read_capsule(&mut reader).await?;
        if first_cap.capsule_type != CAPSULE_ADDRESS_ASSIGN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected ADDRESS_ASSIGN capsule, got {}",
                    first_cap.capsule_type
                ),
            ));
        }
        let assignments = decode_address_assign_value(&first_cap.value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let assigned_ip = first_assigned_ip(&assignments).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no address assigned by server")
        })?;

        let (to_tunnel_tx, mut to_tunnel_rx) = mpsc::channel::<Packet<Ip>>(128);
        let (from_tunnel_tx, from_tunnel_rx) = mpsc::channel::<Packet<Ip>>(128);

        let client = Client::start_raw(vec![assigned_ip], 1420, to_tunnel_tx, from_tunnel_rx)
            .await
            .map_err(|e| io::Error::other(format!("failed to start userspace stack: {e:?}")))?;

        let reader_f_tx = from_tunnel_tx;
        tokio::spawn(async move {
            while let Ok(cap) = read_capsule(&mut reader).await {
                if cap.capsule_type == CAPSULE_DATAGRAM {
                    if let Some(pkt_data) = decode_datagram_value(&cap.value) {
                        if let Ok(pkt) = Packet::from_bytes(BytesMut::from(pkt_data)).try_into_ip()
                        {
                            if reader_f_tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(packet) = to_tunnel_rx.recv().await {
                let cap = encode_datagram_capsule(packet.into_bytes().as_ref());
                let data = Bytes::from(cap);
                send_stream.reserve_capacity(data.len());
                while send_stream.capacity() < data.len() {
                    if poll_fn(|cx| send_stream.poll_capacity(cx)).await.is_none() {
                        return;
                    }
                }
                if send_stream.send_data(data, false).is_err() {
                    break;
                }
            }
        });

        log::info(format!(
            "MASQUE outbound {} connected over h2, assigned IP {}",
            self.tag, assigned_ip
        ));
        Ok(client)
    }

    async fn start_h3_client(&self) -> io::Result<Client> {
        let host = match self.address.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(self.address.clone()),
        };
        let addrs = resolve_all(&host, self.port).await?;
        let target_addr = addrs.into_iter().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "could not resolve server address")
        })?;

        let connector = TlsConnector::system().map_err(io::Error::other)?;
        let rustls_cfg = connector
            .quic_client_config_for(&self.tls_config, b"h3")
            .map_err(io::Error::other)?;
        let quic_client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| io::Error::other(format!("quic client tls: {e}")))?;

        let server_name = self.tls_config.server_name.clone();

        let mut transport_cfg = quinn::TransportConfig::default();
        transport_cfg.datagram_receive_buffer_size(Some(1024 * 1024));
        transport_cfg.datagram_send_buffer_size(1024 * 1024);

        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
        client_cfg.transport_config(Arc::new(transport_cfg));

        let bind_addr: SocketAddr = if target_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_cfg);

        let connection = endpoint
            .connect(target_addr, &server_name)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;

        let mut h3_builder = h3::client::builder();
        h3_builder.enable_extended_connect(true);
        h3_builder.enable_datagram(true);

        let (mut driver, mut send_request) = h3_builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(io::Error::other)?;

        tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut req_builder = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{}{}", self.authority(), self.path))
            .header("Capsule-Protocol", "?1")
            .header("User-Agent", "Go-http-client/2.0")
            .extension(h2::ext::Protocol::from("connect-ip"));

        for (k, v) in &self.headers {
            req_builder = req_builder.header(k, v);
        }

        let req = req_builder.body(()).map_err(io::Error::other)?;
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(io::Error::other)?;
        let response = stream.recv_response().await.map_err(io::Error::other)?;

        if response.status() != StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("MASQUE server returned status {}", response.status()),
            ));
        }

        let stream_id = stream.id();
        let quarter_stream_id = stream_id.into_inner() / 4;

        // Read until the first capsule is complete
        let mut initial_data = BytesMut::new();
        loop {
            if let Some((_, o1)) = crate::masque_capsule::decode_varint(&initial_data) {
                if let Some((len, o2)) = crate::masque_capsule::decode_varint(&initial_data[o1..]) {
                    if len > 65536 * 2 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "capsule exceeds maximum allowed length",
                        ));
                    }
                    if initial_data.len() as u64 >= (o1 + o2) as u64 + len {
                        break;
                    }
                }
            }
            match stream.recv_data().await.map_err(io::Error::other)? {
                Some(mut chunk) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    initial_data.extend_from_slice(&bytes);
                }
                None => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }

        let mut cursor = io::Cursor::new(initial_data);
        let first_cap = read_capsule(&mut cursor).await?;
        if first_cap.capsule_type != CAPSULE_ADDRESS_ASSIGN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected ADDRESS_ASSIGN capsule, got {}",
                    first_cap.capsule_type
                ),
            ));
        }
        let assignments = decode_address_assign_value(&first_cap.value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let assigned_ip = first_assigned_ip(&assignments).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no address assigned by server")
        })?;

        let (to_tunnel_tx, mut to_tunnel_rx) = mpsc::channel::<Packet<Ip>>(128);
        let (from_tunnel_tx, from_tunnel_rx) = mpsc::channel::<Packet<Ip>>(128);

        let client = Client::start_raw(vec![assigned_ip], 1420, to_tunnel_tx, from_tunnel_rx)
            .await
            .map_err(|e| io::Error::other(format!("failed to start userspace stack: {e:?}")))?;

        let dgram_conn_read = connection.clone();
        let reader_f_tx = from_tunnel_tx;

        tokio::spawn(async move {
            while let Ok(dgram) = dgram_conn_read.read_datagram().await {
                if let Some((qid, offset1)) = crate::masque_capsule::decode_varint(&dgram) {
                    if qid == quarter_stream_id {
                        let rest = &dgram[offset1..];
                        if let Some((cid, offset2)) = crate::masque_capsule::decode_varint(rest) {
                            if cid == 0 {
                                let pkt_data = &rest[offset2..];
                                if let Ok(pkt) =
                                    Packet::from_bytes(BytesMut::from(pkt_data)).try_into_ip()
                                {
                                    if reader_f_tx.send(pkt).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let dgram_conn_write = connection.clone();
        tokio::spawn(async move {
            let mut prefix = Vec::new();
            crate::masque_capsule::encode_varint(quarter_stream_id, &mut prefix);
            crate::masque_capsule::encode_varint(0, &mut prefix); // Context ID = 0

            while let Some(packet) = to_tunnel_rx.recv().await {
                let payload = packet.into_bytes();
                let mut dgram = Vec::with_capacity(prefix.len() + payload.len());
                dgram.extend_from_slice(&prefix);
                dgram.extend_from_slice(payload.as_ref());
                if dgram_conn_write.send_datagram(Bytes::from(dgram)).is_err() {
                    break;
                }
            }
        });

        log::info(format!(
            "MASQUE outbound {} connected over h3, assigned IP {}",
            self.tag, assigned_ip
        ));
        Ok(client)
    }
}
