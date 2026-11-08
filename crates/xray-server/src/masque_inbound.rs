//! MASQUE server inbound (proxy/masque and transport/masque).
//! Implements RFC 9484 (CONNECT-IP) over HTTP/2 and HTTP/3 with userspace smoltcp stack.

use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::{Method, Response, StatusCode};
use serde_json::Value;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{broadcast, mpsc, Mutex};
use xray_config::Network;
use xray_wireguard::{IncomingTcpStream, IncomingUdpSession, Ip, Packet, Server};

use crate::config::Inbound;
use crate::log;
use crate::masque_capsule::{
    decode_datagram_value, encode_address_assign_capsule, encode_datagram_capsule,
    encode_route_advertisement_capsule, read_capsule, CAPSULE_ADDRESS_REQUEST, CAPSULE_DATAGRAM,
};
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query, Router};
use crate::stats;
use crate::vless::{copy, relay, Activity, Host};

#[derive(Clone, Debug)]
pub struct MasqueUser {
    pub email: String,
    pub pass: String,
    pub level: u32,
}

#[derive(Clone, Debug)]
pub struct MasqueServerConfig {
    pub users: Vec<MasqueUser>,
    pub address: Vec<String>,
    pub prefixes: Vec<(IpAddr, u8)>,
    pub mtu: u16,
    pub path: String,
}

pub fn parse(tag: &str, item: &Value) -> Result<MasqueServerConfig, String> {
    let err = |m: &str| m.to_string();
    let settings = item.get("settings").unwrap_or(&Value::Null);

    let users_val = settings
        .get("users")
        .or_else(|| settings.get("clients"))
        .and_then(Value::as_array);

    let mut users = Vec::new();
    let mut emails = HashMap::new();

    if let Some(user_list) = users_val {
        for u in user_list {
            let email = u.get("email").and_then(Value::as_str).unwrap_or("");
            if email.is_empty() {
                return Err(err("MASQUE: \"email\" is empty"));
            }
            if email.contains(':') {
                return Err(format!("MASQUE: invalid \"email\" {email}"));
            }
            let pass = u.get("pass").and_then(Value::as_str).unwrap_or("");
            if pass.is_empty() {
                return Err(format!("MASQUE: \"pass\" of {email} is empty"));
            }
            let lower = email.to_lowercase();
            if emails.contains_key(&lower) {
                return Err(format!("MASQUE: duplicate \"email\" {email}"));
            }
            emails.insert(lower, true);
            let level = u.get("level").and_then(Value::as_u64).unwrap_or(0) as u32;
            users.push(MasqueUser {
                email: email.to_owned(),
                pass: pass.to_owned(),
                level,
            });
        }
    }

    let addr_list = settings
        .get("address")
        .and_then(Value::as_array)
        .ok_or_else(|| err("MASQUE: \"address\" is not set"))?;
    if addr_list.is_empty() {
        return Err(err("MASQUE: \"address\" is not set"));
    }

    let mut raw_addrs = Vec::new();
    let mut prefixes = Vec::new();
    let mut has_v4 = false;
    let mut has_v6 = false;

    for a in addr_list {
        let s = a
            .as_str()
            .ok_or_else(|| err("MASQUE: \"address\" is not set"))?;
        let (ip_str, prefix_len) = if let Some((ip, pfx)) = s.split_once('/') {
            let len = pfx
                .parse::<u8>()
                .map_err(|_| format!("MASQUE: invalid \"address\" {s}"))?;
            (ip, len)
        } else {
            return Err(format!("MASQUE: invalid \"address\" {s}"));
        };

        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|_| format!("MASQUE: invalid \"address\" {s}"))?;
        if ip.is_ipv4() {
            if has_v4 {
                return Err(err(
                    "MASQUE: \"address\" takes at most one IPv4 and one IPv6 prefix",
                ));
            }
            has_v4 = true;
        } else {
            if has_v6 {
                return Err(err(
                    "MASQUE: \"address\" takes at most one IPv4 and one IPv6 prefix",
                ));
            }
            has_v6 = true;
        }
        raw_addrs.push(s.to_owned());
        prefixes.push((ip, prefix_len));
    }

    let mtu = match settings.get("mtu").and_then(Value::as_u64) {
        Some(0) | None => 1280,
        Some(m) if (1280..=65535).contains(&m) => m as u16,
        _ => return Err(err("MASQUE: \"mtu\" must be between 1280 and 65535")),
    };

    let stream = item.get("streamSettings").unwrap_or(&Value::Null);
    let masque_settings = stream.get("masqueSettings").unwrap_or(&Value::Null);
    let path = masque_settings
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("/.well-known/masque/ip/*/*/")
        .to_owned();

    let _ = tag;
    Ok(MasqueServerConfig {
        users,
        address: raw_addrs,
        prefixes,
        mtu,
        path,
    })
}

pub struct H2StreamReader {
    stream: h2::RecvStream,
    buf: Bytes,
}

impl H2StreamReader {
    pub fn new(stream: h2::RecvStream) -> Self {
        Self {
            stream,
            buf: Bytes::new(),
        }
    }
}

impl AsyncRead for H2StreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.buf.is_empty() {
            let to_copy = buf.remaining().min(self.buf.len());
            buf.put_slice(&self.buf[..to_copy]);
            self.buf = self.buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }
        match self.stream.poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                let _ = self.stream.flow_control().release_capacity(bytes.len());
                let to_copy = buf.remaining().min(bytes.len());
                buf.put_slice(&bytes[..to_copy]);
                self.buf = bytes.slice(to_copy..);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn send_h2_data(stream: &mut h2::SendStream<Bytes>, data: Bytes) -> std::io::Result<()> {
    let mut sent = 0;
    while sent < data.len() {
        let chunk_size = (data.len() - sent).min(16384);
        stream.reserve_capacity(chunk_size);
        while stream.capacity() < chunk_size {
            poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stream closed")
                })?
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;
        }
        let chunk = data.slice(sent..sent + chunk_size);
        stream
            .send_data(chunk, false)
            .map_err(std::io::Error::other)?;
        sent += chunk_size;
    }
    Ok(())
}

/// Xray's `validator.get`: Basic credentials, the email without case, the
/// password in constant time. With no users nobody gets in.
fn check_auth(headers: &http::HeaderMap, users: &[MasqueUser]) -> Option<MasqueUser> {
    let auth = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = auth.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pass) = creds.split_once(':')?;
    let found = users.iter().find(|u| u.email.eq_ignore_ascii_case(user))?;
    constant_time_eq(found.pass.as_bytes(), pass.as_bytes()).then(|| found.clone())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn start(
    inbound: &Inbound,
    ctx: Arc<crate::vless::Context>,
    router: Arc<Router>,
) -> Result<tokio::task::AbortHandle, String> {
    let config = inbound
        .masque
        .as_ref()
        .ok_or_else(|| "missing masque settings".to_string())?;

    let mut stack_addrs = Vec::new();
    let mut client_ip = IpAddr::V4(Ipv4Addr::new(10, 14, 0, 2));

    for &(ip, _) in &config.prefixes {
        stack_addrs.push(ip);
        if ip.is_ipv4() {
            if let IpAddr::V4(v4) = ip {
                let oct = v4.octets();
                client_ip = IpAddr::V4(Ipv4Addr::new(
                    oct[0],
                    oct[1],
                    oct[2],
                    oct[3].wrapping_add(1),
                ));
            }
        }
    }

    let (to_tunnel_tx, mut to_tunnel_rx) = mpsc::channel::<Packet<Ip>>(128);
    let (from_tunnel_tx, from_tunnel_rx) = mpsc::channel::<Packet<Ip>>(128);

    let server = Server::start_raw(stack_addrs, config.mtu, to_tunnel_tx, from_tunnel_rx);
    let server = Arc::new(server);
    let server_run = server.clone();
    let s_ctx = ctx.clone();
    let s_router = router.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(tcp) = server_run.accept_tcp() => {
                    let ctx = s_ctx.clone();
                    let router = s_router.clone();
                    tokio::spawn(async move {
                        handle_tcp(tcp, ctx, router).await;
                    });
                }
                Some(udp) = server_run.accept_udp() => {
                    let ctx = s_ctx.clone();
                    let router = s_router.clone();
                    tokio::spawn(async move {
                        Box::pin(handle_udp(udp, ctx, router)).await;
                    });
                }
                else => break,
            }
        }
    });

    let (broadcast_tx, _) = broadcast::channel::<(IpAddr, Bytes)>(256);
    let bcast_tx = broadcast_tx.clone();

    tokio::spawn(async move {
        while let Some(packet) = to_tunnel_rx.recv().await {
            let bytes_pkt = packet.into_bytes();
            let bytes = bytes_pkt.as_ref();
            if !bytes.is_empty() {
                let dest = match bytes[0] >> 4 {
                    4 if bytes.len() >= 20 => {
                        let octets: [u8; 4] = bytes[16..20].try_into().unwrap();
                        IpAddr::V4(octets.into())
                    }
                    6 if bytes.len() >= 40 => {
                        let octets: [u8; 16] = bytes[24..40].try_into().unwrap();
                        IpAddr::V6(octets.into())
                    }
                    _ => continue,
                };
                let _ = bcast_tx.send((dest, Bytes::copy_from_slice(bytes)));
            }
        }
    });

    let tls_settings = inbound
        .tls
        .clone()
        .ok_or("MASQUE requires \"security\": \"tls\"")?;
    let inbound_tag = inbound.tag.clone();
    let quic_params = inbound.quic_params.clone();
    let alpn = &tls_settings.alpn;
    let use_h2 = alpn.contains(&"h2".to_string());
    let use_h3 = alpn.contains(&"h3".to_string()) || !use_h2;

    let listen_host = if inbound.listen.is_empty() {
        "0.0.0.0"
    } else {
        &inbound.listen
    };
    let bind_addr: SocketAddr = format!("{}:{}", listen_host, inbound.port)
        .parse()
        .map_err(|e| format!("invalid listen address: {e}"))?;

    let users = Arc::new(config.users.clone());
    let path = Arc::new(config.path.clone());

    let h2_users = users.clone();
    let h2_path = path.clone();
    let h2_from_tx = from_tunnel_tx.clone();
    let h2_bcast_tx = broadcast_tx.clone();

    let server_task = tokio::spawn(async move {
        let mut tasks = Vec::new();

        if use_h2 {
            let rustls_cfg = match crate::build_rustls_server_config(
                &tls_settings,
                vec![b"h2".to_vec()],
                true,
            ) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    log::warn(format!("MASQUE failed to build TLS config: {e}"));
                    return;
                }
            };
            let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                Ok(l) => l,
                Err(e) => {
                    log::warn(format!("MASQUE failed to bind TCP {bind_addr}: {e}"));
                    return;
                }
            };
            log::info(format!(
                "listening {} (masque over h2) on {}",
                inbound_tag, bind_addr
            ));

            let acceptor = tokio_rustls::TlsAcceptor::from(rustls_cfg);
            let u = h2_users.clone();
            let p = h2_path.clone();
            let f_tx = h2_from_tx.clone();
            let b_tx = h2_bcast_tx.clone();

            tasks.push(tokio::spawn(async move {
                while let Ok((stream, _peer)) = listener.accept().await {
                    let acc = acceptor.clone();
                    let u = u.clone();
                    let p = p.clone();
                    let f_tx = f_tx.clone();
                    let b_tx = b_tx.clone();

                    tokio::spawn(async move {
                        let tls_stream = match acc.accept(stream).await {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        let mut h2_conn = match h2::server::Builder::new()
                            .enable_connect_protocol()
                            .max_concurrent_streams(100)
                            .handshake(tls_stream)
                            .await
                        {
                            Ok(c) => c,
                            Err(_) => return,
                        };

                        while let Some(res) = h2_conn.accept().await {
                            let (req, respond) = match res {
                                Ok(r) => r,
                                Err(_) => break,
                            };
                            let u = u.clone();
                            let p = p.clone();
                            let f_tx = f_tx.clone();
                            let b_tx = b_tx.clone();

                            tokio::spawn(async move {
                                handle_h2_request(req, respond, u, p, client_ip, f_tx, b_tx).await;
                            });
                        }
                    });
                }
            }));
        }

        if use_h3 {
            let h3_quic = match crate::xhttp_outbound::xhttp_h3_quic_config(quic_params.as_ref()) {
                Ok(c) => c,
                Err(e) => {
                    log::warn(format!("MASQUE H3 config error: {e}"));
                    return;
                }
            };
            let mut transport_cfg = match crate::xhttp::build_quic_transport_config(&h3_quic) {
                Ok(c) => c,
                Err(e) => {
                    log::warn(format!("MASQUE H3 transport error: {e}"));
                    return;
                }
            };
            transport_cfg.datagram_receive_buffer_size(Some(1024 * 1024));
            transport_cfg.datagram_send_buffer_size(1024 * 1024);

            let rustls_cfg = match crate::build_rustls_server_config(
                &tls_settings,
                vec![b"h3".to_vec()],
                true,
            ) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    log::warn(format!("MASQUE H3 TLS error: {e}"));
                    return;
                }
            };
            let quic_server_crypto =
                match quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg) {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn(format!("MASQUE H3 crypto error: {e}"));
                        return;
                    }
                };
            let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
            server_cfg.transport_config(Arc::new(transport_cfg));

            let endpoint = match quinn::Endpoint::server(server_cfg, bind_addr) {
                Ok(ep) => ep,
                Err(e) => {
                    log::warn(format!("MASQUE failed to bind UDP {bind_addr}: {e}"));
                    return;
                }
            };
            log::info(format!(
                "listening {} (masque over h3) on {}",
                inbound_tag, bind_addr
            ));

            let u = users.clone();
            let p = path.clone();
            let f_tx = from_tunnel_tx.clone();
            let b_tx = broadcast_tx.clone();

            tasks.push(tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let u = u.clone();
                    let p = p.clone();
                    let f_tx = f_tx.clone();
                    let b_tx = b_tx.clone();

                    tokio::spawn(async move {
                        let conn = match incoming.await {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                        let mut h3_builder = h3::server::builder();
                        h3_builder.enable_extended_connect(true);
                        h3_builder.enable_datagram(true);

                        let mut h3_conn = match h3_builder
                            .build(h3_quinn::Connection::new(conn.clone()))
                            .await
                        {
                            Ok(c) => c,
                            Err(_) => return,
                        };

                        while let Some(resolver) = h3_conn.accept().await.ok().flatten() {
                            let (req, stream) = match resolver.resolve_request().await {
                                Ok(pair) => pair,
                                Err(_) => continue,
                            };
                            let u = u.clone();
                            let p = p.clone();
                            let f_tx = f_tx.clone();
                            let b_tx = b_tx.clone();
                            let conn_clone = conn.clone();

                            tokio::spawn(async move {
                                handle_h3_request(
                                    req, stream, conn_clone, u, p, client_ip, f_tx, b_tx,
                                )
                                .await;
                            });
                        }
                    });
                }
            }));
        }

        for t in tasks {
            let _ = t.await;
        }
    });

    Ok(server_task.abort_handle())
}

async fn handle_h2_request(
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    users: Arc<Vec<MasqueUser>>,
    path: Arc<String>,
    client_ip: IpAddr,
    from_tunnel_tx: mpsc::Sender<Packet<Ip>>,
    bcast_tx: broadcast::Sender<(IpAddr, Bytes)>,
) {
    if req.method() != Method::CONNECT {
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(())
                .unwrap(),
            true,
        );
        return;
    }

    if req
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|p| p.as_str())
        != Some("connect-ip")
    {
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(())
                .unwrap(),
            true,
        );
        return;
    }

    let req_path = req.uri().path();
    let expected_path = path.as_str();
    let path_matches = if expected_path.ends_with("/*/*/") || expected_path.ends_with("/*/") {
        let pfx = expected_path.trim_end_matches("/*/");
        req_path.starts_with(pfx)
    } else {
        req_path == expected_path
    };
    if !path_matches {
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap(),
            true,
        );
        return;
    }

    if check_auth(req.headers(), &users).is_none() {
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(
                    "WWW-Authenticate",
                    "Basic realm=\"masque\", charset=\"UTF-8\"",
                )
                .body(())
                .unwrap(),
            true,
        );
        return;
    }

    let mut send_stream = match respond.send_response(
        Response::builder()
            .status(StatusCode::OK)
            .header("Capsule-Protocol", "?1")
            .body(())
            .unwrap(),
        false,
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let recv_stream = req.into_body();
    let mut reader = H2StreamReader::new(recv_stream);

    let assign = encode_address_assign_capsule(&[(0, client_ip, 32)]);
    if send_h2_data(&mut send_stream, Bytes::from(assign))
        .await
        .is_err()
    {
        return;
    }
    let routes = encode_route_advertisement_capsule(&[(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        0,
    )]);
    if send_h2_data(&mut send_stream, Bytes::from(routes))
        .await
        .is_err()
    {
        return;
    }

    let send_stream = Arc::new(Mutex::new(send_stream));
    let send_for_writer = send_stream.clone();
    let mut bcast_rx = bcast_tx.subscribe();

    let writer_task = tokio::spawn(async move {
        while let Ok((dest, packet_bytes)) = bcast_rx.recv().await {
            if dest == client_ip {
                let cap = encode_datagram_capsule(&packet_bytes);
                let mut s = send_for_writer.lock().await;
                if send_h2_data(&mut s, Bytes::from(cap)).await.is_err() {
                    break;
                }
            }
        }
    });

    let reader_task = tokio::spawn(async move {
        while let Ok(cap) = read_capsule(&mut reader).await {
            if cap.capsule_type == CAPSULE_DATAGRAM {
                if let Some(pkt_data) = decode_datagram_value(&cap.value) {
                    if let Ok(pkt) = Packet::from_bytes(BytesMut::from(pkt_data)).try_into_ip() {
                        if from_tunnel_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                }
            } else if cap.capsule_type == CAPSULE_ADDRESS_REQUEST {
                let assign = encode_address_assign_capsule(&[(0, client_ip, 32)]);
                let mut s = send_stream.lock().await;
                let _ = send_h2_data(&mut s, Bytes::from(assign)).await;
            }
        }
    });

    tokio::select! {
        _ = reader_task => {}
        _ = writer_task => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    conn: quinn::Connection,
    users: Arc<Vec<MasqueUser>>,
    path: Arc<String>,
    client_ip: IpAddr,
    from_tunnel_tx: mpsc::Sender<Packet<Ip>>,
    bcast_tx: broadcast::Sender<(IpAddr, Bytes)>,
) {
    if req.method() != Method::CONNECT {
        let _ = stream
            .send_response(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(())
                    .unwrap(),
            )
            .await;
        return;
    }
    let req_path = req.uri().path();
    let expected_path = path.as_str();
    let path_matches = if expected_path.ends_with("/*/*/") || expected_path.ends_with("/*/") {
        let pfx = expected_path.trim_end_matches("/*/");
        req_path.starts_with(pfx)
    } else {
        req_path == expected_path
    };
    if !path_matches {
        let _ = stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap(),
            )
            .await;
        return;
    }

    if check_auth(req.headers(), &users).is_none() {
        let _ = stream
            .send_response(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(
                        "WWW-Authenticate",
                        "Basic realm=\"masque\", charset=\"UTF-8\"",
                    )
                    .body(())
                    .unwrap(),
            )
            .await;
        return;
    }

    if stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("Capsule-Protocol", "?1")
                .body(())
                .unwrap(),
        )
        .await
        .is_err()
    {
        return;
    }

    let assign = encode_address_assign_capsule(&[(0, client_ip, 32)]);
    let _ = stream.send_data(Bytes::from(assign)).await;
    let routes = encode_route_advertisement_capsule(&[(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        0,
    )]);
    let _ = stream.send_data(Bytes::from(routes)).await;

    let stream_id = stream.id();
    let quarter_stream_id = stream_id.into_inner() / 4;

    let dgram_conn_read = conn.clone();
    let f_tx = from_tunnel_tx.clone();

    let reader_task = tokio::spawn(async move {
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
                                if f_tx.send(pkt).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let mut bcast_rx = bcast_tx.subscribe();
    let dgram_conn_write = conn.clone();

    let writer_task = tokio::spawn(async move {
        let mut prefix = Vec::new();
        crate::masque_capsule::encode_varint(quarter_stream_id, &mut prefix);
        crate::masque_capsule::encode_varint(0, &mut prefix); // Context ID = 0

        while let Ok((dest, packet_bytes)) = bcast_rx.recv().await {
            if dest == client_ip {
                let mut dgram = prefix.clone();
                dgram.extend_from_slice(&packet_bytes);
                if dgram_conn_write.send_datagram(Bytes::from(dgram)).is_err() {
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = reader_task => {}
        _ = writer_task => {}
    }
}

async fn handle_tcp(tcp: IncomingTcpStream, ctx: Arc<crate::vless::Context>, router: Arc<Router>) {
    let query = Query {
        inbound: &ctx.tag,
        inbound_port: ctx.port,
        user: "",
        source: tcp.src,
        network: Network::Tcp,
        domain: None,
        ip: Some(tcp.dst.ip()),
        port: tcp.dst.port(),
        protocol: None,
        attributes: None,
        local_ip: None,
        vless_route: None,
        process_info: None,
    };
    let decision = router.route(&query).await;
    let accepted = !matches!(decision.action, Action::Block(_));
    log::access(
        tcp.src,
        accepted,
        format!("tcp:{}:{}", tcp.dst.ip(), tcp.dst.port()),
        &ctx.tag,
        &decision.tag,
        "",
    );
    if !accepted {
        return;
    }
    let host = Host::Ip(tcp.dst.ip());
    let target_stream = match outbound::connect(&router, &decision, &host, tcp.dst.port()).await {
        Ok(s) => s,
        Err(e) => {
            log::warn(format!("masque tcp connect {}: {e}", tcp.dst));
            return;
        }
    };
    let traffic = stats::get().traffic(&ctx.tag, "", 0, &decision.tag);
    let (mut client_r, mut client_w) = tokio::io::split(tcp.stream);
    let (mut target_r, mut target_w) = tokio::io::split(target_stream);
    let activity = Activity::new();
    let _ = relay(
        copy(&mut client_r, &mut target_w, &activity, |n| traffic.up(n)),
        copy(&mut target_r, &mut client_w, &activity, |n| traffic.down(n)),
        &activity,
    )
    .await;
}

async fn handle_udp(udp: IncomingUdpSession, ctx: Arc<crate::vless::Context>, router: Arc<Router>) {
    let query = Query {
        inbound: &ctx.tag,
        inbound_port: ctx.port,
        user: "",
        source: udp.src,
        network: Network::Udp,
        domain: None,
        ip: Some(udp.dst.ip()),
        port: udp.dst.port(),
        protocol: None,
        attributes: None,
        local_ip: None,
        vless_route: None,
        process_info: None,
    };
    let decision = router.route(&query).await;
    let accepted = !matches!(decision.action, Action::Block(_));
    log::access(
        udp.src,
        accepted,
        format!("udp:{}:{}", udp.dst.ip(), udp.dst.port()),
        &ctx.tag,
        &decision.tag,
        "",
    );
    if !accepted {
        return;
    }
    let cone = match ConeUdp::open(router.clone(), &decision).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            log::warn(format!("masque udp open {}: {e}", udp.dst));
            return;
        }
    };
    let traffic = stats::get().traffic(&ctx.tag, "", 0, &decision.tag);
    let host = Host::Ip(udp.dst.ip());
    let port = udp.dst.port();

    if let Ok(addr) = cone.target(&host, port).await {
        let _ = cone.send_to(&udp.first_packet, addr).await;
        traffic.up(udp.first_packet.len());
    }

    let (mut client_rx, resp_tx) = (udp.rx, udp.response_tx);
    let src = udp.src;
    let dst = udp.dst;
    let cone_send = cone.clone();
    let traffic_up = traffic.clone();
    let host_up = host.clone();

    let up = tokio::spawn(async move {
        while let Some(pkt) = client_rx.recv().await {
            traffic_up.up(pkt.len());
            if let Ok(addr) = cone_send.target(&host_up, port).await {
                if cone_send.send_to(&pkt, addr).await.is_err() {
                    break;
                }
            }
        }
    });

    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, _from)) = cone.recv_from(&mut buf).await {
            traffic.down(n);
            if resp_tx.send((dst, src, buf[..n].to_vec())).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}
