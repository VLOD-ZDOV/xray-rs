use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    io::IoSliceMut,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use blake2::{digest::consts::U32, Blake2b, Digest};
use bytes::Bytes;
use quinn::{udp, AsyncUdpSocket, Runtime, UdpPoller};
use rand::{Rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

use xray_proxy::hysteria::{
    decode_tcp_request, decode_udp_message, encode_tcp_response, encode_udp_message,
    fragment_udp_message, Reassembler, TcpResponse, UdpMessage, WireError,
};
use xray_transport::hysteria::gecko::{self, GeckoPacketSize, Reassembly};

use crate::{
    config::Inbound,
    outbound::{self, UdpLink},
    routing::Router,
    stats,
    vless::{self, Host, HysteriaUser, RouteRequest},
};
use xray_config::Network;

const SALT_LEN: usize = 8;

const MAX_REASSEMBLERS: usize = 256;

fn key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

fn encode(password: &str, salt: [u8; SALT_LEN], input: &[u8], output: &mut [u8]) {
    let mut mask = key(password, &salt);
    output[..SALT_LEN].copy_from_slice(&salt);
    for (i, byte) in input.iter().enumerate() {
        output[SALT_LEN + i] = byte ^ mask[i % mask.len()];
    }
    mask.zeroize();
}

fn decode(password: &str, buffer: &mut [u8], meta: &mut udp::RecvMeta) {
    if meta.stride <= SALT_LEN
        || meta.len > buffer.len()
        || (!meta.len.is_multiple_of(meta.stride) && meta.len % meta.stride <= SALT_LEN)
    {
        meta.len = 0;
        meta.stride = 1;
        return;
    }
    let mut written = 0;
    for offset in (0..meta.len).step_by(meta.stride) {
        let end = (offset + meta.stride).min(meta.len);
        let mut mask = key(password, &buffer[offset..offset + SALT_LEN]);
        for i in 0..end - offset - SALT_LEN {
            buffer[written + i] = buffer[offset + SALT_LEN + i] ^ mask[i % mask.len()];
        }
        written += end - offset - SALT_LEN;
        mask.zeroize();
    }
    meta.len = written;
    meta.stride -= SALT_LEN;
}

pub(crate) struct ServerCarrierSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Arc<Zeroizing<String>>,
    gecko: Option<GeckoPacketSize>,
    last_message: AtomicU32,
    ready: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
    scratch: Mutex<Box<[u8]>>,
    send_buffer: Mutex<Vec<u8>>,
    reassemblies: Mutex<HashMap<SocketAddr, (Reassembly, Instant)>>,
}

impl ServerCarrierSocket {
    pub(crate) fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        password: Arc<Zeroizing<String>>,
        gecko: Option<GeckoPacketSize>,
    ) -> Self {
        Self {
            inner,
            password,
            gecko,
            last_message: AtomicU32::new(0),
            ready: Mutex::new(VecDeque::new()),
            scratch: Mutex::new(vec![0u8; 65536].into_boxed_slice()),
            send_buffer: Mutex::new(Vec::with_capacity(2048)),
            reassemblies: Mutex::new(HashMap::new()),
        }
    }

    fn next_message(&self) -> u8 {
        self.last_message
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1) as u8
    }
}

impl fmt::Debug for ServerCarrierSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerCarrierSocket")
            .field("gecko", &self.gecko)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ServerCarrierSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        let mut buffer = self.send_buffer.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(gecko) = self
            .gecko
            .as_ref()
            .filter(|_| gecko::is_fragmented(transmit.contents))
        {
            let message = self.next_message();
            let frames =
                gecko::fragment(transmit.contents, message, *gecko, &mut rand::thread_rng());
            for (index, frame) in frames.iter().enumerate() {
                buffer.resize(frame.len() + SALT_LEN, 0);
                let mut salt = [0u8; SALT_LEN];
                rand::thread_rng().fill_bytes(&mut salt);
                encode(&self.password, salt, frame, &mut buffer);
                let fragment = udp::Transmit {
                    destination: transmit.destination,
                    ecn: transmit.ecn,
                    contents: &buffer,
                    segment_size: None,
                    src_ip: transmit.src_ip,
                };
                match self.inner.try_send(&fragment) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && index > 0 => {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            return Ok(());
        }

        buffer.resize(transmit.contents.len() + SALT_LEN, 0);
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        encode(&self.password, salt, transmit.contents, &mut buffer);
        let rewritten = udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buffer,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&rewritten)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            {
                let mut ready = self.ready.lock().unwrap_or_else(|e| e.into_inner());
                if let Some((addr, datagram)) = ready.pop_front() {
                    meta[0] = udp::RecvMeta {
                        len: datagram.len(),
                        stride: datagram.len(),
                        addr,
                        ecn: None,
                        dst_ip: None,
                    };
                    if datagram.len() <= bufs[0].len() {
                        bufs[0][..datagram.len()].copy_from_slice(&datagram);
                    } else {
                        meta[0].len = 0;
                        meta[0].stride = 1;
                    }
                    return Poll::Ready(Ok(1));
                }
            }

            let mut scratch = self.scratch.lock().unwrap_or_else(|e| e.into_inner());
            let mut wire = [IoSliceMut::new(&mut scratch)];
            let count = std::task::ready!(self.inner.poll_recv(cx, &mut wire, &mut meta[..1]))?;
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            if meta[0].len <= SALT_LEN {
                continue;
            }

            decode(&self.password, &mut scratch, &mut meta[0]);
            if meta[0].len == 0 {
                continue;
            }

            if let Some(_gecko) = &self.gecko {
                let datagram = &scratch[..meta[0].len];
                if gecko::is_fragmented(datagram) {
                    if let Some(frame) = gecko::parse_frame(datagram) {
                        let now = Instant::now();
                        let completed = {
                            let mut reassemblies =
                                self.reassemblies.lock().unwrap_or_else(|e| e.into_inner());
                            if reassemblies.len() > 4096 {
                                reassemblies.retain(|_, (_, last)| {
                                    now.duration_since(*last) < Duration::from_secs(10)
                                });
                            }
                            let entry = reassemblies
                                .entry(meta[0].addr)
                                .or_insert_with(|| (Reassembly::default(), now));
                            entry.1 = now;
                            entry.0.accept(now, frame)
                        };
                        if let Some(msg) = completed {
                            meta[0].len = msg.len();
                            meta[0].stride = msg.len();
                            if msg.len() <= bufs[0].len() {
                                bufs[0][..msg.len()].copy_from_slice(&msg);
                            } else {
                                meta[0].len = 0;
                                meta[0].stride = 1;
                            }
                            return Poll::Ready(Ok(1));
                        }
                    }
                    continue;
                }
            }

            if meta[0].len <= bufs[0].len() {
                bufs[0][..meta[0].len].copy_from_slice(&scratch[..meta[0].len]);
            } else {
                meta[0].len = 0;
                meta[0].stride = 1;
            }
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn parse_host_port(s: &str) -> Option<(Host, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_str, port_str) = rest.split_once("]:")?;
        let ip = ip_str.parse::<IpAddr>().ok()?;
        let port = port_str.parse::<u16>().ok()?;
        Some((Host::Ip(ip), port))
    } else {
        let (host_str, port_str) = s.rsplit_once(':')?;
        let port = port_str.parse::<u16>().ok()?;
        if let Ok(ip) = host_str.parse::<IpAddr>() {
            Some((Host::Ip(ip), port))
        } else {
            Some((Host::Domain(host_str.to_owned()), port))
        }
    }
}

fn random_padding(min: usize, max: usize) -> String {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(min..=max);
    (0..len)
        .map(|_| rng.gen_range(b'a'..=b'z') as char)
        .collect()
}

pub async fn start(
    inbound: &Inbound,
    ctx: Arc<vless::Context>,
    _router: Arc<Router>,
) -> Result<tokio::task::AbortHandle, String> {
    if inbound.has_udphop {
        let addr_str = if inbound.listen.is_empty() {
            "0.0.0.0"
        } else {
            &inbound.listen
        };
        return Err(format!(
            "failed to listen on address: {}:{} > transport/internet/finalmask/udphop: udphop: client only",
            addr_str, inbound.port
        ));
    }

    let tls_settings = inbound.tls.as_ref().ok_or("Hysteria requires TLS")?;
    let rustls_config =
        crate::build_rustls_server_config(tls_settings, vec![b"h3".to_vec()], true)?;
    let quic_server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))
            .map_err(|e| format!("quic server tls: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(1024u32.into());
    transport.stream_receive_window(8_388_608u32.into());
    transport.receive_window(20_971_520u32.into());
    transport.send_window(20_971_520);
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    server_config.transport_config(Arc::new(transport));

    let listen_addr: SocketAddr = if inbound.listen.is_empty() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), inbound.port)
    } else {
        inbound
            .listen
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, inbound.port))
            .map_err(|e| format!("invalid listen address: {e}"))?
    };

    let std_socket = std::net::UdpSocket::bind(listen_addr)
        .map_err(|e| format!("failed to bind UDP socket on {listen_addr}: {e}"))?;
    let tokio_socket = quinn::TokioRuntime
        .wrap_udp_socket(std_socket)
        .map_err(|e| e.to_string())?;

    let abstract_socket: Arc<dyn AsyncUdpSocket> = if let Some(pwd) = &inbound.hysteria_salamander {
        Arc::new(ServerCarrierSocket::new(
            tokio_socket,
            Arc::new(Zeroizing::new(pwd.clone())),
            inbound.hysteria_gecko,
        ))
    } else {
        tokio_socket
    };

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        abstract_socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| e.to_string())?;

    let udp_idle_timeout = Duration::from_secs(inbound.hysteria_udp_idle_timeout.unwrap_or(60));
    let masq = inbound.hysteria_masq.clone();

    let task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let ctx = ctx.clone();
            let masq = masq.clone();
            // The handshake runs in its own task: one stalled peer must not hold up the rest.
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        handle_connection(connection, ctx, udp_idle_timeout, masq).await
                    }
                    Err(e) => crate::log::debug(format!("quic handshake failed: {e}")),
                }
            });
        }
    });

    Ok(task.abort_handle())
}

async fn serve_masq<S>(
    response: &mut h3::server::RequestStream<S, Bytes>,
    masq: Option<&crate::config::HysteriaMasqConfig>,
    req_path: &str,
) where
    S: h3::quic::BidiStream<Bytes>,
{
    match masq {
        None
        | Some(crate::config::HysteriaMasqConfig {
            masq_type: crate::config::HysteriaMasqType::NotFound,
            ..
        }) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(())
                .ok();
            if let Some(resp) = resp {
                if response.send_response(resp).await.is_ok() {
                    let _ = response
                        .send_data(Bytes::from_static(b"404 page not found\n"))
                        .await;
                }
            }
        }
        Some(crate::config::HysteriaMasqConfig {
            masq_type: crate::config::HysteriaMasqType::String,
            masq_string,
            masq_string_headers,
            masq_string_status_code,
            ..
        }) => {
            let status = if *masq_string_status_code != 0 {
                http::StatusCode::from_u16(*masq_string_status_code).unwrap_or(http::StatusCode::OK)
            } else {
                http::StatusCode::OK
            };
            let mut builder = http::Response::builder().status(status);
            for (k, v) in masq_string_headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            if let Ok(resp) = builder.body(()) {
                if response.send_response(resp).await.is_ok() {
                    if let Some(s) = masq_string {
                        let _ = response
                            .send_data(Bytes::copy_from_slice(s.as_bytes()))
                            .await;
                    }
                }
            }
        }
        Some(crate::config::HysteriaMasqConfig {
            masq_type: crate::config::HysteriaMasqType::File,
            masq_file,
            ..
        }) => {
            let mut served = false;
            if let Some(dir) = masq_file {
                let clean_path = req_path.trim_start_matches('/');
                let target_path = std::path::Path::new(dir).join(clean_path);
                if let (Ok(canonical_dir), Ok(canonical_target)) = (
                    std::fs::canonicalize(dir),
                    std::fs::canonicalize(&target_path),
                ) {
                    if canonical_target.starts_with(&canonical_dir) && canonical_target.is_file() {
                        if let Ok(contents) = std::fs::read(&canonical_target) {
                            let resp = http::Response::builder()
                                .status(http::StatusCode::OK)
                                .body(())
                                .ok();
                            if let Some(resp) = resp {
                                if response.send_response(resp).await.is_ok() {
                                    let _ = response.send_data(Bytes::from(contents)).await;
                                    served = true;
                                }
                            }
                        }
                    }
                }
            }
            if !served {
                let resp = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(())
                    .ok();
                if let Some(resp) = resp {
                    if response.send_response(resp).await.is_ok() {
                        let _ = response
                            .send_data(Bytes::from_static(b"404 page not found\n"))
                            .await;
                    }
                }
            }
        }
        Some(crate::config::HysteriaMasqConfig {
            masq_type: crate::config::HysteriaMasqType::Proxy,
            ..
        }) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .ok();
            if let Some(resp) = resp {
                let _ = response.send_response(resp).await;
            }
        }
    }
    let _ = response.finish().await;
}

async fn handle_connection(
    connection: quinn::Connection,
    ctx: Arc<vless::Context>,
    udp_idle_timeout: Duration,
    masq: Option<crate::config::HysteriaMasqConfig>,
) {
    let masq_for_auth = masq.clone();
    let auth_res = tokio::time::timeout(Duration::from_secs(4), async {
        let mut h3_conn: h3::server::Connection<_, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .ok()?;
        let request = h3_conn.accept().await.ok()??;
        let (request, mut response) = request.resolve_request().await.ok()?;

        let is_auth_path = request.uri().path().ends_with("/auth") || request.uri().path() == "/";
        if request.method() != http::Method::POST || !is_auth_path {
            serve_masq(&mut response, masq_for_auth.as_ref(), request.uri().path()).await;
            return None;
        }
        let auth_header = match request
            .headers()
            .get("hysteria-auth")
            .and_then(|h| h.to_str().ok())
        {
            Some(a) => a,
            None => {
                serve_masq(&mut response, masq_for_auth.as_ref(), request.uri().path()).await;
                return None;
            }
        };

        let user = {
            let users = ctx
                .hysteria_users
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            users.iter().find(|u| u.auth == auth_header).cloned()
        };
        let user = match user {
            Some(u) => u,
            None => {
                serve_masq(&mut response, masq_for_auth.as_ref(), request.uri().path()).await;
                return None;
            }
        };

        let padding = random_padding(256, 1024);
        let resp = http::Response::builder()
            .status(http::StatusCode::from_u16(233).unwrap())
            .header("hysteria-udp", "true")
            .header("hysteria-cc-rx", "0")
            .header("hysteria-padding", padding)
            .body(())
            .ok()?;
        response.send_response(resp).await.ok()?;
        response.finish().await.ok()?;

        // h3::server::Connection::drop sends H3_NO_ERROR closing the underlying
        // QUIC connection. In Hysteria 2, HTTP/3 is only used for the initial auth
        // exchange; we must not close the QUIC connection on completion.
        std::mem::forget(h3_conn);
        Some(user)
    })
    .await;

    let user = match auth_res {
        Ok(Some(u)) => u,
        _ => {
            connection.close(0x100u32.into(), b"unauthorized");
            return;
        }
    };

    let peer_addr = connection.remote_address();
    let _online = stats::get().connect(&user.email, user.level, peer_addr.ip());

    let conn_for_tcp = connection.clone();
    let ctx_for_tcp = ctx.clone();
    let user_for_tcp = user.clone();

    let tcp_task = tokio::spawn(handle_tcp_streams(conn_for_tcp, ctx_for_tcp, user_for_tcp));
    let udp_task = tokio::spawn(handle_udp_datagrams(
        connection,
        ctx,
        user,
        udp_idle_timeout,
    ));

    let _ = tokio::join!(tcp_task, udp_task);
}

async fn handle_tcp_streams(
    connection: quinn::Connection,
    ctx: Arc<vless::Context>,
    user: HysteriaUser,
) {
    let peer = connection.remote_address();
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let ctx = ctx.clone();
        let user = user.clone();
        tokio::spawn(async move {
            let mut wire = Vec::new();
            let mut buf = [0u8; 2048];
            let (req, consumed) = loop {
                let n =
                    match tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await {
                        Ok(Ok(Some(n))) => n,
                        _ => return,
                    };
                wire.extend_from_slice(&buf[..n]);
                match decode_tcp_request(&wire) {
                    Ok((req, consumed)) => break (req, consumed),
                    Err(WireError::Incomplete) => {
                        if wire.len() > 8192 {
                            return;
                        }
                        continue;
                    }
                    Err(_) => return,
                }
            };

            let host_port = req.address;
            let (host, port) = match parse_host_port(host_port) {
                Some(hp) => hp,
                None => return,
            };

            let early = &wire[consumed..];
            let route = RouteRequest {
                ctx_tag: &ctx.tag,
                inbound_port: ctx.port,
                email: &user.email,
                peer,
                network: Network::Tcp,
                host: &host,
                port,
                sniffing: &ctx.sniffing,
            };

            let decision = match route.allow(&ctx.router, early).await {
                Some(d) => d,
                None => {
                    let resp = encode_tcp_response(&TcpResponse {
                        status: 1,
                        message: b"",
                        padding: b"",
                    })
                    .unwrap_or_default();
                    let _ = send.write_all(&resp).await;
                    let _ = send.finish();
                    return;
                }
            };

            let resp = encode_tcp_response(&TcpResponse {
                status: 0,
                message: b"",
                padding: b"",
            })
            .unwrap_or_default();
            if send.write_all(&resp).await.is_err() {
                return;
            }

            let mut outbound_stream =
                match outbound::connect(&ctx.router, &decision, &host, port).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

            if !early.is_empty() && outbound_stream.write_all(early).await.is_err() {
                return;
            }

            eprintln!("[hysteria] connected outbound, relaying");

            let traffic = stats::get().traffic(&ctx.tag, &user.email, user.level, &decision.tag);
            let (mut out_r, mut out_w) = tokio::io::split(outbound_stream);

            let up = async {
                let mut buf = vec![0u8; 16384];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) if n > 0 => {
                            traffic.up(n);
                            if out_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let _ = out_w.shutdown().await;
            };

            let down = async {
                let mut buf = vec![0u8; 16384];
                loop {
                    match out_r.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            traffic.down(n);
                            if send.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let _ = send.finish();
            };

            tokio::join!(up, down);
        });
    }
}

type SessionEntry = (mpsc::Sender<Vec<u8>>, Instant);
type UdpSessions = Arc<Mutex<HashMap<u32, SessionEntry>>>;

async fn handle_udp_datagrams(
    connection: quinn::Connection,
    ctx: Arc<vless::Context>,
    user: HysteriaUser,
    udp_idle_timeout: Duration,
) {
    let peer = connection.remote_address();
    let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
    let reassemblers: Arc<Mutex<HashMap<u32, Reassembler>>> = Arc::new(Mutex::new(HashMap::new()));

    let sessions_sweep = sessions.clone();
    let reassemblers_sweep = reassemblers.clone();
    let sweep_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let now = Instant::now();
            let mut s = sessions_sweep.lock().unwrap_or_else(|e| e.into_inner());
            s.retain(|_, (_, last_active)| now.duration_since(*last_active) < udp_idle_timeout);
            drop(s);
            let mut r = reassemblers_sweep.lock().unwrap_or_else(|e| e.into_inner());
            r.retain(|_, reassembler| {
                reassembler.expire(now);
                reassembler.buffered_payload_bytes() > 0
            });
        }
    });

    while let Ok(datagram) = connection.read_datagram().await {
        let message = match decode_udp_message(&datagram) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let (address_str, payload) = if message.fragment_count <= 1 {
            (message.address.to_owned(), message.payload.to_vec())
        } else {
            let mut r_map = reassemblers.lock().unwrap_or_else(|e| e.into_inner());
            // Each partial packet holds up to 64 KiB; cap them per connection.
            if r_map.len() >= MAX_REASSEMBLERS && !r_map.contains_key(&message.session_id) {
                continue;
            }
            let reassembler = r_map.entry(message.session_id).or_insert_with(|| {
                Reassembler::new(message.session_id, 65535, Duration::from_secs(10))
                    .expect("valid reassembler")
            });
            match reassembler.feed(&message, Instant::now()) {
                Ok(Some(datagram)) => (datagram.address, datagram.payload),
                _ => continue,
            }
        };

        let session_id = message.session_id;
        let session_tx = {
            let mut s_map = sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((tx, last_active)) = s_map.get_mut(&session_id) {
                *last_active = Instant::now();
                Some(tx.clone())
            } else {
                None
            }
        };

        if let Some(tx) = session_tx {
            let _ = tx.try_send(payload);
        } else {
            let (host, port) = match parse_host_port(&address_str) {
                Some(hp) => hp,
                None => continue,
            };
            let route = RouteRequest {
                ctx_tag: &ctx.tag,
                inbound_port: ctx.port,
                email: &user.email,
                peer,
                network: Network::Udp,
                host: &host,
                port,
                sniffing: &ctx.sniffing,
            };
            let decision = match route.allow(&ctx.router, &payload).await {
                Some(d) => d,
                None => continue,
            };
            let link = match UdpLink::open(&ctx.router, &decision, &host, port).await {
                Ok(l) => Arc::new(l),
                Err(_) => continue,
            };

            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
            sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(session_id, (tx, Instant::now()));

            let conn = connection.clone();
            let sessions_for_task = sessions.clone();
            let traffic = stats::get().traffic(&ctx.tag, &user.email, user.level, &decision.tag);
            let addr_for_down = address_str.clone();

            traffic.up(payload.len());
            let _ = link.send(&payload).await;

            tokio::spawn(async move {
                let link_up = link.clone();
                let traffic_up = traffic.clone();
                let up = async move {
                    while let Some(packet) = rx.recv().await {
                        traffic_up.up(packet.len());
                        if link_up.send(&packet).await.is_err() {
                            break;
                        }
                    }
                };

                let link_down = link;
                let traffic_down = traffic;
                let down = async move {
                    let mut buf = vec![0u8; 65535];
                    let mut packet_id: u16 = 1;
                    loop {
                        let n = match link_down.recv(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => break,
                        };
                        traffic_down.down(n);
                        let max_dgram = conn.max_datagram_size().unwrap_or(1200);
                        let msg = UdpMessage {
                            session_id,
                            packet_id,
                            fragment_id: 0,
                            fragment_count: 1,
                            address: &addr_for_down,
                            payload: &buf[..n],
                        };
                        packet_id = packet_id.wrapping_add(1);

                        match fragment_udp_message(&msg, max_dgram) {
                            Ok(fragments) => {
                                for frag in fragments {
                                    if let Ok(encoded) = encode_udp_message(&frag) {
                                        if conn
                                            .send_datagram_wait(Bytes::from(encoded))
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                if let Ok(encoded) = encode_udp_message(&msg) {
                                    let _ = conn.send_datagram_wait(Bytes::from(encoded)).await;
                                }
                            }
                        }
                    }
                };

                tokio::select! {
                    _ = up => {},
                    _ = down => {},
                }

                sessions_for_task
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&session_id);
            });
        }
    }

    sweep_task.abort();
    sessions.lock().unwrap_or_else(|e| e.into_inner()).clear();
}
