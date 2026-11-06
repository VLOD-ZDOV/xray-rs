//! Mux.Cool server (Xray common/mux): TCP sub-sessions and UDP packet sessions,
//! which is how Xray clients carry XUDP. Frame layout:
//! u16 meta_len | u16 id | u8 status | u8 option | [u8 network | u16 port | addr] [global id]
//! then, with OptionData, u16 data_len | data.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use xray_config::Network;

use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, BlockAction, Decision, Router};
use crate::stats::{self, Traffic};
use crate::vless::{host_label, Host, RouteRequest, Sniffing, CONN_IDLE};

pub(crate) const STATUS_NEW: u8 = 1;
pub(crate) const STATUS_KEEP: u8 = 2;
pub(crate) const STATUS_END: u8 = 3;
pub(crate) const STATUS_KEEP_ALIVE: u8 = 4;
pub(crate) const OPTION_DATA: u8 = 1;
pub(crate) const OPTION_ERROR: u8 = 2;
pub(crate) const NETWORK_TCP: u8 = 1;
pub(crate) const NETWORK_UDP: u8 = 2;
const MAX_META: usize = 512;
const MAX_SESSIONS: usize = 1024;
// Xray splits stream data into 8 KiB frames.
const STREAM_CHUNK: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub id: u16,
    pub status: u8,
    pub option: u8,
    pub target: Option<(u8, Host, u16)>,
    pub data: Option<Vec<u8>>,
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let meta_len = reader.read_u16().await? as usize;
    if !(4..=MAX_META).contains(&meta_len) {
        return Err(invalid("invalid mux metadata length"));
    }
    let mut meta = vec![0u8; meta_len];
    reader.read_exact(&mut meta).await?;
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let (status, option) = (meta[2], meta[3]);

    let mut target = None;
    // A Keep frame may carry a per-packet UDP address; the flag byte must be checked first.
    if status == STATUS_NEW || (status == STATUS_KEEP && meta.len() > 4 && meta[4] == NETWORK_UDP) {
        let network = meta[4];
        if network != NETWORK_TCP && network != NETWORK_UDP {
            return Err(invalid("unknown mux network"));
        }
        let (host, port, _) =
            parse_port_addr(&meta[5..]).ok_or_else(|| invalid("bad mux address"))?;
        target = Some((network, host, port));
    }

    let data = if option & OPTION_DATA != 0 {
        let len = reader.read_u16().await? as usize;
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await?;
        Some(data)
    } else {
        None
    };
    Ok(Frame {
        id,
        status,
        option,
        target,
        data,
    })
}

fn parse_port_addr(buf: &[u8]) -> Option<(Host, u16, usize)> {
    let port = u16::from_be_bytes([*buf.first()?, *buf.get(1)?]);
    let (host, used) = match *buf.get(2)? {
        1 => (
            Host::Ip(IpAddr::from(<[u8; 4]>::try_from(buf.get(3..7)?).ok()?)),
            7,
        ),
        2 => {
            let len = *buf.get(3)? as usize;
            let name = std::str::from_utf8(buf.get(4..4 + len)?).ok()?;
            let host = name
                .parse::<IpAddr>()
                .map_or_else(|_| Host::Domain(name.to_owned()), Host::Ip);
            (host, 4 + len)
        }
        3 => (
            Host::Ip(IpAddr::from(<[u8; 16]>::try_from(buf.get(3..19)?).ok()?)),
            19,
        ),
        _ => return None,
    };
    Some((host, port, used))
}

/// Encodes a server-to-client frame. `udp_from` marks a UDP packet's source.
pub fn encode_frame(
    id: u16,
    status: u8,
    option: u8,
    udp_from: Option<SocketAddr>,
    data: Option<&[u8]>,
) -> Bytes {
    let mut meta = BytesMut::with_capacity(32);
    meta.put_u16(id);
    meta.put_u8(status);
    meta.put_u8(option);
    if let Some(addr) = udp_from {
        meta.put_u8(NETWORK_UDP);
        meta.put_u16(addr.port());
        match addr.ip() {
            IpAddr::V4(ip) => {
                meta.put_u8(1);
                meta.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                meta.put_u8(3);
                meta.put_slice(&ip.octets());
            }
        }
    }
    let mut out = BytesMut::with_capacity(2 + meta.len() + data.map_or(0, |d| 2 + d.len()));
    out.put_u16(meta.len() as u16);
    out.put_slice(&meta);
    if let Some(data) = data {
        out.put_u16(data.len() as u16);
        out.put_slice(data);
    }
    out.freeze()
}

fn end_frame(id: u16, error: bool) -> Bytes {
    encode_frame(
        id,
        STATUS_END,
        if error { OPTION_ERROR } else { 0 },
        None,
        None,
    )
}

pub struct Info {
    pub peer: SocketAddr,
    pub tag: String,
    pub port: u16,
    pub email: String,
    pub level: u32,
    pub router: Arc<Router>,
    pub sniffing: Sniffing,
}

struct Packet {
    data: Bytes,
    dest: Option<(Host, u16)>,
}

struct Session {
    input: mpsc::Sender<Packet>,
    udp: bool,
    task: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn serve<R, W>(uplink: &mut R, downlink: &mut W, info: &Info) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
    let mut sessions: HashMap<u16, Session> = HashMap::new();

    let reader = async {
        loop {
            let frame = match read_frame(uplink).await {
                Ok(frame) => frame,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            match frame.status {
                STATUS_NEW => {
                    let Some((network, mut host, port)) = frame.target else {
                        return Err(invalid("mux new frame without target"));
                    };
                    if sessions.len() >= MAX_SESSIONS {
                        let _ = out_tx.send(end_frame(frame.id, true)).await;
                        continue;
                    }
                    let udp = network == NETWORK_UDP;
                    let route = RouteRequest {
                        ctx_tag: &info.tag,
                        inbound_port: info.port,
                        email: &info.email,
                        peer: info.peer,
                        network: if udp { Network::Udp } else { Network::Tcp },
                        host: &host,
                        port,
                        sniffing: &info.sniffing,
                    };
                    let Some(decision) = route
                        .allow(&info.router, frame.data.as_deref().unwrap_or_default())
                        .await
                    else {
                        let _ = out_tx.send(end_frame(frame.id, true)).await;
                        continue;
                    };
                    if let Action::Block(BlockAction::Http403) = decision.action {
                        if !udp {
                            let resp = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=600\r\nContent-Length: 0\r\n\r\n";
                            let _ = out_tx
                                .send(encode_frame(
                                    frame.id,
                                    STATUS_KEEP,
                                    OPTION_DATA,
                                    None,
                                    Some(resp),
                                ))
                                .await;
                        }
                        let _ = out_tx.send(end_frame(frame.id, false)).await;
                        continue;
                    }
                    let data = frame.data.as_deref().unwrap_or_default();
                    info.sniffing.override_host(data, &mut host);
                    let traffic =
                        stats::get().traffic(&info.tag, &info.email, info.level, &decision.tag);
                    let dial = Dial {
                        router: info.router.clone(),
                        decision,
                        traffic,
                    };
                    let (tx, rx) = mpsc::channel(64);
                    let out = out_tx.clone();
                    let id = frame.id;
                    let task = if udp {
                        tokio::spawn(udp_session(id, (host, port), rx, out, dial))
                    } else {
                        tokio::spawn(tcp_session(id, (host, port), rx, out, dial))
                    };
                    let session = Session {
                        input: tx,
                        udp,
                        task,
                    };
                    if let Some(data) = frame.data {
                        forward(
                            &session,
                            Packet {
                                data: data.into(),
                                dest: None,
                            },
                        )
                        .await;
                    }
                    sessions.insert(frame.id, session);
                }
                STATUS_KEEP => {
                    let Some(data) = frame.data else { continue };
                    match sessions.get(&frame.id) {
                        Some(session) => {
                            let dest = frame.target.map(|(_, host, port)| (host, port));
                            forward(
                                session,
                                Packet {
                                    data: data.into(),
                                    dest,
                                },
                            )
                            .await;
                        }
                        // Tell the client this session is gone.
                        None => {
                            let _ = out_tx.send(end_frame(frame.id, false)).await;
                        }
                    }
                }
                STATUS_END => {
                    sessions.remove(&frame.id);
                }
                STATUS_KEEP_ALIVE => {}
                _ => return Err(invalid("unknown mux status")),
            }
        }
    };
    let writer = async {
        while let Some(frame) = out_rx.recv().await {
            downlink.write_all(&frame).await?;
            downlink.flush().await?;
        }
        Ok::<(), io::Error>(())
    };
    tokio::select! {
        result = reader => result,
        result = writer => result,
    }
}

async fn forward(session: &Session, packet: Packet) {
    if session.udp {
        // Drop UDP under pressure instead of stalling every other session.
        let _ = session.input.try_send(packet);
    } else {
        let _ = session.input.send(packet).await;
    }
}

/// Where a sub-session's traffic goes after routing.
struct Dial {
    router: Arc<Router>,
    decision: Decision,
    traffic: Traffic,
}

async fn tcp_session(
    id: u16,
    target: (Host, u16),
    mut input: mpsc::Receiver<Packet>,
    out: mpsc::Sender<Bytes>,
    dial: Dial,
) {
    let result: io::Result<()> = async {
        let stream = outbound::connect(&dial.router, &dial.decision, &target.0, target.1).await?;
        let (mut r, mut w) = tokio::io::split(stream);
        let up = async {
            while let Some(packet) = input.recv().await {
                w.write_all(&packet.data).await?;
                dial.traffic.up(packet.data.len());
            }
            w.shutdown().await
        };
        let down = async {
            let mut buf = vec![0u8; STREAM_CHUNK];
            loop {
                let n = timeout(CONN_IDLE, r.read(&mut buf))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                if n == 0 {
                    return Ok(());
                }
                dial.traffic.down(n);
                let frame = encode_frame(id, STATUS_KEEP, OPTION_DATA, None, Some(&buf[..n]));
                out.send(frame)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            }
        };
        tokio::pin!(up);
        tokio::select! {
            result = &mut up => { result?; Ok(()) }
            result = down => result,
        }
    }
    .await;
    if let Err(e) = &result {
        log::debug(format!("mux tcp session {id} ended: {e}"));
    }
    let _ = out.send(end_frame(id, result.is_err())).await;
}

/// Full-cone UDP: one socket per session, any destination, replies tagged
/// with their source address.
async fn udp_session(
    id: u16,
    target: (Host, u16),
    mut input: mpsc::Receiver<Packet>,
    out: mpsc::Sender<Bytes>,
    dial: Dial,
) {
    let result: io::Result<()> = async {
        let cone = ConeUdp::open(dial.router.clone(), &dial.decision).await?;
        let mut resolved: HashMap<(String, u16), SocketAddr> = HashMap::new();
        let up = async {
            while let Some(packet) = input.recv().await {
                let (host, port) = packet
                    .dest
                    .as_ref()
                    .map_or((&target.0, target.1), |(h, p)| (h, *p));
                let key = (host_label(host), port);
                let addr = match resolved.get(&key) {
                    Some(addr) => *addr,
                    None => match cone.target(host, port).await {
                        Ok(addr) => *resolved.entry(key).or_insert(addr),
                        Err(e) => {
                            log::debug(format!("mux udp {id}: {e}"));
                            continue;
                        }
                    },
                };
                match cone.send_to(&packet.data, addr).await {
                    Ok(()) => dial.traffic.up(packet.data.len()),
                    Err(e) => log::debug(format!("mux udp {id} send to {addr}: {e}")),
                }
            }
            Ok::<(), io::Error>(())
        };
        let down = async {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, from) = timeout(CONN_IDLE, cone.recv_from(&mut buf))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                dial.traffic.down(n);
                let frame = encode_frame(id, STATUS_KEEP, OPTION_DATA, Some(from), Some(&buf[..n]));
                out.send(frame)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            }
        };
        tokio::select! {
            result = up => result,
            result = down => result,
        }
    }
    .await;
    if let Err(e) = &result {
        log::debug(format!("mux udp session {id} ended: {e}"));
    }
    let _ = out.send(end_frame(id, result.is_err())).await;
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxUdp443 {
    Reject,
    Allow,
    Skip,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MuxSettings {
    pub enabled: bool,
    pub concurrency: i16,
    pub xudp_concurrency: i16,
    pub udp443: MuxUdp443,
}

impl MuxSettings {
    pub fn parse(v: Option<&serde_json::Value>) -> Option<Self> {
        let v = v?;
        let enabled = v
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let concurrency = v
            .get("concurrency")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(8) as i16;
        let xudp_concurrency = v
            .get("xudpConcurrency")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(16) as i16;
        let udp443_str = v
            .get("xudpProxyUDP443")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("reject");
        let udp443 = match udp443_str.to_ascii_lowercase().as_str() {
            "allow" => MuxUdp443::Allow,
            "skip" => MuxUdp443::Skip,
            _ => MuxUdp443::Reject,
        };
        Some(Self {
            enabled,
            concurrency: if concurrency == 0 { 8 } else { concurrency },
            xudp_concurrency: if xudp_concurrency == 0 {
                16
            } else {
                xudp_concurrency
            },
            udp443,
        })
    }
}

pub struct MuxClientPool {
    pub concurrency: u16,
    parents: tokio::sync::Mutex<Vec<Arc<MuxParent>>>,
}

struct MuxParent {
    writer_tx: mpsc::Sender<Bytes>,
    sessions: Arc<tokio::sync::Mutex<HashMap<u16, mpsc::Sender<Bytes>>>>,
    active_count: Arc<std::sync::atomic::AtomicU16>,
    next_id: std::sync::atomic::AtomicU16,
    concurrency: u16,
    is_closed: Arc<std::sync::atomic::AtomicBool>,
}

impl MuxClientPool {
    pub fn new(concurrency: u16) -> Self {
        Self {
            concurrency: if concurrency == 0 { 8 } else { concurrency },
            parents: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    pub async fn open_sub_session<F, Fut>(
        &self,
        open_parent: F,
        host: &Host,
        port: u16,
    ) -> io::Result<Box<dyn crate::outbound::Stream>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = io::Result<Box<dyn crate::outbound::Stream>>>,
    {
        use std::sync::atomic::Ordering;

        let mut parents = self.parents.lock().await;
        parents.retain(|p| !p.is_closed.load(Ordering::Relaxed));

        let parent = match parents
            .iter()
            .find(|p| p.active_count.load(Ordering::Relaxed) < p.concurrency)
        {
            Some(p) => Arc::clone(p),
            None => {
                let raw_stream = open_parent().await?;
                let (reader, writer) = tokio::io::split(raw_stream);
                let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(512);
                let sessions: Arc<tokio::sync::Mutex<HashMap<u16, mpsc::Sender<Bytes>>>> =
                    Arc::new(tokio::sync::Mutex::new(HashMap::new()));
                let is_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

                let is_closed_w = Arc::clone(&is_closed);
                tokio::spawn(async move {
                    let mut writer = writer;
                    while let Some(bytes) = writer_rx.recv().await {
                        if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err()
                        {
                            is_closed_w.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                });

                let sessions_r = Arc::clone(&sessions);
                let is_closed_r = Arc::clone(&is_closed);
                tokio::spawn(async move {
                    let mut reader = reader;
                    while let Ok(frame) = read_frame(&mut reader).await {
                        match frame.status {
                            STATUS_KEEP => {
                                let lock = sessions_r.lock().await;
                                if let Some(tx) = lock.get(&frame.id) {
                                    if let Some(data) = frame.data {
                                        let _ = tx.send(Bytes::from(data)).await;
                                    }
                                }
                            }
                            STATUS_END => {
                                let mut lock = sessions_r.lock().await;
                                lock.remove(&frame.id);
                            }
                            _ => {}
                        }
                    }
                    is_closed_r.store(true, Ordering::Relaxed);
                    let mut lock = sessions_r.lock().await;
                    lock.clear();
                });

                let p = Arc::new(MuxParent {
                    writer_tx,
                    sessions,
                    active_count: Arc::new(std::sync::atomic::AtomicU16::new(0)),
                    next_id: std::sync::atomic::AtomicU16::new(1),
                    concurrency: self.concurrency,
                    is_closed,
                });
                parents.push(Arc::clone(&p));
                p
            }
        };

        let session_id = loop {
            let id = parent.next_id.fetch_add(1, Ordering::Relaxed);
            let id = if id == 0 {
                parent.next_id.store(2, Ordering::Relaxed);
                1
            } else {
                id
            };
            let s = parent.sessions.lock().await;
            if !s.contains_key(&id) {
                break id;
            }
        };

        let (sub_tx, sub_rx) = mpsc::channel(64);
        {
            let mut s = parent.sessions.lock().await;
            s.insert(session_id, sub_tx);
            parent.active_count.fetch_add(1, Ordering::Relaxed);
        }

        let target = xray_routing::Target::new(
            match host {
                Host::Ip(ip) => xray_routing::TargetAddr::Ip(*ip),
                Host::Domain(d) => xray_routing::TargetAddr::Domain(d.clone()),
            },
            port,
            xray_routing::Network::Tcp,
        );
        let new_frame = xray_proxy::mux::Frame {
            session_id,
            status: xray_proxy::mux::Status::New,
            error: false,
            target: Some(target),
            global_id: None,
            payload: None,
        };
        let wire = xray_proxy::mux::encode(&new_frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        parent
            .writer_tx
            .send(Bytes::from(wire))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Mux parent closed"))?;

        Ok(Box::new(MuxSubStream {
            session_id,
            writer_tx: parent.writer_tx.clone(),
            sessions: Arc::clone(&parent.sessions),
            active_count: Arc::clone(&parent.active_count),
            rx: sub_rx,
            buffer: Bytes::new(),
            closed: false,
        }))
    }
}

pub struct MuxSubStream {
    session_id: u16,
    writer_tx: mpsc::Sender<Bytes>,
    sessions: Arc<tokio::sync::Mutex<HashMap<u16, mpsc::Sender<Bytes>>>>,
    active_count: Arc<std::sync::atomic::AtomicU16>,
    rx: mpsc::Receiver<Bytes>,
    buffer: Bytes,
    closed: bool,
}

impl AsyncRead for MuxSubStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.buffer.len());
            buf.put_slice(&self.buffer.split_to(to_read));
            return std::task::Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(chunk)) => {
                let to_read = std::cmp::min(buf.remaining(), chunk.len());
                buf.put_slice(&chunk[..to_read]);
                if to_read < chunk.len() {
                    self.buffer = chunk.slice(to_read..);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for MuxSubStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if self.closed {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Mux session closed",
            )));
        }
        let chunk_len = std::cmp::min(buf.len(), 8192);
        let frame = xray_proxy::mux::Frame {
            session_id: self.session_id,
            status: xray_proxy::mux::Status::Keep,
            error: false,
            target: None,
            global_id: None,
            payload: Some(&buf[..chunk_len]),
        };
        let wire = xray_proxy::mux::encode(&frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        match self.writer_tx.try_send(Bytes::from(wire)) {
            Ok(()) => std::task::Poll::Ready(Ok(chunk_len)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => std::task::Poll::Ready(Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "Mux parent closed"),
            )),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            let end = end_frame(self.session_id, false);
            let _ = self.writer_tx.try_send(end);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for MuxSubStream {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let end = end_frame(self.session_id, false);
            let _ = self.writer_tx.try_send(end);
        }
        self.active_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let sessions = Arc::clone(&self.sessions);
        let id = self.session_id;
        tokio::spawn(async move {
            let mut s = sessions.lock().await;
            s.remove(&id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_xudp_new_frame_with_global_id() {
        let mut meta = vec![
            0,
            5,
            STATUS_NEW,
            OPTION_DATA,
            NETWORK_UDP,
            0x01,
            0xbb,
            1,
            8,
            8,
            8,
            8,
        ];
        meta.extend_from_slice(&[9; 8]);
        let mut wire = (meta.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&meta);
        wire.extend_from_slice(&[0, 3, b'a', b'b', b'c']);
        let frame = read_frame(&mut wire.as_slice()).await.unwrap();
        assert_eq!(frame.id, 5);
        assert_eq!(
            frame.target,
            Some((NETWORK_UDP, Host::Ip("8.8.8.8".parse().unwrap()), 443))
        );
        assert_eq!(frame.data.as_deref(), Some(&b"abc"[..]));
    }

    #[tokio::test]
    async fn keep_frame_round_trips_udp_source() {
        let from: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let wire = encode_frame(7, STATUS_KEEP, OPTION_DATA, Some(from), Some(b"hi"));
        let frame = read_frame(&mut &wire[..]).await.unwrap();
        assert_eq!(frame.status, STATUS_KEEP);
        assert_eq!(frame.target, Some((NETWORK_UDP, Host::Ip(from.ip()), 53)));
        assert_eq!(frame.data.as_deref(), Some(&b"hi"[..]));
    }

    #[tokio::test]
    async fn plain_keep_frame_has_no_target() {
        let wire = encode_frame(1, STATUS_KEEP, OPTION_DATA, None, Some(b"x"));
        let frame = read_frame(&mut &wire[..]).await.unwrap();
        assert_eq!(frame.target, None);
    }
}
