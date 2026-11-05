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

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 2;
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
                        sniffing: info.sniffing,
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
                    if !udp {
                        let data = frame.data.as_deref().unwrap_or_default();
                        info.sniffing.override_host(data, &mut host);
                    }
                    let traffic = stats::get().traffic(&info.tag, &info.email, &decision.tag);
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
