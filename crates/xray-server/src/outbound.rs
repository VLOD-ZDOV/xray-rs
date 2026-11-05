//! Dialing the routed outbound: direct (freedom), a WireGuard tunnel or a SOCKS5 proxy.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use xray_config::Network;
use xray_wireguard::UdpSession;

use crate::routing::{Action, Decision, Router};
use crate::socks::SocksUdp;
use crate::vless::{resolve, resolve_all, Host, CONNECT_TIMEOUT};
use crate::wg::{to_io, WgOutbound};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub async fn connect(router: &Router, decision: &Decision, host: &Host, port: u16) -> io::Result<Box<dyn Stream>> {
    match &decision.action {
        Action::Direct => Ok(Box::new(connect_direct(router, &decision.tag, host, port).await?)),
        Action::Wireguard(wg) => Ok(Box::new(wg.connect(host, port).await?)),
        Action::Socks(socks) => Ok(Box::new(socks.connect(host, port).await?)),
        Action::Block => Err(blocked(&decision.tag)),
    }
}

pub fn check_final(router: &Router, outbound: &str, network: Network, addr: SocketAddr) -> io::Result<()> {
    match router.final_action(outbound, network, addr) {
        Action::Block => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{addr} blocked by finalRules of {outbound:?}"))),
        _ => Ok(()),
    }
}

/// Tries each resolved address that passes the outbound's finalRules.
async fn connect_direct(router: &Router, outbound: &str, host: &Host, port: u16) -> io::Result<TcpStream> {
    let mut last_error = None;
    for addr in resolve_all(host, port).await? {
        if let Err(e) = check_final(router, outbound, Network::Tcp, addr) {
            last_error = Some(e);
            continue;
        }
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => last_error = Some(io::Error::new(io::ErrorKind::TimedOut, format!("connect to {addr} timed out"))),
        }
    }
    Err(last_error.unwrap_or_else(|| io::ErrorKind::NotFound.into()))
}

/// UDP to one destination (VLESS command 2).
pub enum UdpLink {
    Direct(UdpSocket),
    Wireguard(UdpSession),
    Socks(SocksUdp, SocketAddr),
}

impl UdpLink {
    pub async fn open(router: &Router, decision: &Decision, host: &Host, port: u16) -> io::Result<Self> {
        match &decision.action {
            Action::Direct => {
                let target = resolve(host, port).await?;
                check_final(router, &decision.tag, Network::Udp, target)?;
                let bind: SocketAddr = if target.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
                let socket = UdpSocket::bind(bind).await?;
                socket.connect(target).await?;
                Ok(Self::Direct(socket))
            }
            Action::Wireguard(wg) => Ok(Self::Wireguard(wg.open_udp(wg.udp_target(host, port).await?).await?)),
            Action::Socks(socks) => Ok(Self::Socks(socks.associate().await?, resolve(host, port).await?)),
            Action::Block => Err(blocked(&decision.tag)),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send(data).await.map(|_| ()),
            Self::Wireguard(session) => session.send(data).await.map_err(to_io),
            Self::Socks(udp, target) => udp.send_to(data, *target).await,
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.recv(buf).await,
            Self::Wireguard(session) => {
                let packet = session.recv().await.map_err(to_io)?;
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            Self::Socks(udp, target) => loop {
                let (n, from) = udp.recv_from(buf).await?;
                if from == *target {
                    break Ok(n);
                }
            },
        }
    }
}

/// A WireGuard UDP flow and the task forwarding its replies.
type WgFlow = (Arc<UdpSession>, JoinHandle<()>);

/// Full-cone UDP for XUDP: any destination, replies carry their source.
pub enum ConeUdp {
    Direct {
        socket: UdpSocket,
        dual_stack: bool,
        router: Arc<Router>,
        outbound: String,
    },
    Wireguard {
        wg: Arc<WgOutbound>,
        sessions: Mutex<HashMap<SocketAddr, WgFlow>>,
        tx: mpsc::Sender<(SocketAddr, Bytes)>,
        rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    },
    Socks(SocksUdp),
}

impl ConeUdp {
    pub async fn open(router: Arc<Router>, decision: &Decision) -> io::Result<Self> {
        match &decision.action {
            Action::Direct => {
                let socket = match UdpSocket::bind(("::", 0)).await {
                    Ok(socket) => socket,
                    Err(_) => UdpSocket::bind(("0.0.0.0", 0)).await?,
                };
                let dual_stack = socket.local_addr()?.is_ipv6();
                Ok(Self::Direct { socket, dual_stack, router, outbound: decision.tag.clone() })
            }
            Action::Wireguard(wg) => {
                let (tx, rx) = mpsc::channel(256);
                Ok(Self::Wireguard { wg: wg.clone(), sessions: Mutex::new(HashMap::new()), tx, rx: Mutex::new(rx) })
            }
            Action::Socks(socks) => Ok(Self::Socks(socks.associate().await?)),
            Action::Block => Err(blocked(&decision.tag)),
        }
    }

    /// Resolves a destination for this outbound (domains via the system resolver).
    pub async fn target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        match self {
            Self::Direct { router, outbound, .. } => {
                let addr = resolve(host, port).await?;
                check_final(router, outbound, Network::Udp, addr)?;
                Ok(addr)
            }
            Self::Wireguard { wg, .. } => wg.udp_target(host, port).await,
            Self::Socks(_) => resolve(host, port).await,
        }
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        match self {
            Self::Direct { socket, dual_stack, .. } => {
                let addr = match addr {
                    SocketAddr::V4(v4) if *dual_stack => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
                    other => other,
                };
                socket.send_to(data, addr).await.map(|_| ())
            }
            Self::Wireguard { wg, sessions, tx, .. } => {
                let mut sessions = sessions.lock().await;
                if sessions.get(&addr).is_none_or(|(_, task)| task.is_finished()) {
                    let session = Arc::new(wg.open_udp(addr).await?);
                    let (reader, tx) = (session.clone(), tx.clone());
                    let task = tokio::spawn(async move {
                        while let Ok(packet) = reader.recv().await {
                            if tx.send((addr, packet)).await.is_err() {
                                break;
                            }
                        }
                    });
                    if let Some((_, old)) = sessions.insert(addr, (session, task)) {
                        old.abort();
                    }
                }
                let session = sessions[&addr].0.clone();
                drop(sessions);
                session.send(data).await.map_err(to_io)
            }
            Self::Socks(udp) => udp.send_to(data, addr).await,
        }
    }

    /// Next reply; `buf` receives the payload for the direct socket.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Direct { socket, .. } => {
                let (n, from) = socket.recv_from(buf).await?;
                let from = match from {
                    SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().map_or(from, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
                    other => other,
                };
                Ok((n, from))
            }
            Self::Wireguard { rx, .. } => {
                let (from, packet) = rx.lock().await.recv().await.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok((n, from))
            }
            Self::Socks(udp) => udp.recv_from(buf).await,
        }
    }
}

impl Drop for ConeUdp {
    fn drop(&mut self) {
        if let Self::Wireguard { sessions, .. } = self {
            for (_, task) in sessions.get_mut().values() {
                task.abort();
            }
        }
    }
}

fn blocked(tag: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("blocked by outbound {tag:?}"))
}
