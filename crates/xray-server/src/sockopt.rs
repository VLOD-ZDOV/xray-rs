//! `streamSettings.sockopt`: socket options for listeners and freedom dials.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio_tfo::{TfoListener, TfoStream};

use crate::config::{SockoptSettings, TproxyMode};
use crate::log;

/// Binds a listener with Xray's inbound options.
pub fn bind_tcp(addr: SocketAddr, sockopt: &SockoptSettings) -> io::Result<TcpListener> {
    let protocol = sockopt.mptcp.then_some(Protocol::MPTCP);
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, protocol)?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(sockopt.v6only)?;
    }
    if sockopt.mark != 0 {
        warn("mark", socket.set_mark(sockopt.mark));
    }
    apply_tcp(&socket, sockopt);
    if sockopt.tproxy != TproxyMode::Off {
        let transparent = if addr.is_ipv4() {
            socket.set_ip_transparent_v4(true)
        } else {
            socket.set_ip_transparent_v6(true)
        };
        warn("tproxy", transparent);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let listener = std::net::TcpListener::from(socket);
    // tokio-tfo sets TCP_FASTOPEN (queue 1024) on the socket; the duplicate
    // descriptor it owns shares the socket, so the option stays.
    if sockopt.tcp_fast_open.is_some_and(|tfo| tfo > 0) {
        warn(
            "tcpFastOpen",
            TfoListener::from_std(listener.try_clone()?).map(drop),
        );
    }
    TcpListener::from_std(listener)
}

pub fn set_nodelay(stream: &impl AsFd) {
    let _ = SockRef::from(stream).set_tcp_nodelay(true);
}

/// Where a redirected connection was going (`tproxy: "redirect"`).
pub fn original_destination(stream: &impl AsFd) -> Option<SocketAddr> {
    let sock = SockRef::from(stream);
    sock.original_dst_v4()
        .or_else(|_| sock.original_dst_v6())
        .ok()
        .and_then(|addr| addr.as_socket())
}

/// Xray's outbound options, set before connecting.
pub fn apply_dial(socket: &TcpSocket, sockopt: &SockoptSettings) {
    let sock = SockRef::from(socket);
    if sockopt.mark != 0 {
        warn("mark", sock.set_mark(sockopt.mark));
    }
    if let Some(iface) = &sockopt.interface {
        warn("interface", sock.bind_device(Some(iface.as_bytes())));
    }
    apply_tcp(&sock, sockopt);
}

/// Connects with TCP Fast Open when it is on: the SYN carries the first write.
pub async fn connect(
    socket: TcpSocket,
    addr: SocketAddr,
    sockopt: Option<&SockoptSettings>,
) -> io::Result<Box<dyn crate::outbound::Stream>> {
    if let Some(sockopt) = sockopt {
        apply_dial(&socket, sockopt);
        if sockopt.tcp_fast_open.is_some_and(|tfo| tfo > 0) {
            let stream = TfoStream::connect_with_socket(socket, addr).await?;
            set_nodelay(&stream);
            return Ok(Box::new(stream));
        }
    }
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(Box::new(stream))
}

/// The TCP options Xray sets on both sides. Keepalive: a positive idle or
/// interval turns it on, otherwise a negative one turns it off.
fn apply_tcp(sock: &Socket, sockopt: &SockoptSettings) {
    let idle = sockopt.tcp_keep_alive_idle.unwrap_or(0);
    let interval = sockopt.tcp_keep_alive_interval.unwrap_or(0);
    if idle > 0 || interval > 0 {
        let mut keepalive = TcpKeepalive::new();
        if idle > 0 {
            keepalive = keepalive.with_time(Duration::from_secs(idle as u64));
        }
        if interval > 0 {
            keepalive = keepalive.with_interval(Duration::from_secs(interval as u64));
        }
        warn("keepalive", sock.set_tcp_keepalive(&keepalive));
    } else if idle < 0 || interval < 0 {
        warn("keepalive", sock.set_keepalive(false));
    }
    if let Some(name) = &sockopt.tcp_congestion {
        warn("tcpCongestion", sock.set_tcp_congestion(name.as_bytes()));
    }
    if let Some(ms) = sockopt.tcp_user_timeout_ms {
        let timeout = Duration::from_millis(u64::from(ms));
        warn("tcpUserTimeout", sock.set_tcp_user_timeout(Some(timeout)));
    }
    if let Some(mss) = sockopt.tcp_max_seg {
        warn("tcpMaxSeg", sock.set_tcp_mss(mss));
    }
}

fn warn(option: &str, result: io::Result<()>) {
    if let Err(e) = result {
        log::warn(format!("sockopt {option}: {e}"));
    }
}

/// A freedom UDP socket with Xray's outbound mark and interface.
pub fn bind_udp(addr: SocketAddr, sockopt: Option<&SockoptSettings>) -> io::Result<UdpSocket> {
    let Some(sockopt) = sockopt else {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        return UdpSocket::from_std(socket);
    };
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    if sockopt.mark != 0 {
        warn("mark", socket.set_mark(sockopt.mark));
    }
    if let Some(iface) = &sockopt.interface {
        warn("interface", socket.bind_device(Some(iface.as_bytes())));
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}
