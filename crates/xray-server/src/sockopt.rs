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
    if sockopt.tproxy != TproxyMode::Off {
        let transparent = sock
            .set_ip_transparent_v4(true)
            .or_else(|_| sock.set_ip_transparent_v6(true));
        warn("tproxy", transparent);
    }
}

pub fn apply_dial_udp(socket: &impl AsFd, sockopt: &SockoptSettings) {
    let sock = SockRef::from(socket);
    if sockopt.mark != 0 {
        warn("mark", sock.set_mark(sockopt.mark));
    }
    if let Some(iface) = &sockopt.interface {
        warn("interface", sock.bind_device(Some(iface.as_bytes())));
    }
    if sockopt.tproxy != TproxyMode::Off {
        let transparent = sock
            .set_ip_transparent_v4(true)
            .or_else(|_| sock.set_ip_transparent_v6(true));
        warn("tproxy", transparent);
    }
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
    UdpSocket::from_std(socket.into())
}

pub fn apply_trusted_x_forwarded_for(
    headers: &http::HeaderMap,
    trusted: &[String],
    remote_addr: SocketAddr,
) -> SocketAddr {
    let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return remote_addr;
    };
    apply_trusted_x_forwarded_for_value(
        value,
        |header_name| {
            headers
                .keys()
                .any(|k| k.as_str().eq_ignore_ascii_case(header_name))
        },
        trusted,
        remote_addr,
    )
}

pub fn apply_trusted_x_forwarded_for_raw<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    trusted: &[String],
    remote_addr: SocketAddr,
) -> SocketAddr {
    let list: Vec<(&str, &str)> = headers.into_iter().collect();
    let Some((_, value)) = list
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
    else {
        return remote_addr;
    };
    apply_trusted_x_forwarded_for_value(
        value,
        |header_name| {
            list.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(header_name))
        },
        trusted,
        remote_addr,
    )
}

fn apply_trusted_x_forwarded_for_value(
    value: &str,
    has_header: impl Fn(&str) -> bool,
    trusted: &[String],
    remote_addr: SocketAddr,
) -> SocketAddr {
    if value.trim().is_empty() {
        return remote_addr;
    }
    for t in trusted {
        if has_header(t) {
            let first = match value.find(',') {
                Some(idx) => &value[..idx],
                None => value,
            };
            let clean = first.trim().trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
                return SocketAddr::new(ip, 0);
            }
            return remote_addr;
        }
    }
    if trusted.is_empty() {
        log::warn(format!(
            "received \"X-Forwarded-For\" from {remote_addr} but \"sockopt.trustedXForwardedFor\" is not configured; ignoring it and using the real remote address"
        ));
    } else {
        log::error(format!(
            "ignored potentially forged \"X-Forwarded-For\" from {remote_addr}: {value}"
        ));
    }
    remote_addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_trusted_x_forwarded_for() {
        let remote: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // 1. Without trusted header configured
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            http::HeaderValue::from_static("129.78.138.66, 129.78.64.103"),
        );
        assert_eq!(apply_trusted_x_forwarded_for(&headers, &[], remote), remote);

        // 2. With trusted header present
        headers.insert(
            http::header::HeaderName::from_static("x-trusted-cdn"),
            http::HeaderValue::from_static(""),
        );
        let trusted = vec!["x-trusted-cdn".to_string()];
        let expected: SocketAddr = "129.78.138.66:0".parse().unwrap();
        assert_eq!(
            apply_trusted_x_forwarded_for(&headers, &trusted, remote),
            expected
        );

        // 3. Ignore non-IP X-Forwarded-For
        let mut non_ip = http::HeaderMap::new();
        non_ip.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            http::HeaderValue::from_static("example.com"),
        );
        non_ip.insert(
            http::header::HeaderName::from_static("x-trusted-cdn"),
            http::HeaderValue::from_static(""),
        );
        assert_eq!(
            apply_trusted_x_forwarded_for(&non_ip, &trusted, remote),
            remote
        );

        // 4. Raw iterator version matches
        let raw = vec![
            ("X-Forwarded-For", "129.78.138.66, 129.78.64.103"),
            ("X-Trusted-CDN", ""),
        ];
        assert_eq!(
            apply_trusted_x_forwarded_for_raw(raw, &trusted, remote),
            expected
        );
    }
}
