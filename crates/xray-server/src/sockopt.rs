//! `streamSettings.sockopt`: socket options for listeners and freedom dials.

#![forbid(unsafe_code)]

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
    if let Some(clamp) = sockopt.tcp_window_clamp {
        warn(
            "tcpWindowClamp",
            crate::raw_sockopt::set_tcp_window_clamp(&socket, clamp),
        );
    }
    let net = if addr.is_ipv6() { "tcp6" } else { "tcp4" };
    apply_custom_sockopts(&socket, sockopt, net);
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
    if let Some(clamp) = sockopt.tcp_window_clamp {
        warn(
            "tcpWindowClamp",
            crate::raw_sockopt::set_tcp_window_clamp(socket, clamp),
        );
    }
    apply_custom_sockopts(socket, sockopt, "tcp");
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
    apply_custom_sockopts(socket, sockopt, "udp");
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

fn apply_custom_sockopts(fd: &impl AsFd, sockopt: &SockoptSettings, network: &str) {
    let os = std::env::consts::OS;
    for custom in &sockopt.custom_sockopt {
        if let Some(sys) = &custom.system {
            if !sys.is_empty() && !sys.eq_ignore_ascii_case(os) {
                log::debug(format!(
                    "CustomSockopt system not match: want {sys} got {os}"
                ));
                continue;
            }
        }
        if let Some(net) = &custom.network {
            if !net.is_empty() && !network.starts_with(net) {
                continue;
            }
        }
        let res = match &custom.value {
            crate::config::CustomSockoptValue::Int(v) => {
                crate::raw_sockopt::setsockopt_int(fd, custom.level, custom.opt, *v)
            }
            crate::config::CustomSockoptValue::Str(s) => {
                crate::raw_sockopt::setsockopt_bytes(fd, custom.level, custom.opt, s.as_bytes())
            }
        };
        warn(&format!("customSockopt({})", custom.opt), res);
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
    let net = if addr.is_ipv6() { "udp6" } else { "udp4" };
    apply_custom_sockopts(&socket, sockopt, net);
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

/// Sorts socket addresses according to RFC 8305 / Xray Happy Eyeballs specification.
pub fn sort_ips_happy_eyeballs(ips: &mut [SocketAddr], prioritize_ipv6: bool, interleave: u32) {
    if ips.len() < 2 {
        return;
    }
    let interleave = interleave.max(1) as usize;
    let mut ip4 = Vec::new();
    let mut ip6 = Vec::new();
    for &addr in ips.iter() {
        if addr.is_ipv4() {
            ip4.push(addr);
        } else {
            ip6.push(addr);
        }
    }
    if ip4.is_empty() || ip6.is_empty() {
        return;
    }
    let mut sorted = Vec::with_capacity(ips.len());
    let mut c4 = 0;
    let mut c6 = 0;
    let mut ip4_turn = !prioritize_ipv6;
    while c4 < ip4.len() || c6 < ip6.len() {
        if ip4_turn {
            let take = (ip4.len() - c4).min(interleave);
            sorted.extend_from_slice(&ip4[c4..c4 + take]);
            c4 += take;
            if c6 < ip6.len() {
                ip4_turn = false;
            }
        } else {
            let take = (ip6.len() - c6).min(interleave);
            sorted.extend_from_slice(&ip6[c6..c6 + take]);
            c6 += take;
            if c4 < ip4.len() {
                ip4_turn = true;
            }
        }
    }
    ips.copy_from_slice(&sorted);
}

/// Happy Eyeballs concurrent TCP race dialer (RFC 8305).
pub async fn connect_happy_eyeballs(
    addrs: &[SocketAddr],
    bind_ip: Option<std::net::IpAddr>,
    sockopt: Option<&SockoptSettings>,
    try_delay: Duration,
    max_concurrent: usize,
    overall_timeout: Duration,
) -> io::Result<Box<dyn crate::outbound::Stream>> {
    use tokio::task::JoinSet;
    use tokio::time::sleep;

    let max_concurrent = max_concurrent.max(1);
    let mut next_idx = 0;
    // JoinSet aborts the losing attempts when dropped.
    let mut in_flight = JoinSet::new();
    let mut last_err = None;

    let deadline = tokio::time::Instant::now() + overall_timeout;

    let make_attempt = |addr: SocketAddr, idx: usize| {
        let sockopt_clone = sockopt.cloned();
        async move {
            let socket = if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()
            } else {
                tokio::net::TcpSocket::new_v6()
            };
            let socket = match socket {
                Ok(s) => s,
                Err(e) => return (idx, addr, Err(e)),
            };
            if let Some(ip) = bind_ip {
                if let Err(e) = socket.bind(SocketAddr::new(ip, 0)) {
                    return (idx, addr, Err(e));
                }
            }
            let res = connect(socket, addr, sockopt_clone.as_ref()).await;
            (idx, addr, res)
        }
    };

    if next_idx < addrs.len() {
        in_flight.spawn(make_attempt(addrs[next_idx], next_idx));
        next_idx += 1;
    }

    let delay_sleep = sleep(try_delay);
    tokio::pin!(delay_sleep);

    while !in_flight.is_empty() || next_idx < addrs.len() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "happy eyeballs connect timed out",
            ));
        }

        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "happy eyeballs connect timed out",
                ));
            }
            _ = &mut delay_sleep, if next_idx < addrs.len() && in_flight.len() < max_concurrent => {
                in_flight.spawn(make_attempt(addrs[next_idx], next_idx));
                next_idx += 1;
                delay_sleep.as_mut().reset(tokio::time::Instant::now() + try_delay);
            }
            Some(join_res) = in_flight.join_next() => {
                match join_res {
                    Ok((_idx, _addr, Ok(stream))) => {
                        return Ok(stream);
                    }
                    Ok((_idx, _addr, Err(e))) => {
                        last_err = Some(e);
                        if next_idx < addrs.len() && in_flight.len() < max_concurrent {
                            in_flight.spawn(make_attempt(addrs[next_idx], next_idx));
                            next_idx += 1;
                            delay_sleep.as_mut().reset(tokio::time::Instant::now() + try_delay);
                        }
                    }
                    Err(join_err) => {
                        last_err = Some(io::Error::other(join_err.to_string()));
                    }
                }
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses to connect")))
}

use crate::config::AddressPortStrategy;

pub async fn resolve_address_port_strategy(
    host: &str,
    port: u16,
    strategy: AddressPortStrategy,
) -> Result<(String, u16), String> {
    if strategy == AddressPortStrategy::None {
        return Ok((host.to_string(), port));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok((host.to_string(), port));
    }

    match strategy {
        AddressPortStrategy::None => Ok((host.to_string(), port)),
        AddressPortStrategy::SrvPortOnly
        | AddressPortStrategy::SrvAddressOnly
        | AddressPortStrategy::SrvPortAndAddress => {
            let (override_port, override_address) = match strategy {
                AddressPortStrategy::SrvPortOnly => (true, false),
                AddressPortStrategy::SrvAddressOnly => (false, true),
                AddressPortStrategy::SrvPortAndAddress => (true, true),
                _ => unreachable!(),
            };
            let parts: Vec<&str> = host.splitn(3, '.').collect();
            if parts.len() != 3 {
                return Err(format!("invalid address format {host}"));
            }
            let service = parts[0].strip_prefix('_').unwrap_or(parts[0]);
            let proto = parts[1].strip_prefix('_').unwrap_or(parts[1]);
            let domain = parts[2];
            let qname = format!("_{service}._{proto}.{domain}");
            let (target_addr, target_port) = query_dns_srv(&qname)
                .await
                .map_err(|e| format!("failed to lookup SRV record: {e}"))?;
            let new_host = if override_address {
                target_addr
            } else {
                host.to_string()
            };
            let new_port = if override_port { target_port } else { port };
            Ok((new_host, new_port))
        }
        AddressPortStrategy::TxtPortOnly
        | AddressPortStrategy::TxtAddressOnly
        | AddressPortStrategy::TxtPortAndAddress => {
            let (override_port, override_address) = match strategy {
                AddressPortStrategy::TxtPortOnly => (true, false),
                AddressPortStrategy::TxtAddressOnly => (false, true),
                AddressPortStrategy::TxtPortAndAddress => (true, true),
                _ => unreachable!(),
            };
            let txt_records = query_dns_txt(host)
                .await
                .map_err(|e| format!("failed to lookup TXT record: {e}"))?;
            for txt in txt_records {
                if let Some((addr, p)) = parse_txt_endpoint(&txt) {
                    let new_host = if override_address {
                        addr
                    } else {
                        host.to_string()
                    };
                    let new_port = if override_port { p } else { port };
                    return Ok((new_host, new_port));
                }
            }
            Ok((host.to_string(), port))
        }
    }
}

fn parse_txt_endpoint(txt: &str) -> Option<(String, u16)> {
    let s = txt.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some((addr.ip().to_string(), addr.port()));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            let h = h
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(h);
            return Some((h.to_string(), port));
        }
    }
    None
}

fn get_system_nameservers() -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") || line.starts_with("nameserver\t") {
                let ip_str = line["nameserver".len()..].trim();
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    servers.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    if servers.is_empty() {
        servers.push(SocketAddr::from(([127, 0, 0, 1], 53)));
        servers.push(SocketAddr::from(([127, 0, 0, 53], 53)));
    }
    servers
}

fn encode_dns_query(qname: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&[0x12, 0x34]); // Transaction ID
    query.extend_from_slice(&[0x01, 0x00]); // Standard query, RD=1
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QD=1
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // IN class
    query
}

async fn exchange_dns_query(qname: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut query = encode_dns_query(qname, qtype);
    let id: [u8; 2] = rand::random();
    query[..2].copy_from_slice(&id);
    let nameservers = get_system_nameservers();
    let mut buf = [0u8; 4096];
    for ns in nameservers {
        let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        if socket.connect(ns).await.is_err() {
            continue;
        }
        if socket.send(&query).await.is_err() {
            continue;
        }
        if let Ok(Ok(len)) =
            tokio::time::timeout(Duration::from_millis(1500), socket.recv(&mut buf)).await
        {
            if len >= query.len()
                && buf[..2] == id
                && buf[2] & 0x80 != 0
                && buf[12..query.len()].eq_ignore_ascii_case(&query[12..])
            {
                return Ok(buf[..len].to_vec());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "DNS query timed out",
    ))
}

async fn query_dns_srv(qname: &str) -> io::Result<(String, u16)> {
    let resp = exchange_dns_query(qname, 33).await?;
    parse_srv_response(&resp)
}

async fn query_dns_txt(qname: &str) -> io::Result<Vec<String>> {
    let resp = exchange_dns_query(qname, 16).await?;
    parse_txt_response(&resp)
}

fn skip_dns_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    while offset < buf.len() {
        let b = buf[offset];
        if b == 0 {
            return Some(offset + 1);
        } else if b & 0xc0 == 0xc0 {
            return Some(offset + 2);
        } else {
            offset += 1 + (b as usize);
        }
    }
    None
}

fn read_dns_name(buf: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut loops = 0;
    while offset < buf.len() && loops < 50 {
        loops += 1;
        let b = buf[offset];
        if b == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        } else if b & 0xc0 == 0xc0 {
            if offset + 1 >= buf.len() {
                return None;
            }
            let ptr = (((b & 0x3f) as usize) << 8) | (buf[offset + 1] as usize);
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
        } else {
            let len = b as usize;
            offset += 1;
            if offset + len > buf.len() {
                return None;
            }
            if let Ok(label) = std::str::from_utf8(&buf[offset..offset + len]) {
                labels.push(label.to_string());
            }
            offset += len;
            if !jumped {
                next_offset = offset;
            }
        }
    }
    let _ = next_offset;
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn parse_srv_response(buf: &[u8]) -> io::Result<(String, u16)> {
    if buf.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short dns response",
        ));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(buf, offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid question name"))?;
        offset += 4; // QTYPE + QCLASS
    }
    for _ in 0..ancount {
        offset = skip_dns_name(buf, offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid answer name"))?;
        if offset + 10 > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short answer record",
            ));
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if rtype == 33 && rdlen >= 6 && offset + rdlen <= buf.len() {
            let port = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]);
            let target = read_dns_name(buf, offset + 6).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid SRV target name")
            })?;
            return Ok((target, port));
        }
        offset += rdlen;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no SRV record found in response",
    ))
}

fn parse_txt_response(buf: &[u8]) -> io::Result<Vec<String>> {
    if buf.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short dns response",
        ));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(buf, offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid question name"))?;
        offset += 4; // QTYPE + QCLASS
    }
    let mut results = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(buf, offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid answer name"))?;
        if offset + 10 > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short answer record",
            ));
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if rtype == 16 && offset + rdlen <= buf.len() {
            let rdata = &buf[offset..offset + rdlen];
            let mut roffset = 0;
            while roffset < rdata.len() {
                let slen = rdata[roffset] as usize;
                roffset += 1;
                if roffset + slen <= rdata.len() {
                    if let Ok(s) = std::str::from_utf8(&rdata[roffset..roffset + slen]) {
                        results.push(s.to_string());
                    }
                    roffset += slen;
                } else {
                    break;
                }
            }
        }
        offset += rdlen;
    }
    if results.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no TXT record found in response",
        ))
    } else {
        Ok(results)
    }
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

    #[test]
    fn test_sort_ips_happy_eyeballs() {
        let v4_1: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let v4_2: SocketAddr = "2.2.2.2:80".parse().unwrap();
        let v6_1: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let v6_2: SocketAddr = "[2001:db8::2]:80".parse().unwrap();

        // 1. Prioritize IPv4, interleave 1
        let mut list = vec![v4_1, v4_2, v6_1, v6_2];
        sort_ips_happy_eyeballs(&mut list, false, 1);
        assert_eq!(list, vec![v4_1, v6_1, v4_2, v6_2]);

        // 2. Prioritize IPv6, interleave 1
        let mut list = vec![v4_1, v4_2, v6_1, v6_2];
        sort_ips_happy_eyeballs(&mut list, true, 1);
        assert_eq!(list, vec![v6_1, v4_1, v6_2, v4_2]);

        // 3. Prioritize IPv6, interleave 2
        let mut list = vec![v4_1, v4_2, v6_1, v6_2];
        sort_ips_happy_eyeballs(&mut list, true, 2);
        assert_eq!(list, vec![v6_1, v6_2, v4_1, v4_2]);
    }

    #[test]
    fn test_parse_txt_endpoint() {
        assert_eq!(
            parse_txt_endpoint("192.0.2.1:8443"),
            Some(("192.0.2.1".to_string(), 8443))
        );
        assert_eq!(
            parse_txt_endpoint("[2001:db8::1]:9443"),
            Some(("2001:db8::1".to_string(), 9443))
        );
        assert_eq!(
            parse_txt_endpoint("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(parse_txt_endpoint("invalid"), None);
    }

    #[tokio::test]
    async fn test_tcp_window_clamp_and_custom_sockopt() {
        let json_cfg = serde_json::json!({
            "tcpWindowClamp": 65536,
            "customSockopt": [
                {
                    "level": "0",
                    "opt": "1",
                    "value": "16",
                    "type": "int"
                },
                {
                    "system": "windows",
                    "level": "0",
                    "opt": "1",
                    "value": "16",
                    "type": "int"
                }
            ]
        });
        let sockopt = crate::config::parse_sockopt(&json_cfg, "test")
            .unwrap()
            .expect("should parse");
        assert_eq!(sockopt.tcp_window_clamp, Some(65536));
        assert_eq!(sockopt.custom_sockopt.len(), 2);

        let listener = bind_tcp("127.0.0.1:0".parse().unwrap(), &sockopt)
            .expect("bind_tcp with window clamp and custom sockopt");
        let local_addr = listener.local_addr().unwrap();

        #[cfg(target_os = "linux")]
        {
            let clamp_val = crate::raw_sockopt::getsockopt_int(
                &listener,
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
            )
            .expect("getsockopt TCP_WINDOW_CLAMP");
            assert_eq!(clamp_val, 65536);
        }

        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        let stream = connect(socket, local_addr, Some(&sockopt)).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        drop(stream);
        drop(accepted);
    }
}
