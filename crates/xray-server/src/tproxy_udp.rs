//! Linux TPROXY for UDP: a transparent socket that reports each datagram's
//! original destination, and reply sockets that send back from that address
//! (Xray's dokodemo FakeUDP).

use std::io;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

#[cfg(target_os = "linux")]
use crate::raw_sockopt::setsockopt_int;

/// Binds the inbound socket; an empty listen is dual-stack like Go's.
#[cfg(target_os = "linux")]
pub fn bind(listen: &str, port: u16, mark: u32) -> io::Result<UdpSocket> {
    let addr = if listen.is_empty() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))
    } else {
        let ip: IpAddr = listen
            .trim_matches(['[', ']'])
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid listen address"))?;
        SocketAddr::new(ip, port)
    };
    let socket = transparent_socket(addr, mark)?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
        setsockopt_int(&socket, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR, 1)?;
    }
    // A dual-stack socket gets IPv4 datagrams with the IPv4 control message.
    let v4 = setsockopt_int(&socket, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1);
    if addr.is_ipv4() {
        v4?;
    }
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// A socket bound to `from`, a foreign address, to answer `to`.
#[cfg(target_os = "linux")]
pub fn reply_socket(from: SocketAddr, mark: u32) -> io::Result<UdpSocket> {
    let socket = transparent_socket(from, mark)?;
    socket.set_reuse_port(true)?;
    socket.bind(&from.into())?;
    UdpSocket::from_std(socket.into())
}

#[cfg(target_os = "linux")]
fn transparent_socket(addr: SocketAddr, mark: u32) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_ip_transparent_v6(true)?;
    } else {
        socket.set_ip_transparent_v4(true)?;
    }
    if mark != 0 {
        socket.set_mark(mark)?;
    }
    Ok(socket)
}

/// Receives one datagram: its length, sender and original destination.
#[cfg(target_os = "linux")]
pub async fn recv(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let mut cmsg = nix::cmsg_space!(libc::sockaddr_in6);
    socket
        .async_io(tokio::io::Interest::READABLE, || {
            let mut iov = [io::IoSliceMut::new(buf)];
            let msg = recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
                .map_err(io::Error::from)?;
            let peer = msg
                .address
                .as_ref()
                .and_then(storage_addr)
                .ok_or_else(|| io::Error::other("datagram without a source address"))?;
            let mut original = None;
            for c in msg.cmsgs().map_err(io::Error::from)? {
                match c {
                    ControlMessageOwned::Ipv4OrigDstAddr(a) => {
                        original = Some(SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                            u16::from_be(a.sin_port),
                        )));
                    }
                    ControlMessageOwned::Ipv6OrigDstAddr(a) => {
                        original = Some(SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(a.sin6_addr.s6_addr),
                            u16::from_be(a.sin6_port),
                            0,
                            0,
                        )));
                    }
                    _ => {}
                }
            }
            Ok((msg.bytes, canonical(peer), original.map(canonical)))
        })
        .await
}

#[cfg(target_os = "linux")]
fn storage_addr(storage: &nix::sys::socket::SockaddrStorage) -> Option<SocketAddr> {
    if let Some(a) = storage.as_sockaddr_in() {
        return Some(SocketAddr::V4((*a).into()));
    }
    storage
        .as_sockaddr_in6()
        .map(|a| SocketAddr::V6((*a).into()))
}

pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

#[cfg(not(target_os = "linux"))]
pub fn bind(_: &str, _: u16, _: u32) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "UDP tproxy needs Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn reply_socket(_: SocketAddr, _: u32) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "UDP tproxy needs Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn recv(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    let (n, peer) = socket.recv_from(buf).await?;
    Ok((n, canonical(peer), None))
}
