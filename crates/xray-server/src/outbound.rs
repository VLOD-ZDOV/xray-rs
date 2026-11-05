//! Dialing the routed outbound: direct (freedom), WireGuard, SOCKS5, VLESS, VMess, Trojan, Shadowsocks, HTTP, DNS, Loopback.

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

use crate::dns_outbound::DnsUdpSession;
use crate::routing::{Action, Decision, FreedomSettings, FreedomStrategy, Query, Router};
use crate::socks::SocksUdp;
use crate::vless::{resolve, resolve_all, Host, CONNECT_TIMEOUT};
use crate::vless_outbound::{VlessConeUdp, VlessUdpLink};
use crate::wg::{to_io, WgOutbound};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub async fn connect(
    router: &Router,
    decision: &Decision,
    host: &Host,
    port: u16,
) -> io::Result<Box<dyn Stream>> {
    match &decision.action {
        Action::Direct(settings) => {
            let (target_host, target_port) = match &settings.redirect {
                Some(r) => r.apply(host, port),
                None => (host.clone(), port),
            };
            connect_direct(router, &decision.tag, settings, &target_host, target_port).await
        }
        Action::Wireguard(wg) => Ok(Box::new(wg.connect(host, port).await?)),
        Action::Socks(socks) => Ok(Box::new(socks.connect(host, port).await?)),
        Action::Vless(vless) => Ok(vless.connect(host, port).await?),
        Action::Vmess(vmess) => Ok(vmess.connect(host, port).await?),
        Action::Trojan(trojan) => Ok(trojan.connect(host, port).await?),
        Action::Shadowsocks(ss) => Ok(ss.connect(host, port).await?),
        Action::Http(http) => Ok(http.connect(host, port).await?),
        Action::Dns(dns) => Ok(dns.connect().await?),
        Action::Loopback(inbound_tag) => {
            let query = Query {
                inbound: inbound_tag,
                inbound_port: 0,
                user: "",
                source: "127.0.0.1:0".parse().unwrap(),
                network: Network::Tcp,
                domain: match host {
                    Host::Domain(d) => Some(d),
                    Host::Ip(_) => None,
                },
                ip: match host {
                    Host::Ip(ip) => Some(*ip),
                    Host::Domain(_) => None,
                },
                port,
                protocol: None,
            };
            let next = router.route(&query).await;
            Box::pin(connect(router, &next, host, port)).await
        }
        Action::Block(_) => Err(blocked(&decision.tag)),
    }
}

pub fn check_final(
    router: &Router,
    outbound: &str,
    network: Network,
    addr: SocketAddr,
) -> io::Result<()> {
    match router.final_action(outbound, network, addr) {
        Action::Block(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{addr} blocked by finalRules of {outbound:?}"),
        )),
        _ => Ok(()),
    }
}

/// Applies freedom's domainStrategy filtering to candidate addresses.
pub fn apply_strategy(addrs: &mut Vec<SocketAddr>, strategy: FreedomStrategy) -> io::Result<()> {
    match strategy {
        FreedomStrategy::AsIs | FreedomStrategy::UseIP => {}
        FreedomStrategy::UseIPv4 => {
            addrs.retain(SocketAddr::is_ipv4);
        }
        FreedomStrategy::UseIPv6 => {
            addrs.retain(SocketAddr::is_ipv6);
        }
    }
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses matched freedom domainStrategy {strategy:?}"),
        ));
    }
    Ok(())
}

/// Tries each resolved address that passes the outbound's finalRules and matches domainStrategy.
async fn connect_direct(
    router: &Router,
    outbound: &str,
    settings: &FreedomSettings,
    host: &Host,
    port: u16,
) -> io::Result<Box<dyn Stream>> {
    let mut last_error = None;
    let mut addrs = resolve_all(host, port).await?;
    apply_strategy(&mut addrs, settings.strategy)?;
    for addr in addrs {
        if let Err(e) = check_final(router, outbound, Network::Tcp, addr) {
            last_error = Some(e);
            continue;
        }
        if let Some(fragment) = &settings.fragment {
            let dialer = xray_transport::TransportDialer::system()
                .map_err(|e| io::Error::other(e.to_string()))?
                .with_tcp_fragment(fragment.clone());
            let target = xray_routing::Target::new(
                match host {
                    Host::Ip(ip) => xray_routing::TargetAddr::Ip(*ip),
                    Host::Domain(d) => xray_routing::TargetAddr::Domain(d.clone()),
                },
                port,
                xray_routing::Network::Tcp,
            );
            match timeout(
                CONNECT_TIMEOUT,
                dialer.connect_stream(
                    &xray_transport::ConnectorConfig::Tcp,
                    &xray_transport::stream::TransportLayer::Raw,
                    &target,
                    &[addr],
                    None,
                ),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(Box::new(stream)),
                Ok(Err(e)) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        e.to_string(),
                    ))
                }
                Err(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connect to {addr} timed out"),
                    ))
                }
            }
        } else {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true)?;
                    return Ok(Box::new(stream));
                }
                Ok(Err(e)) => last_error = Some(e),
                Err(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connect to {addr} timed out"),
                    ))
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::ErrorKind::NotFound.into()))
}

/// UDP to one destination.
pub enum UdpLink {
    Direct(UdpSocket),
    Wireguard(UdpSession),
    Socks(SocksUdp, SocketAddr),
    Vless(VlessUdpLink),
    Dns(Arc<DnsUdpSession>),
}

impl UdpLink {
    pub async fn open(
        router: &Router,
        decision: &Decision,
        host: &Host,
        port: u16,
    ) -> io::Result<Self> {
        match &decision.action {
            Action::Direct(settings) => {
                let (target_host, target_port) = match &settings.redirect {
                    Some(r) => r.apply(host, port),
                    None => (host.clone(), port),
                };
                let mut addrs = resolve_all(&target_host, target_port).await?;
                apply_strategy(&mut addrs, settings.strategy)?;
                let target = addrs[0];
                check_final(router, &decision.tag, Network::Udp, target)?;
                let bind: SocketAddr = if target.is_ipv4() {
                    ([0, 0, 0, 0], 0).into()
                } else {
                    ([0u16; 8], 0).into()
                };
                let socket = UdpSocket::bind(bind).await?;
                socket.connect(target).await?;
                Ok(Self::Direct(socket))
            }
            Action::Wireguard(wg) => Ok(Self::Wireguard(
                wg.open_udp(wg.udp_target(host, port).await?).await?,
            )),
            Action::Socks(socks) => Ok(Self::Socks(
                socks.associate().await?,
                resolve(host, port).await?,
            )),
            Action::Vless(vless) => Ok(Self::Vless(vless.open_udp(host, port).await?)),
            Action::Dns(dns) => Ok(Self::Dns(Arc::new(DnsUdpSession::new(dns.clone())))),
            Action::Loopback(inbound_tag) => {
                let query = Query {
                    inbound: inbound_tag,
                    inbound_port: 0,
                    user: "",
                    source: "127.0.0.1:0".parse().unwrap(),
                    network: Network::Udp,
                    domain: match host {
                        Host::Domain(d) => Some(d),
                        Host::Ip(_) => None,
                    },
                    ip: match host {
                        Host::Ip(ip) => Some(*ip),
                        Host::Domain(_) => None,
                    },
                    port,
                    protocol: None,
                };
                let next = router.route(&query).await;
                Box::pin(Self::open(router, &next, host, port)).await
            }
            _ => Err(blocked(&decision.tag)),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send(data).await.map(|_| ()),
            Self::Wireguard(session) => session.send(data).await.map_err(to_io),
            Self::Socks(udp, target) => udp.send_to(data, *target).await,
            Self::Vless(vless) => vless.send(data).await,
            Self::Dns(session) => session.send(data).await,
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
            Self::Vless(vless) => vless.recv(buf).await,
            Self::Dns(session) => session.recv(buf).await,
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
        settings: FreedomSettings,
    },
    Wireguard {
        wg: Arc<WgOutbound>,
        sessions: Mutex<HashMap<SocketAddr, WgFlow>>,
        tx: mpsc::Sender<(SocketAddr, Bytes)>,
        rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    },
    Socks(SocksUdp),
    Vless(VlessConeUdp),
    Dns(Arc<DnsUdpSession>),
}

impl ConeUdp {
    pub async fn open(router: Arc<Router>, decision: &Decision) -> io::Result<Self> {
        match &decision.action {
            Action::Direct(settings) => {
                let socket = match UdpSocket::bind(("::", 0)).await {
                    Ok(socket) => socket,
                    Err(_) => UdpSocket::bind(("0.0.0.0", 0)).await?,
                };
                let dual_stack = socket.local_addr()?.is_ipv6();
                Ok(Self::Direct {
                    socket,
                    dual_stack,
                    router,
                    outbound: decision.tag.clone(),
                    settings: settings.clone(),
                })
            }
            Action::Wireguard(wg) => {
                let (tx, rx) = mpsc::channel(256);
                Ok(Self::Wireguard {
                    wg: wg.clone(),
                    sessions: Mutex::new(HashMap::new()),
                    tx,
                    rx: Mutex::new(rx),
                })
            }
            Action::Socks(socks) => Ok(Self::Socks(socks.associate().await?)),
            Action::Vless(vless) => Ok(Self::Vless(vless.open_cone_udp())),
            Action::Dns(dns) => Ok(Self::Dns(Arc::new(DnsUdpSession::new(dns.clone())))),
            Action::Loopback(inbound_tag) => {
                let query = Query {
                    inbound: inbound_tag,
                    inbound_port: 0,
                    user: "",
                    source: "127.0.0.1:0".parse().unwrap(),
                    network: Network::Udp,
                    domain: None,
                    ip: None,
                    port: 0,
                    protocol: None,
                };
                let next = router.route(&query).await;
                Box::pin(Self::open(router, &next)).await
            }
            _ => Err(blocked(&decision.tag)),
        }
    }

    /// Resolves a destination for this outbound (domains via the system resolver).
    pub async fn target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        match self {
            Self::Direct {
                router,
                outbound,
                settings,
                ..
            } => {
                let (target_host, target_port) = match &settings.redirect {
                    Some(r) => r.apply(host, port),
                    None => (host.clone(), port),
                };
                let mut addrs = resolve_all(&target_host, target_port).await?;
                apply_strategy(&mut addrs, settings.strategy)?;
                let addr = addrs[0];
                check_final(router, outbound, Network::Udp, addr)?;
                Ok(addr)
            }
            Self::Wireguard { wg, .. } => wg.udp_target(host, port).await,
            Self::Socks(_) => resolve(host, port).await,
            Self::Vless(vless) => vless.udp_target(host, port).await,
            Self::Dns(_) => resolve(host, port).await,
        }
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        match self {
            Self::Direct {
                socket, dual_stack, ..
            } => {
                let addr = match addr {
                    SocketAddr::V4(v4) if *dual_stack => {
                        SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
                    }
                    other => other,
                };
                socket.send_to(data, addr).await.map(|_| ())
            }
            Self::Wireguard {
                wg, sessions, tx, ..
            } => {
                let mut sessions = sessions.lock().await;
                if sessions
                    .get(&addr)
                    .is_none_or(|(_, task)| task.is_finished())
                {
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
            Self::Vless(vless) => vless.send_to(data, addr).await,
            Self::Dns(session) => session.send(data).await,
        }
    }

    /// Next reply; `buf` receives the payload for the direct socket.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Direct { socket, .. } => {
                let (n, from) = socket.recv_from(buf).await?;
                let from = match from {
                    SocketAddr::V6(v6) => v6
                        .ip()
                        .to_ipv4_mapped()
                        .map_or(from, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
                    other => other,
                };
                Ok((n, from))
            }
            Self::Wireguard { rx, .. } => {
                let (from, packet) = rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok((n, from))
            }
            Self::Socks(udp) => udp.recv_from(buf).await,
            Self::Vless(vless) => vless.recv_from(buf).await,
            Self::Dns(session) => {
                let n = session.recv(buf).await?;
                Ok((n, "127.0.0.1:53".parse().unwrap()))
            }
        }
    }
}

impl Drop for ConeUdp {
    fn drop(&mut self) {
        match self {
            Self::Wireguard { sessions, .. } => {
                for (_, task) in sessions.get_mut().values() {
                    task.abort();
                }
            }
            Self::Vless(vless) => {
                vless.abort_all();
            }
            _ => {}
        }
    }
}

fn blocked(tag: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("blocked by outbound {tag:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freedom_domain_strategy_filtering() {
        let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:80".parse().unwrap();

        let mut addrs = vec![v4, v6];
        apply_strategy(&mut addrs, FreedomStrategy::AsIs).unwrap();
        assert_eq!(addrs, vec![v4, v6]);

        let mut addrs = vec![v4, v6];
        apply_strategy(&mut addrs, FreedomStrategy::UseIPv4).unwrap();
        assert_eq!(addrs, vec![v4]);

        let mut addrs = vec![v4, v6];
        apply_strategy(&mut addrs, FreedomStrategy::UseIPv6).unwrap();
        assert_eq!(addrs, vec![v6]);

        let mut addrs = vec![v4];
        assert!(apply_strategy(&mut addrs, FreedomStrategy::UseIPv6).is_err());
    }

    #[test]
    fn freedom_redirect_applying() {
        let redirect = crate::routing::RedirectSetting {
            host: Some(Host::Ip("127.0.0.1".parse().unwrap())),
            port: 8080,
        };
        let (h, p) = redirect.apply(&Host::Domain("example.com".to_string()), 443);
        assert_eq!(h, Host::Ip("127.0.0.1".parse().unwrap()));
        assert_eq!(p, 8080);

        let partial = crate::routing::RedirectSetting {
            host: None,
            port: 9090,
        };
        let (h2, p2) = partial.apply(&Host::Domain("example.com".to_string()), 80);
        assert_eq!(h2, Host::Domain("example.com".to_string()));
        assert_eq!(p2, 9090);
    }

    #[tokio::test]
    async fn dns_outbound_local_resolution() {
        let dns = crate::dns_outbound::DnsOutbound {
            tag: "dns".into(),
            address: None,
            port: 53,
            network: Network::Udp,
        };

        // Standard DNS query for localhost A record: ID=0x1234, Flags=0x0100, QD=1, AN=0, NS=0, AR=0
        // QNAME = 9localhost0, QTYPE = 1 (A), QCLASS = 1 (IN)
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'l',
            b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let resp = dns.resolve_query(&query).await.unwrap();
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        // QR flag set
        assert_eq!(resp[2] & 0x80, 0x80);
    }

    #[tokio::test]
    async fn prefixed_stream_behavior() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(64);
        let prefix = b"HELLO_".to_vec();
        let mut prefixed = crate::outbound_transport::PrefixedStream::new(server, prefix);

        tokio::spawn(async move {
            let _ = client.write_all(b"WORLD").await;
        });

        let mut buf = vec![0u8; 11];
        prefixed.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO_WORLD");
    }
}
