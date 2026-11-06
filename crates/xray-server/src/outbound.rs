//! Dialing the routed outbound: direct (freedom), WireGuard, SOCKS5, VLESS, VMess, Trojan, Shadowsocks, HTTP, DNS, Loopback.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use xray_config::Network;
use xray_wireguard::UdpSession;

use crate::dns_outbound::DnsUdpSession;
use crate::routing::{
    Action, Decision, FreedomFragmentPackets, FreedomFragmentSetting, FreedomNoiseFamily,
    FreedomNoisePacket, FreedomNoiseSetting, FreedomSettings, FreedomStrategy, Query, Router,
};
use crate::shadowsocks_outbound::{ShadowsocksConeUdp, ShadowsocksUdpLink};
use crate::socks::SocksUdp;
use crate::trojan_outbound::{TrojanConeUdp, TrojanUdpLink};
use crate::vless::{resolve, resolve_all, Host, CONNECT_TIMEOUT};
use crate::vless_outbound::{VlessConeUdp, VlessUdpLink};
use crate::vmess_outbound::{VmessConeUdp, VmessUdpLink};
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
                attributes: None,
                local_ip: None,
                vless_route: None,
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

fn rand_between(min: u64, max: u64) -> u64 {
    if min >= max {
        min
    } else {
        rand::thread_rng().gen_range(min..=max)
    }
}

pub struct FragmentWriterStream {
    inner: Box<dyn Stream>,
    setting: FreedomFragmentSetting,
    count: u64,
    pending: VecDeque<Vec<u8>>,
    current_offset: usize,
    sleep_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl FragmentWriterStream {
    pub fn new(inner: Box<dyn Stream>, setting: FreedomFragmentSetting) -> Self {
        Self {
            inner,
            setting,
            count: 0,
            pending: VecDeque::new(),
            current_offset: 0,
            sleep_timer: None,
        }
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(chunk) = self.pending.front() {
            if let Some(ref mut timer) = self.sleep_timer {
                if timer.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep_timer = None;
            }

            match Pin::new(&mut self.inner).poll_write(cx, &chunk[self.current_offset..]) {
                Poll::Ready(Ok(n)) => {
                    self.current_offset += n;
                    if self.current_offset == chunk.len() {
                        self.pending.pop_front();
                        self.current_offset = 0;
                        if !self.pending.is_empty() {
                            let delay_ms =
                                rand_between(self.setting.interval.0, self.setting.interval.1);
                            if delay_ms > 0 {
                                let mut timer = Box::pin(tokio::time::sleep(
                                    std::time::Duration::from_millis(delay_ms),
                                ));
                                if timer.as_mut().poll(cx).is_pending() {
                                    self.sleep_timer = Some(timer);
                                    return Poll::Pending;
                                }
                            }
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for FragmentWriterStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentWriterStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.poll_flush_pending(cx)?.is_pending() {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.count += 1;
        let count = self.count;

        let should_fragment_tls = match self.setting.packets {
            FreedomFragmentPackets::TlsHello => count == 1 && buf.len() > 5 && buf[0] == 22,
            _ => false,
        };

        if should_fragment_tls {
            let record_len = 5 + (((buf[3] as usize) << 8) | (buf[4] as usize));
            if buf.len() >= record_len {
                let data = &buf[5..record_len];
                let max_split = rand_between(self.setting.max_split.0, self.setting.max_split.1);
                let mut split_num = 0;
                let mut from = 0;
                let mut combined_hello = Vec::new();

                while from < data.len() {
                    let chunk_size =
                        rand_between(self.setting.length.0, self.setting.length.1) as usize;
                    split_num += 1;
                    let mut to = from + chunk_size;
                    if to > data.len() || (max_split > 0 && split_num >= max_split) {
                        to = data.len();
                    }
                    let l = to - from;
                    let header = [buf[0], buf[1], buf[2], (l >> 8) as u8, l as u8];
                    let mut chunk = Vec::with_capacity(5 + l);
                    chunk.extend_from_slice(&header);
                    chunk.extend_from_slice(&data[from..to]);
                    from = to;

                    if self.setting.interval.1 == 0 {
                        combined_hello.extend_from_slice(&chunk);
                    } else {
                        self.pending.push_back(chunk);
                    }
                }

                if self.setting.interval.1 == 0 && !combined_hello.is_empty() {
                    self.pending.push_back(combined_hello);
                }

                if buf.len() > record_len {
                    self.pending.push_back(buf[record_len..].to_vec());
                }

                let _ = self.poll_flush_pending(cx);
                return Poll::Ready(Ok(buf.len()));
            }
        }

        let in_range = match self.setting.packets {
            FreedomFragmentPackets::All => true,
            FreedomFragmentPackets::Range(from, to) => count >= from && count <= to,
            FreedomFragmentPackets::TlsHello => false,
        };

        if in_range {
            let max_split = rand_between(self.setting.max_split.0, self.setting.max_split.1);
            let mut split_num = 0;
            let mut from = 0;
            while from < buf.len() {
                let chunk_size =
                    rand_between(self.setting.length.0, self.setting.length.1) as usize;
                split_num += 1;
                let mut to = from + chunk_size;
                if to > buf.len() || (max_split > 0 && split_num >= max_split) {
                    to = buf.len();
                }
                self.pending.push_back(buf[from..to].to_vec());
                from = to;
            }
            let _ = self.poll_flush_pending(cx);
            return Poll::Ready(Ok(buf.len()));
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_flush_pending(cx)?.is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_flush_pending(cx)?.is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn send_udp_noises(
    socket: &UdpSocket,
    noises: &[FreedomNoiseSetting],
    target: SocketAddr,
) -> io::Result<()> {
    if target.port() == 53 || noises.is_empty() {
        return Ok(());
    }
    for n in noises {
        match n.apply_to {
            FreedomNoiseFamily::Ipv4 if !target.is_ipv4() => continue,
            FreedomNoiseFamily::Ipv6 if !target.is_ipv6() => continue,
            _ => {}
        }
        let noise_bytes: Vec<u8> = match &n.packet {
            FreedomNoisePacket::Bytes(b) => b.clone(),
            FreedomNoisePacket::Random(min, max) => {
                let len = rand_between(*min, *max) as usize;
                let mut b = vec![0u8; len];
                rand::thread_rng().fill(&mut b[..]);
                b
            }
        };
        socket.send_to(&noise_bytes, target).await?;
        let delay_ms = rand_between(n.delay_ms.0, n.delay_ms.1);
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
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
    if let Some(ref proxy_tag) = settings.dialer_proxy {
        let decision = router.decision_for_tag(proxy_tag);
        let stream = Box::pin(connect(router, &decision, host, port)).await?;
        if let Some(ref fragment) = settings.fragment {
            return Ok(Box::new(FragmentWriterStream::new(
                stream,
                fragment.clone(),
            )));
        }
        return Ok(stream);
    }

    let bind_ip = settings
        .send_through
        .as_ref()
        .and_then(|st| st.resolve_ip());
    let mut last_error = None;
    let mut addrs = resolve_all(host, port).await?;
    apply_strategy(&mut addrs, settings.strategy)?;
    for addr in addrs {
        if let Err(e) = check_final(router, outbound, Network::Tcp, addr) {
            last_error = Some(e);
            continue;
        }
        let connect_fut = async {
            let socket = if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            if let Some(ip) = bind_ip {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            crate::sockopt::connect(socket, addr, settings.sockopt.as_deref()).await
        };
        match timeout(CONNECT_TIMEOUT, connect_fut).await {
            Ok(Ok(boxed)) => {
                if let Some(ref fragment) = settings.fragment {
                    return Ok(Box::new(FragmentWriterStream::new(boxed, fragment.clone())));
                }
                return Ok(boxed);
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
    Err(last_error.unwrap_or_else(|| io::ErrorKind::NotFound.into()))
}

/// UDP to one destination.
pub enum UdpLink {
    Direct(UdpSocket),
    Wireguard(UdpSession),
    Socks(SocksUdp, SocketAddr),
    Vless(VlessUdpLink),
    Vmess(VmessUdpLink),
    Trojan(TrojanUdpLink),
    Shadowsocks(ShadowsocksUdpLink),
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
                let bind_ip = settings
                    .send_through
                    .as_ref()
                    .and_then(|st| st.resolve_ip());
                let bind: SocketAddr = match bind_ip {
                    Some(ip) => SocketAddr::new(ip, 0),
                    None => {
                        if target.is_ipv4() {
                            ([0, 0, 0, 0], 0).into()
                        } else {
                            ([0u16; 8], 0).into()
                        }
                    }
                };
                let socket = crate::sockopt::bind_udp(bind, settings.sockopt.as_deref())?;
                socket.connect(target).await?;
                send_udp_noises(&socket, &settings.noises, target).await?;
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
            Action::Vmess(vmess) => Ok(Self::Vmess(vmess.open_udp(host, port).await?)),
            Action::Trojan(trojan) => Ok(Self::Trojan(trojan.open_udp(host, port).await?)),
            Action::Shadowsocks(ss) => Ok(Self::Shadowsocks(ss.open_udp(host, port).await?)),
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
                    attributes: None,
                    local_ip: None,
                    vless_route: None,
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
            Self::Vmess(vmess) => vmess.send(data).await,
            Self::Trojan(trojan) => trojan.send(data).await,
            Self::Shadowsocks(ss) => ss.send(data).await,
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
            Self::Vmess(vmess) => vmess.recv(buf).await,
            Self::Trojan(trojan) => trojan.recv(buf).await,
            Self::Shadowsocks(ss) => ss.recv(buf).await,
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
        noised_targets: Arc<Mutex<HashSet<SocketAddr>>>,
    },
    Wireguard {
        wg: Arc<WgOutbound>,
        sessions: Mutex<HashMap<SocketAddr, WgFlow>>,
        tx: mpsc::Sender<(SocketAddr, Bytes)>,
        rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    },
    Socks(SocksUdp),
    Vless(VlessConeUdp),
    Vmess(VmessConeUdp),
    Trojan(TrojanConeUdp),
    Shadowsocks(ShadowsocksConeUdp),
    Dns(Arc<DnsUdpSession>),
}

impl ConeUdp {
    pub async fn open(router: Arc<Router>, decision: &Decision) -> io::Result<Self> {
        match &decision.action {
            Action::Direct(settings) => {
                let bind_ip = settings
                    .send_through
                    .as_ref()
                    .and_then(|st| st.resolve_ip());
                let sockopt = settings.sockopt.as_deref();
                let socket = match bind_ip {
                    Some(ip) => crate::sockopt::bind_udp(SocketAddr::new(ip, 0), sockopt)?,
                    None => crate::sockopt::bind_udp(([0u16; 8], 0).into(), sockopt)
                        .or_else(|_| crate::sockopt::bind_udp(([0, 0, 0, 0], 0).into(), sockopt))?,
                };
                let dual_stack = socket.local_addr()?.is_ipv6();
                Ok(Self::Direct {
                    socket,
                    dual_stack,
                    router,
                    outbound: decision.tag.clone(),
                    settings: settings.clone(),
                    noised_targets: Arc::new(Mutex::new(HashSet::new())),
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
            Action::Vmess(vmess) => Ok(Self::Vmess(vmess.open_cone_udp())),
            Action::Trojan(trojan) => Ok(Self::Trojan(trojan.open_cone_udp())),
            Action::Shadowsocks(ss) => Ok(Self::Shadowsocks(ss.open_cone_udp().await?)),
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
                    attributes: None,
                    local_ip: None,
                    vless_route: None,
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
            Self::Vmess(vmess) => vmess.udp_target(host, port).await,
            Self::Trojan(trojan) => trojan.udp_target(host, port).await,
            Self::Shadowsocks(ss) => ss.udp_target(host, port).await,
            Self::Dns(_) => resolve(host, port).await,
        }
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        match self {
            Self::Direct {
                socket,
                dual_stack,
                settings,
                noised_targets,
                ..
            } => {
                let addr = match addr {
                    SocketAddr::V4(v4) if *dual_stack => {
                        SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
                    }
                    other => other,
                };
                if !settings.noises.is_empty() && addr.port() != 53 {
                    let mut targets = noised_targets.lock().await;
                    if targets.insert(addr) {
                        send_udp_noises(socket, &settings.noises, addr).await?;
                    }
                }
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
            Self::Vmess(vmess) => vmess.send_to(data, addr).await,
            Self::Trojan(trojan) => trojan.send_to(data, addr).await,
            Self::Shadowsocks(ss) => ss.send_to(data, addr).await,
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
            Self::Vmess(vmess) => vmess.recv_from(buf).await,
            Self::Trojan(trojan) => trojan.recv_from(buf).await,
            Self::Shadowsocks(ss) => ss.recv_from(buf).await,
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
            Self::Vmess(vmess) => {
                vmess.abort_all();
            }
            Self::Trojan(trojan) => {
                trojan.abort_all();
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
