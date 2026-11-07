use crate::client::{Stop, IP_PACKET_QUEUE, STREAM_BUFFER};
use crate::io as transport;
use crate::stack::{tcp_socket, Packets};
use bytes::BytesMut;
use gotatun::packet::{Ip, Packet};
use smoltcp::{
    iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle,
        SocketSet,
    },
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpCidr, IpEndpoint, Ipv4Packet, Ipv6Packet, UdpPacket},
};
use std::{
    collections::HashMap,
    future::poll_fn,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
    time::{Duration, Instant as Clock},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{mpsc, watch, Mutex, Notify},
};
use xray_proxy::wireguard::{AllowedIp, KeyMaterial};

#[derive(Clone, Debug)]
pub struct ServerPeerConfig {
    pub public_key: KeyMaterial,
    pub preshared_key: Option<KeyMaterial>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<AllowedIp>,
    pub keepalive: u16,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub secret_key: KeyMaterial,
    pub peers: Vec<ServerPeerConfig>,
    pub addresses: Vec<IpAddr>,
    pub listen_addr: SocketAddr,
    pub mtu: u16,
    pub reserved: [u8; 3],
}

pub struct IncomingTcpStream {
    pub stream: DuplexStream,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub struct IncomingUdpSession {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub first_packet: Vec<u8>,
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub response_tx: mpsc::Sender<(SocketAddr, SocketAddr, Vec<u8>)>,
}

pub struct Server {
    stop: Stop,
    tcp_rx: Arc<Mutex<mpsc::Receiver<IncomingTcpStream>>>,
    udp_rx: Arc<Mutex<mpsc::Receiver<IncomingUdpSession>>>,
}

impl Server {
    pub async fn start(config: ServerConfig) -> Result<Self, io::Error> {
        let stop = Stop::new();
        let wake = Arc::new(Notify::new());
        let (ip_tx, from_engine) = mpsc::channel(IP_PACKET_QUEUE);
        let (to_engine, ip_rx) = mpsc::channel(IP_PACKET_QUEUE);

        let carrier = transport::Factory {
            ipv4: config.listen_addr.is_ipv4(),
            ipv6: config.listen_addr.is_ipv6(),
            protector: None,
            protection_failed: Arc::new(AtomicBool::new(false)),
            stop: stop.clone(),
            carrier: watch::channel(None).0,
            reserved: config.reserved,
            listen_addr: Some(config.listen_addr),
        };

        let peers = config.peers.iter().map(|p| {
            let mut peer = gotatun::device::Peer::new(x25519_dalek::PublicKey::from(
                *p.public_key.expose_bytes(),
            ));
            if let Some(ep) = p.endpoint {
                peer.endpoint = Some(ep);
            }
            peer.allowed_ips = p
                .allowed_ips
                .iter()
                .map(|ip| {
                    format!("{}/{}", ip.network(), ip.prefix_length())
                        .parse()
                        .expect("validated prefix")
                })
                .collect();
            peer.preshared_key = p
                .preshared_key
                .as_ref()
                .map(|k| gotatun::PresharedKey::new(k.expose_bytes()));
            peer.keepalive = (p.keepalive != 0).then_some(p.keepalive);
            peer
        });

        let mut limits = gotatun::device::DeviceLimits::mobile();
        limits.packet_reservations = 256;
        limits.io_queue_packets = 16;
        limits.pending_packets_per_peer = limits.pending_packets / config.peers.len().max(1);

        let mut device = gotatun::device::DeviceBuilder::new()
            .with_limits(limits)
            .with_private_key(x25519_dalek::StaticSecret::from(
                *config.secret_key.expose_bytes(),
            ))
            .with_peers(peers)
            .with_udp(carrier.clone())
            .with_ip_pair(
                transport::IpTx {
                    tx: ip_tx,
                    stop: stop.clone(),
                },
                transport::IpRx {
                    batch: Vec::with_capacity(IP_PACKET_QUEUE),
                    rx: ip_rx,
                    mtu: config.mtu,
                    stop: stop.clone(),
                    wake: wake.clone(),
                },
            )
            .build()
            .await
            .map_err(|e| io::Error::other(format!("WireGuard device build failed: {e:?}")))?;

        let (tcp_tx, tcp_rx) = mpsc::channel(64);
        let (udp_tx, udp_rx) = mpsc::channel(64);
        let (udp_resp_tx, udp_resp_rx) = mpsc::channel(128);

        let stack = ServerStack::new(
            &config,
            to_engine,
            from_engine,
            tcp_tx,
            udp_tx,
            udp_resp_tx,
            udp_resp_rx,
            stop.clone(),
            wake.clone(),
        );

        let dev_stop = stop.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = dev_stop.cancelled() => {}
                _ = device.wait() => {}
            }
            let _ = device.stop().await;
        });

        let stack_stop = stop.clone();
        tokio::spawn(async move {
            stack.run(stack_stop).await;
        });

        Ok(Self {
            stop,
            tcp_rx: Arc::new(Mutex::new(tcp_rx)),
            udp_rx: Arc::new(Mutex::new(udp_rx)),
        })
    }

    pub async fn accept_tcp(&self) -> Option<IncomingTcpStream> {
        self.tcp_rx.lock().await.recv().await
    }

    pub async fn accept_udp(&self) -> Option<IncomingUdpSession> {
        self.udp_rx.lock().await.recv().await
    }

    pub fn start_raw(
        addresses: Vec<IpAddr>,
        mtu: u16,
        to_tunnel: mpsc::Sender<Packet<Ip>>,
        from_tunnel: mpsc::Receiver<Packet<Ip>>,
    ) -> Self {
        let stop = Stop::new();
        let wake = Arc::new(Notify::new());
        let (tcp_tx, tcp_rx) = mpsc::channel(64);
        let (udp_tx, udp_rx) = mpsc::channel(64);
        let (udp_resp_tx, udp_resp_rx) = mpsc::channel(128);

        let config = ServerConfig {
            secret_key: KeyMaterial::parse("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=").unwrap(),
            peers: vec![],
            addresses,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            mtu,
            reserved: [0; 3],
        };

        let stack = ServerStack::new(
            &config,
            to_tunnel,
            from_tunnel,
            tcp_tx,
            udp_tx,
            udp_resp_tx,
            udp_resp_rx,
            stop.clone(),
            wake.clone(),
        );

        let stack_stop = stop.clone();
        tokio::spawn(async move {
            stack.run(stack_stop).await;
        });

        Self {
            stop,
            tcp_rx: Arc::new(Mutex::new(tcp_rx)),
            udp_rx: Arc::new(Mutex::new(udp_rx)),
        }
    }

    pub fn close(&self) {
        self.stop.close();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.close();
    }
}

enum PacketType {
    Tcp {
        src: SocketAddr,
        dst: SocketAddr,
        syn: bool,
        ack: bool,
    },
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
}

fn inspect_packet(buf: &[u8]) -> Option<PacketType> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    if version == 4 && buf.len() >= 20 {
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        if buf.len() < ihl {
            return None;
        }
        let proto = buf[9];
        let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
        if proto == 6 && buf.len() >= ihl + 20 {
            let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
            let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
            let flags = buf[ihl + 13];
            return Some(PacketType::Tcp {
                src: SocketAddr::new(src_ip, src_port),
                dst: SocketAddr::new(dst_ip, dst_port),
                syn: flags & 0x02 != 0,
                ack: flags & 0x10 != 0,
            });
        } else if proto == 17 && buf.len() >= ihl + 8 {
            let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
            let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
            let len = u16::from_be_bytes([buf[ihl + 4], buf[ihl + 5]]) as usize;
            let end = (ihl + len).min(buf.len());
            let payload = buf[ihl + 8..end].to_vec();
            return Some(PacketType::Udp {
                src: SocketAddr::new(src_ip, src_port),
                dst: SocketAddr::new(dst_ip, dst_port),
                payload,
            });
        }
    } else if version == 6 && buf.len() >= 40 {
        let next_hdr = buf[6];
        let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&buf[8..24]).unwrap(),
        ));
        let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&buf[24..40]).unwrap(),
        ));
        let ihl = 40;
        if next_hdr == 6 && buf.len() >= ihl + 20 {
            let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
            let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
            let flags = buf[ihl + 13];
            return Some(PacketType::Tcp {
                src: SocketAddr::new(src_ip, src_port),
                dst: SocketAddr::new(dst_ip, dst_port),
                syn: flags & 0x02 != 0,
                ack: flags & 0x10 != 0,
            });
        } else if next_hdr == 17 && buf.len() >= ihl + 8 {
            let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
            let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
            let len = u16::from_be_bytes([buf[ihl + 4], buf[ihl + 5]]) as usize;
            let end = (ihl + len).min(buf.len());
            let payload = buf[ihl + 8..end].to_vec();
            return Some(PacketType::Udp {
                src: SocketAddr::new(src_ip, src_port),
                dst: SocketAddr::new(dst_ip, dst_port),
                payload,
            });
        }
    }
    None
}

struct ServerTcpFlow {
    handle: SocketHandle,
    bridge: DuplexStream,
    src: SocketAddr,
    dst: SocketAddr,
    write_eof: bool,
    read_eof: bool,
}

struct ServerStack {
    interface: Interface,
    device: Packets,
    sockets: SocketSet<'static>,
    flows: HashMap<u64, ServerTcpFlow>,
    udp_sessions: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>,
    incoming: mpsc::Receiver<Packet<Ip>>,
    tcp_tx: mpsc::Sender<IncomingTcpStream>,
    udp_tx: mpsc::Sender<IncomingUdpSession>,
    udp_resp_tx: mpsc::Sender<(SocketAddr, SocketAddr, Vec<u8>)>,
    udp_resp_rx: mpsc::Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    stop: Stop,
    wake: Arc<Notify>,
    start: Clock,
    next_id: u64,
}

impl ServerStack {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &ServerConfig,
        tx: mpsc::Sender<Packet<Ip>>,
        incoming: mpsc::Receiver<Packet<Ip>>,
        tcp_tx: mpsc::Sender<IncomingTcpStream>,
        udp_tx: mpsc::Sender<IncomingUdpSession>,
        udp_resp_tx: mpsc::Sender<(SocketAddr, SocketAddr, Vec<u8>)>,
        udp_resp_rx: mpsc::Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
        stop: Stop,
        wake: Arc<Notify>,
    ) -> Self {
        let mut device = Packets {
            tx,
            rx: None,
            mtu: usize::from(config.mtu),
        };
        let mut options = InterfaceConfig::new(HardwareAddress::Ip);
        options.random_seed = rand::random();
        let mut interface = Interface::new(options, &mut device, Instant::ZERO);
        interface.set_round_robin_egress(true);
        interface.set_tcp_egress_burst(32);
        interface.set_any_ip(true);
        interface.update_ip_addrs(|ips| {
            for address in &config.addresses {
                ips.push(IpCidr::new(
                    (*address).into(),
                    if address.is_ipv4() { 32 } else { 128 },
                ))
                .expect("configured address fits");
            }
        });
        for address in &config.addresses {
            match address {
                IpAddr::V4(ip) => {
                    let _ = interface.routes_mut().add_default_ipv4_route(*ip);
                }
                IpAddr::V6(ip) => {
                    let _ = interface.routes_mut().add_default_ipv6_route(*ip);
                }
            }
        }
        Self {
            interface,
            device,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            udp_sessions: HashMap::new(),
            incoming,
            tcp_tx,
            udp_tx,
            udp_resp_tx,
            udp_resp_rx,
            stop,
            wake,
            start: Clock::now(),
            next_id: 1,
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    async fn run(mut self, stop: Stop) {
        loop {
            let delay = self
                .interface
                .poll_delay(self.now(), &self.sockets)
                .map(|d| Duration::from_millis(d.total_millis().max(1)))
                .unwrap_or(Duration::from_millis(50))
                .min(Duration::from_millis(50));
            let wake = self.wake.clone();
            tokio::select! { biased;
                _ = stop.cancelled() => return,
                result = poll_fn(|cx| self.drive(cx)) => if !result { return; },
                _ = wake.notified() => {},
                _ = tokio::time::sleep(delay) => {},
            }
            tokio::task::yield_now().await;
        }
    }

    fn drive(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.device.tx.is_closed() || self.stop.is_closed() {
            return Poll::Ready(false);
        }
        let mut progress = false;

        // 1. Drain UDP responses
        while let Poll::Ready(Some((from, to, payload))) = self.udp_resp_rx.poll_recv(cx) {
            self.send_udp_packet(from, to, &payload);
            progress = true;
        }

        // 2. Process incoming packets from gotatun
        for _ in 0..IP_PACKET_QUEUE {
            if self.device.rx.is_none() {
                match self.incoming.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => {
                        let bytes_pkt = packet.into_bytes();
                        let parsed = inspect_packet(&bytes_pkt);
                        match parsed {
                            Some(PacketType::Udp { src, dst, payload }) => {
                                let mut clean = false;
                                if let Some(tx) = self.udp_sessions.get(&(src, dst)) {
                                    if tx.try_send(payload.clone()).is_err() {
                                        clean = true;
                                    }
                                } else {
                                    clean = true;
                                }
                                if clean {
                                    let (tx, rx) = mpsc::channel(128);
                                    self.udp_sessions.insert((src, dst), tx);
                                    let _ = self.udp_tx.try_send(IncomingUdpSession {
                                        src,
                                        dst,
                                        first_packet: payload,
                                        rx,
                                        response_tx: self.udp_resp_tx.clone(),
                                    });
                                }
                                progress = true;
                                continue;
                            }
                            Some(PacketType::Tcp {
                                src,
                                dst,
                                syn: true,
                                ack: false,
                            }) => {
                                if !self.flows.values().any(|f| f.src == src && f.dst == dst) {
                                    let (bridge_app, bridge_stack) =
                                        tokio::io::duplex(STREAM_BUFFER);
                                    let mut socket = tcp_socket();
                                    let _ = socket.set_receive_window_limit(1024 * 1024);
                                    if socket
                                        .listen(IpEndpoint::new(dst.ip().into(), dst.port()))
                                        .is_ok()
                                    {
                                        let handle = self.sockets.add(socket);
                                        let id = self.next_id;
                                        self.next_id += 1;
                                        self.flows.insert(
                                            id,
                                            ServerTcpFlow {
                                                handle,
                                                bridge: bridge_stack,
                                                src,
                                                dst,
                                                write_eof: false,
                                                read_eof: false,
                                            },
                                        );
                                        let _ = self.tcp_tx.try_send(IncomingTcpStream {
                                            stream: bridge_app,
                                            src,
                                            dst,
                                        });
                                    }
                                }
                                if let Ok(pkt) = bytes_pkt.try_into_ip() {
                                    self.device.rx = Some(pkt);
                                }
                                progress = true;
                            }
                            _ => {
                                if let Ok(pkt) = bytes_pkt.try_into_ip() {
                                    self.device.rx = Some(pkt);
                                }
                                progress = true;
                            }
                        }
                    }
                    Poll::Ready(None) => return Poll::Ready(false),
                    Poll::Pending => break,
                }
            }

            let now = self.now();
            progress |=
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets)
                    != PollIngressSingleResult::None;
            if self.device.rx.is_some() || self.incoming.is_empty() {
                break;
            }
        }

        // 3. Drive TCP flows
        let mut removed = Vec::new();
        for (&id, flow) in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            if socket.state() == tcp::State::Closed {
                removed.push(id);
                continue;
            }
            if socket.state() != tcp::State::Established && socket.state() != tcp::State::CloseWait
            {
                continue;
            }

            if !flow.write_eof && socket.can_send() {
                let read = socket.send(|bytes| {
                    let mut buf = ReadBuf::new(bytes);
                    let result = Pin::new(&mut flow.bridge).poll_read(cx, &mut buf);
                    let n = buf.filled().len();
                    (n, result.map_ok(|()| n))
                });
                match read {
                    Ok(Poll::Ready(Ok(0))) => {
                        flow.write_eof = true;
                        socket.close();
                        progress = true;
                    }
                    Ok(Poll::Ready(Ok(_))) => {
                        progress = true;
                    }
                    Ok(Poll::Ready(Err(_))) | Err(_) => {
                        socket.abort();
                        removed.push(id);
                        continue;
                    }
                    Ok(Poll::Pending) => {}
                }
            }

            let mut failed = false;
            if socket.can_recv() && socket.recv_queue() != 0 {
                let _ = socket.recv(|bytes| {
                    if bytes.is_empty() {
                        return (0, ());
                    }
                    match Pin::new(&mut flow.bridge).poll_write(cx, bytes) {
                        Poll::Ready(Ok(n)) if n != 0 => {
                            progress = true;
                            (n, ())
                        }
                        Poll::Ready(_) => {
                            failed = true;
                            (0, ())
                        }
                        Poll::Pending => (0, ()),
                    }
                });
            }
            if failed {
                socket.abort();
                removed.push(id);
                continue;
            }

            if !flow.read_eof
                && !socket.may_recv()
                && Pin::new(&mut flow.bridge).poll_shutdown(cx).is_ready()
            {
                flow.read_eof = true;
                progress = true;
            }
        }

        let now = self.now();
        let poll_res = self
            .interface
            .poll(now, &mut self.device, &mut self.sockets);
        if poll_res != PollResult::None {
            progress = true;
        }

        for id in removed {
            if let Some(flow) = self.flows.remove(&id) {
                self.sockets.remove(flow.handle);
                progress = true;
            }
        }

        if progress {
            Poll::Ready(true)
        } else {
            Poll::Pending
        }
    }

    fn send_udp_packet(&mut self, from: SocketAddr, to: SocketAddr, payload: &[u8]) {
        let mut buf = vec![0u8; 40 + 8 + payload.len()];
        match (from.ip(), to.ip()) {
            (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
                let total_len = 20 + 8 + payload.len();
                if total_len > 65535 {
                    return;
                }
                let mut ip_packet = Ipv4Packet::new_unchecked(&mut buf[..total_len]);
                ip_packet.set_version(4);
                ip_packet.set_header_len(20);
                ip_packet.set_total_len(total_len as u16);
                ip_packet.set_next_header(smoltcp::wire::IpProtocol::Udp);
                ip_packet.set_hop_limit(64);
                ip_packet.set_src_addr(src_v4);
                ip_packet.set_dst_addr(dst_v4);
                ip_packet.fill_checksum();

                let mut udp_packet = UdpPacket::new_unchecked(&mut buf[20..total_len]);
                udp_packet.set_src_port(from.port());
                udp_packet.set_dst_port(to.port());
                udp_packet.set_len((8 + payload.len()) as u16);
                udp_packet.payload_mut().copy_from_slice(payload);
                udp_packet.fill_checksum(&src_v4.into(), &dst_v4.into());

                let bytes = BytesMut::from(&buf[..total_len]);
                if let Ok(packet) = Packet::from_bytes(bytes).try_into_ip() {
                    let _ = self.device.tx.try_send(packet);
                }
            }
            (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
                let total_len = 40 + 8 + payload.len();
                if total_len > 65535 {
                    return;
                }
                let mut ip_packet = Ipv6Packet::new_unchecked(&mut buf[..total_len]);
                ip_packet.set_version(6);
                ip_packet.set_payload_len((8 + payload.len()) as u16);
                ip_packet.set_next_header(smoltcp::wire::IpProtocol::Udp);
                ip_packet.set_hop_limit(64);
                ip_packet.set_src_addr(src_v6);
                ip_packet.set_dst_addr(dst_v6);

                let mut udp_packet = UdpPacket::new_unchecked(&mut buf[40..total_len]);
                udp_packet.set_src_port(from.port());
                udp_packet.set_dst_port(to.port());
                udp_packet.set_len((8 + payload.len()) as u16);
                udp_packet.payload_mut().copy_from_slice(payload);
                udp_packet.fill_checksum(&src_v6.into(), &dst_v6.into());

                let bytes = BytesMut::from(&buf[..total_len]);
                if let Ok(packet) = Packet::from_bytes(bytes).try_into_ip() {
                    let _ = self.device.tx.try_send(packet);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};

    #[tokio::test]
    async fn test_server_tcp_syn_ack() {
        let (tx, mut rx) = mpsc::channel(16);
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let (tcp_tx, mut tcp_rx) = mpsc::channel(16);
        let (udp_tx, _udp_rx) = mpsc::channel(16);
        let (udp_resp_tx, udp_resp_rx) = mpsc::channel(16);
        let stop = Stop::new();
        let wake = Arc::new(Notify::new());

        let cfg = ServerConfig {
            secret_key: KeyMaterial::parse("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=").unwrap(),
            peers: vec![],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            listen_addr: "127.0.0.1:51820".parse().unwrap(),
            mtu: 1420,
            reserved: [0; 3],
        };

        let mut stack = ServerStack::new(
            &cfg,
            tx,
            incoming_rx,
            tcp_tx,
            udp_tx,
            udp_resp_tx,
            udp_resp_rx,
            stop,
            wake,
        );

        let mut buf = vec![0u8; 40];
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..40]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_hop_limit(64);
        ip.set_src_addr("10.0.0.2".parse().unwrap());
        ip.set_dst_addr("127.0.0.1".parse().unwrap());
        ip.fill_checksum();

        let mut tcp = TcpPacket::new_unchecked(&mut buf[20..40]);
        tcp.set_src_port(12345);
        tcp.set_dst_port(80);
        tcp.set_seq_number(TcpSeqNumber(100));
        tcp.set_ack_number(TcpSeqNumber(0));
        tcp.set_header_len(20);
        tcp.set_syn(true);
        tcp.set_window_len(65535);
        tcp.fill_checksum(&"10.0.0.2".parse().unwrap(), &"127.0.0.1".parse().unwrap());

        let pkt = Packet::from_bytes(BytesMut::from(&buf[..]))
            .try_into_ip()
            .unwrap();
        incoming_tx.send(pkt).await.unwrap();

        let progressed = poll_fn(|cx| stack.drive(cx)).await;
        assert!(progressed);

        let inc = tcp_rx.try_recv();
        assert!(inc.is_ok());

        let out = rx.try_recv();
        assert!(out.is_ok());
        let out_pkt = out.unwrap();
        let out_bytes = out_pkt.into_bytes();
        let out_ip = Ipv4Packet::new_checked(&out_bytes[..]).unwrap();
        let out_tcp = TcpPacket::new_checked(out_ip.payload()).unwrap();
        assert!(out_tcp.syn());
        assert!(out_tcp.ack());
        assert_eq!(out_tcp.src_port(), 80);
        assert_eq!(out_tcp.dst_port(), 12345);
        assert!(out_ip.verify_checksum());
        assert!(out_tcp.verify_checksum(&out_ip.src_addr().into(), &out_ip.dst_addr().into()));
    }
}
