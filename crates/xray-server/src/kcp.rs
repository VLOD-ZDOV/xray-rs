#![forbid(unsafe_code)]

//! mKCP (transport/internet/kcp) implementation matching Xray-core.
//!
//! Provides ARQ reliability, congestion/flow control, header obfuscation
//! (srtp, utp, wechat-video, dtls, wireguard, dns), and seed obfuscation (AES-128-GCM or simple FNV-1a).

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use xray_transport::SocketProtector;

// Commands
pub const CMD_ACK: u8 = 0;
pub const CMD_DATA: u8 = 1;
pub const CMD_TERMINATE: u8 = 2;
pub const CMD_PING: u8 = 3;

// Segment options
pub const OPT_CLOSE: u8 = 1;

pub const DATA_HEADER_SIZE: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KcpHeaderType {
    #[default]
    None,
    Srtp,
    Utp,
    Wechat,
    Dtls,
    Wireguard,
    Dns,
}

impl KcpHeaderType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "srtp" => Some(Self::Srtp),
            "utp" => Some(Self::Utp),
            "wechat" => Some(Self::Wechat),
            "dtls" => Some(Self::Dtls),
            "wireguard" => Some(Self::Wireguard),
            "dns" => Some(Self::Dns),
            _ => None,
        }
    }

    pub fn size(&self, domain_len: usize) -> usize {
        match self {
            Self::None => 0,
            Self::Srtp => 4,
            Self::Utp => 4,
            Self::Wechat => 13,
            Self::Dtls => 13,
            Self::Wireguard => 4,
            Self::Dns => 12 + domain_len + 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcpSettings {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub cwnd_multiplier: u32,
    pub read_buffer_size: u32,
    pub write_buffer_size: u32,
    pub max_sending_window: u32,
    /// finalmask.udp mkcp-legacy layers in config order; the first one sits next to KCP.
    pub masks: Vec<KcpMask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KcpMask {
    Original,
    Header { kind: KcpHeaderType, domain: String },
    Aes(String),
}

impl Default for KcpSettings {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            cwnd_multiplier: 1,
            read_buffer_size: 2,
            write_buffer_size: 2,
            max_sending_window: 2 * 1024 * 1024,
            masks: Vec::new(),
        }
    }
}

impl KcpSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.mtu < 21 {
            return Err("MTU must be at least 21".to_string());
        }
        if self.tti < 10 || self.tti > 1000 {
            return Err("TTI must be between 10 and 1000".to_string());
        }
        if self.cwnd_multiplier < 1 {
            return Err("CwndMultiplier must be at least 1".to_string());
        }
        if self.max_sending_window / self.mtu == 0 {
            return Err(format!("MaxSendingWindow must be at least {}", self.mtu));
        }
        Ok(())
    }

    pub fn sending_in_flight_size(&self) -> u32 {
        let size = self.uplink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        size.max(8)
    }

    pub fn receiving_in_flight_size(&self) -> u32 {
        let size = self.downlink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        size.max(8)
    }
}

// FNV-1a 32-bit hash matching Go's hash/fnv
pub fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = 2166136261u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

pub fn xorfwd(x: &mut [u8]) {
    for i in 4..x.len() {
        x[i] ^= x[i - 4];
    }
}

pub fn xorbkd(x: &mut [u8]) {
    for i in (4..x.len()).rev() {
        x[i] ^= x[i - 4];
    }
}

/// Packs domain name in DNS format (e.g. "www.baidu.com." -> \x03www\x05baidu\x03com\x00)
pub fn pack_dns_domain(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let d = domain.trim_end_matches('.');
    for part in d.split('.') {
        if !part.is_empty() {
            out.push(part.len() as u8);
            out.extend_from_slice(part.as_bytes());
        }
    }
    out.push(0);
    out
}

pub struct HeaderGenerator {
    header_type: KcpHeaderType,
    dns_template: Vec<u8>,
    counter: AtomicU32,
}

impl HeaderGenerator {
    pub fn new(header_type: KcpHeaderType, domain: &str) -> Self {
        let mut dns_template = Vec::new();
        if header_type == KcpHeaderType::Dns {
            dns_template.extend_from_slice(&[0, 0]); // ID
            dns_template.extend_from_slice(&[0x01, 0x00]); // Flags
            dns_template.extend_from_slice(&[0x00, 0x01]); // Questions
            dns_template.extend_from_slice(&[0x00, 0x00]); // Answer
            dns_template.extend_from_slice(&[0x00, 0x00]); // Authority
            dns_template.extend_from_slice(&[0x00, 0x00]); // Additional
            dns_template.extend_from_slice(&pack_dns_domain(domain));
            dns_template.extend_from_slice(&[0x00, 0x01]); // Type A
            dns_template.extend_from_slice(&[0x00, 0x01]); // Class IN
        }
        Self {
            header_type,
            dns_template,
            counter: AtomicU32::new(1),
        }
    }

    pub fn size(&self) -> usize {
        match self.header_type {
            KcpHeaderType::None => 0,
            KcpHeaderType::Srtp => 4,
            KcpHeaderType::Utp => 4,
            KcpHeaderType::Wechat => 13,
            KcpHeaderType::Dtls => 13,
            KcpHeaderType::Wireguard => 4,
            KcpHeaderType::Dns => self.dns_template.len(),
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        let c = self.counter.fetch_add(1, Ordering::Relaxed);
        match self.header_type {
            KcpHeaderType::None => {}
            KcpHeaderType::Srtp => {
                buf.extend_from_slice(&[0x00, 0x00, (c >> 8) as u8, c as u8]);
            }
            KcpHeaderType::Utp => {
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            }
            KcpHeaderType::Wechat => {
                buf.push(0xa1);
                buf.push(0x08);
                buf.extend_from_slice(&c.to_be_bytes());
                buf.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            KcpHeaderType::Dtls => {
                let seq = c;
                let len = 17u16 + (c % 50) as u16;
                buf.extend_from_slice(&[23, 254, 253, 0x00, 0x00, 0, 0]);
                buf.extend_from_slice(&seq.to_be_bytes());
                buf.extend_from_slice(&len.to_be_bytes());
            }
            KcpHeaderType::Wireguard => {
                buf.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
            }
            KcpHeaderType::Dns => {
                let mut pkt = self.dns_template.clone();
                let tid = (c as u16).to_be_bytes();
                pkt[0] = tid[0];
                pkt[1] = tid[1];
                buf.extend_from_slice(&pkt);
            }
        }
    }
}

enum Layer {
    Original,
    Header(HeaderGenerator),
    Aes(Key<Aes128Gcm>),
}

impl Layer {
    fn overhead(&self) -> usize {
        match self {
            Layer::Original => 6,
            Layer::Header(h) => h.size(),
            Layer::Aes(_) => 12 + 16,
        }
    }

    fn seal(&self, plain: &[u8]) -> Vec<u8> {
        match self {
            Layer::Original => {
                let mut out = vec![0u8; 6];
                out[4..6].copy_from_slice(&(plain.len() as u16).to_be_bytes());
                out.extend_from_slice(plain);
                let hash = fnv1a_32(&out[4..]);
                out[..4].copy_from_slice(&hash.to_be_bytes());
                xorfwd(&mut out);
                out
            }
            Layer::Header(h) => {
                let mut out = Vec::with_capacity(h.size() + plain.len());
                h.serialize(&mut out);
                out.extend_from_slice(plain);
                out
            }
            Layer::Aes(key) => {
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let mut out = nonce_bytes.to_vec();
                if let Ok(ct) = Aes128Gcm::new(key).encrypt(&Nonce::from(nonce_bytes), plain) {
                    out.extend_from_slice(&ct);
                }
                out
            }
        }
    }

    fn open(&self, packet: &[u8]) -> Option<Vec<u8>> {
        match self {
            Layer::Original => {
                if packet.len() < 6 {
                    return None;
                }
                let mut buf = packet.to_vec();
                xorbkd(&mut buf);
                let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
                if fnv1a_32(&buf[4..]).to_be_bytes() != buf[..4] || buf.len() - 6 != len {
                    return None;
                }
                buf.drain(..6);
                Some(buf)
            }
            Layer::Header(h) => packet.get(h.size()..).map(<[u8]>::to_vec),
            Layer::Aes(key) => {
                if packet.len() < 12 + 16 {
                    return None;
                }
                let (nonce, ct) = packet.split_at(12);
                let nonce: [u8; 12] = nonce.try_into().ok()?;
                Aes128Gcm::new(key).decrypt(&Nonce::from(nonce), ct).ok()
            }
        }
    }
}

/// Applies the mkcp-legacy masks like Xray's finalmask chain: the first mask
/// in the list is applied to the KCP segments first and the last one is
/// outermost on the wire.
pub struct PacketObfuscator {
    layers: Vec<Layer>,
}

impl PacketObfuscator {
    pub fn new(settings: &KcpSettings) -> Self {
        let layers = settings
            .masks
            .iter()
            .map(|m| match m {
                KcpMask::Original => Layer::Original,
                KcpMask::Header { kind, domain } => {
                    Layer::Header(HeaderGenerator::new(*kind, domain))
                }
                KcpMask::Aes(password) => {
                    let hash = Sha256::digest(password.as_bytes());
                    let key_bytes: [u8; 16] = hash[..16].try_into().unwrap();
                    Layer::Aes(Key::<Aes128Gcm>::from(key_bytes))
                }
            })
            .collect();
        Self { layers }
    }

    pub fn overhead(&self) -> usize {
        self.layers.iter().map(Layer::overhead).sum()
    }

    pub fn seal(&self, plain: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(plain);
        for layer in &self.layers {
            *out = layer.seal(out);
        }
    }

    pub fn open(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut data = packet.to_vec();
        for layer in self.layers.iter().rev() {
            data = layer.open(&data)?;
        }
        Some(data)
    }
}

// ARQ Segment structures
#[derive(Debug, Clone)]
pub struct DataSegment {
    pub conv: u16,
    pub opt: u8,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Vec<u8>,
    pub timeout: u32,
    pub transmit: u32,
}

impl DataSegment {
    pub fn byte_size(&self) -> usize {
        DATA_HEADER_SIZE + self.payload.len()
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.conv.to_be_bytes());
        buf.push(CMD_DATA);
        buf.push(self.opt);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.number.to_be_bytes());
        buf.extend_from_slice(&self.sending_next.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
    }
}

#[derive(Debug, Clone)]
pub struct AckSegment {
    pub conv: u16,
    pub opt: u8,
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub number_list: Vec<u32>,
}

impl AckSegment {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.conv.to_be_bytes());
        buf.push(CMD_ACK);
        buf.push(self.opt);
        buf.extend_from_slice(&self.receiving_window.to_be_bytes());
        buf.extend_from_slice(&self.receiving_next.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(self.number_list.len() as u8);
        for &num in &self.number_list {
            buf.extend_from_slice(&num.to_be_bytes());
        }
    }
}

#[derive(Debug, Clone)]
pub struct CmdOnlySegment {
    pub conv: u16,
    pub cmd: u8,
    pub opt: u8,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

impl CmdOnlySegment {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.conv.to_be_bytes());
        buf.push(self.cmd);
        buf.push(self.opt);
        buf.extend_from_slice(&self.sending_next.to_be_bytes());
        buf.extend_from_slice(&self.receiving_next.to_be_bytes());
        buf.extend_from_slice(&self.peer_rto.to_be_bytes());
    }
}

#[derive(Debug)]
pub enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    Cmd(CmdOnlySegment),
}

impl Segment {
    pub fn conv(&self) -> u16 {
        match self {
            Self::Data(s) => s.conv,
            Self::Ack(s) => s.conv,
            Self::Cmd(s) => s.conv,
        }
    }

    pub fn parse_all(mut buf: &[u8]) -> Vec<Segment> {
        let mut segments = Vec::new();
        while buf.len() >= 4 {
            let conv = u16::from_be_bytes([buf[0], buf[1]]);
            let cmd = buf[2];
            let opt = buf[3];
            buf = &buf[4..];

            match cmd {
                CMD_DATA => {
                    if buf.len() < 14 {
                        break;
                    }
                    let timestamp = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                    let number = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                    let sending_next = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                    let data_len = u16::from_be_bytes(buf[12..14].try_into().unwrap()) as usize;
                    buf = &buf[14..];
                    if buf.len() < data_len {
                        break;
                    }
                    let payload = buf[..data_len].to_vec();
                    buf = &buf[data_len..];
                    segments.push(Segment::Data(DataSegment {
                        conv,
                        opt,
                        timestamp,
                        number,
                        sending_next,
                        payload,
                        timeout: 0,
                        transmit: 0,
                    }));
                }
                CMD_ACK => {
                    if buf.len() < 13 {
                        break;
                    }
                    let receiving_window = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                    let receiving_next = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                    let timestamp = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                    let count = buf[12] as usize;
                    buf = &buf[13..];
                    if buf.len() < count * 4 {
                        break;
                    }
                    let mut number_list = Vec::with_capacity(count);
                    for i in 0..count {
                        number_list.push(u32::from_be_bytes(
                            buf[i * 4..i * 4 + 4].try_into().unwrap(),
                        ));
                    }
                    buf = &buf[count * 4..];
                    segments.push(Segment::Ack(AckSegment {
                        conv,
                        opt,
                        receiving_window,
                        receiving_next,
                        timestamp,
                        number_list,
                    }));
                }
                _ => {
                    if buf.len() < 12 {
                        break;
                    }
                    let sending_next = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                    let receiving_next = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                    let peer_rto = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                    buf = &buf[12..];
                    segments.push(Segment::Cmd(CmdOnlySegment {
                        conv,
                        cmd,
                        opt,
                        sending_next,
                        receiving_next,
                        peer_rto,
                    }));
                }
            }
        }
        segments
    }
}

/// Round trip and RTO tracker following RFC 6298
pub struct RoundTrip {
    pub srtt: u32,
    pub rttvar: u32,
    pub rto: u32,
    pub min_rtt: u32,
}

impl RoundTrip {
    pub fn new(min_rtt: u32) -> Self {
        Self {
            srtt: 0,
            rttvar: 0,
            rto: 100,
            min_rtt,
        }
    }

    pub fn update(&mut self, rtt: u32) {
        if rtt > 0x7FFFFFFF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.srtt);
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let rto = if self.min_rtt < 4 * self.rttvar {
            self.srtt + 4 * self.rttvar
        } else {
            self.srtt + self.rttvar
        };
        self.rto = rto.clamp(100, 10000);
    }
}

/// Active KCP Session handling bidirectional reliable streams over UDP
pub struct KcpSession {
    pub conv: u16,
    pub peer_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
    pub obfuscator: Arc<PacketObfuscator>,
    pub settings: Arc<KcpSettings>,
    pub start_time: Instant,

    // ARQ state
    pub next_send_num: u32,
    pub send_queue: Vec<DataSegment>,
    pub round_trip: RoundTrip,

    pub next_recv_num: u32,
    pub recv_window: BTreeMap<u32, Vec<u8>>,
    pub ack_list: Vec<(u32, u32)>, // (sn, ts)

    pub last_incoming_time: Instant,
    pub last_ping_time: Instant,
    pub local_closed: bool,
    pub peer_closed: bool,
    pub terminating: bool,
    pub terminating_time: Option<Instant>,
    pub terminated: bool,

    pub input_tx: mpsc::Sender<Vec<Segment>>,
}

pub struct KcpDriver {
    pub session: Arc<Mutex<KcpSession>>,
    pub input_rx: mpsc::Receiver<Vec<Segment>>,
    pub duplex_internal: DuplexStream,
}

impl KcpDriver {
    pub async fn run(mut self) {
        let tti = {
            let s = self.session.lock().await;
            Duration::from_millis(s.settings.tti as u64)
        };
        let mut interval = tokio::time::interval(tti);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut read_buf = vec![0u8; 4096];
        let mut app_eof = false;
        let mut send_full = false;

        loop {
            tokio::select! {
                // Periodic ARQ flush & timer
                _ = interval.tick() => {
                    let mut s = self.session.lock().await;
                    if s.terminated {
                        break;
                    }
                    if s.last_incoming_time.elapsed() > Duration::from_secs(30) {
                        s.terminated = true;
                        break;
                    }
                    if s.terminating {
                        if let Some(t) = s.terminating_time {
                            if t.elapsed() > Duration::from_millis(2000) {
                                s.terminated = true;
                                break;
                            }
                        }
                        s.send_cmd(CMD_TERMINATE).await;
                    }
                    s.flush().await;
                }
                // Incoming segments from UDP listener/receiver
                Some(segs) = self.input_rx.recv() => {
                    let mut s = self.session.lock().await;
                    s.last_incoming_time = Instant::now();
                    for seg in segs {
                        match seg {
                            Segment::Data(ds) => {
                                if ds.opt & OPT_CLOSE != 0 {
                                    s.peer_closed = true;
                                }
                                s.process_data(ds, &mut self.duplex_internal).await;
                            }
                            Segment::Ack(ack) => {
                                if ack.opt & OPT_CLOSE != 0 {
                                    s.peer_closed = true;
                                }
                                s.process_ack(ack);
                            }
                            Segment::Cmd(cmd) => {
                                if cmd.opt & OPT_CLOSE != 0 || cmd.cmd == CMD_TERMINATE {
                                    s.peer_closed = true;
                                }
                                s.process_cmd(cmd);
                            }
                        }
                    }
                    s.flush().await;
                }
                // Application write from DuplexStream
                n_res = self.duplex_internal.read(&mut read_buf), if !app_eof && !send_full => {
                    match n_res {
                        Ok(0) => {
                            app_eof = true;
                            let mut s = self.session.lock().await;
                            s.local_closed = true;
                            s.flush().await;
                        }
                        Ok(n) => {
                            let mut s = self.session.lock().await;
                            s.push_app_data(&read_buf[..n]).await;
                        }
                        Err(_) => {
                            let mut s = self.session.lock().await;
                            s.local_closed = true;
                            s.terminated = true;
                            break;
                        }
                    }
                }
            }

            let s = self.session.lock().await;
            if s.terminated || (s.terminating && s.peer_closed) {
                break;
            }
            // Like Xray's sending worker, stop taking application data while
            // the unacknowledged window is full.
            send_full = s.send_queue.len() as u32 > s.settings.max_sending_window / s.settings.mtu;
        }

        // Final cleanup
        let mut s = self.session.lock().await;
        s.send_cmd(CMD_TERMINATE).await;
    }
}

impl KcpSession {
    pub fn new(
        conv: u16,
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        settings: Arc<KcpSettings>,
        obfuscator: Arc<PacketObfuscator>,
    ) -> (
        Arc<Mutex<Self>>,
        mpsc::Receiver<Vec<Segment>>,
        DuplexStream,
        DuplexStream,
    ) {
        let (input_tx, input_rx) = mpsc::channel(1024);
        let (duplex_app, duplex_internal) = tokio::io::duplex(256 * 1024);

        let session = Arc::new(Mutex::new(Self {
            conv,
            peer_addr,
            socket,
            obfuscator,
            round_trip: RoundTrip::new(settings.tti),
            settings,
            start_time: Instant::now(),
            next_send_num: 0,
            send_queue: Vec::new(),
            next_recv_num: 0,
            recv_window: BTreeMap::new(),
            ack_list: Vec::new(),
            last_incoming_time: Instant::now(),
            last_ping_time: Instant::now(),
            local_closed: false,
            peer_closed: false,
            terminating: false,
            terminating_time: None,
            terminated: false,
            input_tx,
        }));

        (session, input_rx, duplex_app, duplex_internal)
    }

    pub fn now_ms(&self) -> u32 {
        self.start_time.elapsed().as_millis() as u32
    }

    pub async fn push_app_data(&mut self, mut data: &[u8]) {
        let mss = (self.settings.mtu as usize)
            .saturating_sub(self.obfuscator.overhead() + DATA_HEADER_SIZE);
        let mss = mss.max(128);

        while !data.is_empty() {
            let chunk_len = data.len().min(mss);
            let payload = data[..chunk_len].to_vec();
            data = &data[chunk_len..];

            let seg = DataSegment {
                conv: self.conv,
                opt: 0,
                timestamp: self.now_ms(),
                number: self.next_send_num,
                sending_next: self.next_recv_num,
                payload,
                timeout: 0,
                transmit: 0,
            };
            self.next_send_num += 1;
            self.send_queue.push(seg);
        }
        self.flush().await;
    }

    pub async fn process_data(&mut self, seg: DataSegment, duplex: &mut DuplexStream) {
        let sn = seg.number;
        let ts = seg.timestamp;

        // Clean send queue based on peer's una
        self.clean_send_queue(seg.sending_next);

        // Record for ACK
        self.ack_list.push((sn, ts));

        if sn == self.next_recv_num {
            let _ = duplex.write_all(&seg.payload).await;
            self.next_recv_num += 1;
            // Drain contiguous buffered segments
            while let Some(p) = self.recv_window.remove(&self.next_recv_num) {
                let _ = duplex.write_all(&p).await;
                self.next_recv_num += 1;
            }
        } else if sn > self.next_recv_num {
            let max_wnd = self.settings.receiving_in_flight_size();
            if sn - self.next_recv_num < max_wnd {
                self.recv_window.insert(sn, seg.payload);
            }
        }
    }

    pub fn process_ack(&mut self, ack: AckSegment) {
        self.clean_send_queue(ack.receiving_next);
        for &num in &ack.number_list {
            self.send_queue.retain(|s| s.number != num);
        }
        if ack.timestamp != 0 {
            let now = self.now_ms();
            if now >= ack.timestamp {
                self.round_trip.update(now - ack.timestamp);
            }
        }
    }

    pub fn process_cmd(&mut self, cmd: CmdOnlySegment) {
        self.clean_send_queue(cmd.receiving_next);
        if cmd.cmd == CMD_TERMINATE {
            self.terminated = true;
        }
    }

    pub fn clean_send_queue(&mut self, una: u32) {
        self.send_queue.retain(|s| s.number >= una);
    }

    pub async fn flush(&mut self) {
        let now = self.now_ms();

        // 1. Send ACKs
        if !self.ack_list.is_empty() {
            let max_ts = self.ack_list.iter().map(|(_, ts)| *ts).max().unwrap_or(0);
            let mut numbers: Vec<u32> = self.ack_list.iter().map(|(sn, _)| *sn).collect();
            numbers.sort_unstable();
            numbers.dedup();
            // Up to 128 numbers per packet
            let chunk_numbers: Vec<u32> = numbers.into_iter().take(128).collect();

            let ack = AckSegment {
                conv: self.conv,
                opt: if self.local_closed { OPT_CLOSE } else { 0 },
                receiving_window: self.next_recv_num + self.settings.receiving_in_flight_size(),
                receiving_next: self.next_recv_num,
                timestamp: max_ts,
                number_list: chunk_numbers,
            };

            let mut raw = Vec::new();
            ack.serialize(&mut raw);
            self.send_packet(&raw).await;
            self.ack_list.clear();
        }

        // 2. Transmit / Retransmit Data
        let rto = self.round_trip.rto;
        let mut to_send = Vec::new();

        for seg in &mut self.send_queue {
            if seg.transmit == 0 {
                // First transmit
                seg.transmit = 1;
                seg.timestamp = now;
                seg.timeout = now + rto;
                seg.sending_next = self.next_recv_num;
                if self.local_closed {
                    seg.opt = OPT_CLOSE;
                }
                to_send.push(seg.clone());
            } else if now >= seg.timeout {
                // Retransmit
                seg.transmit += 1;
                seg.timestamp = now;
                seg.timeout = now + rto;
                seg.sending_next = self.next_recv_num;
                if self.local_closed {
                    seg.opt = OPT_CLOSE;
                }
                to_send.push(seg.clone());
            }
        }

        for seg in to_send {
            let mut raw = Vec::new();
            seg.serialize(&mut raw);
            self.send_packet(&raw).await;
        }

        // 3. Ping if idle
        if self.last_ping_time.elapsed() >= Duration::from_millis(3000) {
            self.send_cmd(CMD_PING).await;
            self.last_ping_time = Instant::now();
        }

        // 4. Terminate if local closed and all queued data has been acknowledged
        if self.local_closed && self.send_queue.is_empty() && !self.terminating {
            self.terminating = true;
            self.terminating_time = Some(Instant::now());
            self.send_cmd(CMD_TERMINATE).await;
        }
    }

    pub async fn send_cmd(&mut self, cmd: u8) {
        let seg = CmdOnlySegment {
            conv: self.conv,
            cmd,
            opt: if self.local_closed { OPT_CLOSE } else { 0 },
            sending_next: self
                .send_queue
                .first()
                .map(|s| s.number)
                .unwrap_or(self.next_send_num),
            receiving_next: self.next_recv_num,
            peer_rto: self.round_trip.rto,
        };
        let mut raw = Vec::new();
        seg.serialize(&mut raw);
        self.send_packet(&raw).await;
    }

    pub async fn send_packet(&self, payload: &[u8]) {
        let mut sealed = Vec::with_capacity(payload.len() + 64);
        self.obfuscator.seal(payload, &mut sealed);
        let _ = self.socket.send_to(&sealed, self.peer_addr).await;
    }
}

/// Start an mKCP inbound listener task
pub async fn start(
    inbound: &crate::config::Inbound,
    ctx: Arc<crate::vless::Context>,
    settings: Arc<KcpSettings>,
    acceptor: Option<crate::TlsAcceptor>,
    _router: Arc<crate::routing::Router>,
) -> Result<tokio::task::AbortHandle, String> {
    let port = inbound.port;
    let bind_addr = if inbound.listen.is_empty() {
        SocketAddr::from(([0, 0, 0, 0], port))
    } else {
        let h = if inbound.listen.contains(':') && !inbound.listen.starts_with('[') {
            format!("[{}]:{port}", inbound.listen)
        } else {
            format!("{}:{port}", inbound.listen)
        };
        h.parse()
            .map_err(|e| format!("invalid listen address: {e}"))?
    };

    let socket = if let Some(sockopt) = &inbound.sockopt {
        crate::sockopt::bind_udp(bind_addr, Some(sockopt))
            .map_err(|e| format!("failed to bind udp with sockopt: {e}"))?
    } else {
        UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("failed to bind udp socket on {bind_addr}: {e}"))?
    };

    crate::log::info(format!(
        "listening {} (mkcp) on {}",
        inbound.tag,
        socket.local_addr().unwrap()
    ));
    let socket = Arc::new(socket);
    let obfuscator = Arc::new(PacketObfuscator::new(&settings));

    type KcpSessionMap = Arc<Mutex<HashMap<(SocketAddr, u16), mpsc::Sender<Vec<Segment>>>>>;
    let sessions: KcpSessionMap = Arc::new(Mutex::new(HashMap::new()));

    let handler = crate::select_inbound_handler(inbound, ctx.clone(), &[])?;

    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    crate::log::warn(format!("mkcp socket recv error: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            let Some(plain) = obfuscator.open(&buf[..n]) else {
                continue;
            };

            let segments = Segment::parse_all(&plain);
            if segments.is_empty() {
                continue;
            }

            let conv = segments[0].conv();
            let key = (peer, conv);

            let mut sess_map = sessions.lock().await;
            if let Some(tx) = sess_map.get(&key) {
                // A full session drops the packet, as UDP would; waiting here
                // would stall every other session behind the shared map.
                if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(segments) {
                    sess_map.remove(&key);
                }
            } else if matches!(&segments[0], Segment::Cmd(c) if c.cmd == CMD_TERMINATE) {
                // Xray opens no connection for a terminate.
            } else {
                // New inbound connection
                let (session, input_rx, duplex_app, duplex_internal) = KcpSession::new(
                    conv,
                    peer,
                    socket.clone(),
                    settings.clone(),
                    obfuscator.clone(),
                );

                let tx = session.lock().await.input_tx.clone();
                let _ = tx.try_send(segments);
                let own_tx = tx.clone();
                sess_map.insert(key, tx);

                // Spawn session driver
                let driver = KcpDriver {
                    session: session.clone(),
                    input_rx,
                    duplex_internal,
                };
                let sessions_ref = sessions.clone();
                tokio::spawn(async move {
                    driver.run().await;
                    let mut map = sessions_ref.lock().await;
                    if map.get(&key).is_some_and(|t| t.same_channel(&own_tx)) {
                        map.remove(&key);
                    }
                });

                // Dispatch to inbound handler (with TLS if configured)
                let handler = handler.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let stream = crate::httpupgrade::PrefixedStream::new(
                        crate::InboundIo::Duplex(duplex_app),
                        Vec::new(),
                    );
                    if let Some(acceptor) = acceptor {
                        let captured = crate::penetrating_tls::CapturedStream::new(stream);
                        if let Ok(Ok(tls_stream)) =
                            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(captured))
                                .await
                        {
                            let penetrating =
                                crate::penetrating_tls::ServerPenetratingTlsStream::new(tls_stream);
                            crate::dispatch(
                                crate::InboundStream::Tls(penetrating),
                                peer,
                                None,
                                None,
                                handler,
                            )
                            .await;
                        }
                    } else {
                        crate::dispatch(
                            crate::InboundStream::Plain(stream),
                            peer,
                            None,
                            None,
                            handler,
                        )
                        .await;
                    }
                });
            }
        }
    });

    Ok(task.abort_handle())
}

/// Dial an mKCP outbound connection
pub async fn dial(
    target_addr: SocketAddr,
    settings: &KcpSettings,
    protector: Option<&crate::outbound_transport::OutboundProtector>,
) -> io::Result<DuplexStream> {
    let bind_addr = if target_addr.is_ipv6() {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    if let Some(p) = protector {
        p.apply_udp_socket(&socket)?;
    }
    socket.connect(target_addr).await?;
    let socket = Arc::new(socket);

    let settings = Arc::new(settings.clone());
    let obfuscator = Arc::new(PacketObfuscator::new(&settings));
    let conv: u16 = rand::random();

    let (session, input_rx, duplex_app, duplex_internal) = KcpSession::new(
        conv,
        target_addr,
        socket.clone(),
        settings.clone(),
        obfuscator.clone(),
    );

    // Driver task
    let driver = KcpDriver {
        session: session.clone(),
        input_rx,
        duplex_internal,
    };
    tokio::spawn(driver.run());

    // Background reader from UDP socket
    let tx = session.lock().await.input_tx.clone();
    let reader_obfs = obfuscator.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok(n) = socket.recv(&mut buf).await {
            if let Some(plain) = reader_obfs.open(&buf[..n]) {
                let segs = Segment::parse_all(&plain);
                if !segs.is_empty() && tx.send(segs).await.is_err() {
                    break;
                }
            }
        }
    });

    Ok(duplex_app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a() {
        assert_eq!(fnv1a_32(b"hello"), 0x4f9f2cab);
    }

    fn roundtrip(masks: Vec<KcpMask>) {
        let obfs = PacketObfuscator::new(&KcpSettings {
            masks,
            ..Default::default()
        });
        let plain = b"test payload 1234567890";
        let mut sealed = Vec::new();
        obfs.seal(plain, &mut sealed);
        assert_eq!(sealed.len(), plain.len() + obfs.overhead());
        assert_eq!(obfs.open(&sealed).as_deref(), Some(plain.as_slice()));
    }

    #[test]
    fn test_masks_roundtrip() {
        roundtrip(Vec::new());
        roundtrip(vec![KcpMask::Original]);
        roundtrip(vec![KcpMask::Aes("my-secret-password".into())]);
        for kind in [
            KcpHeaderType::Srtp,
            KcpHeaderType::Utp,
            KcpHeaderType::Wechat,
            KcpHeaderType::Dtls,
            KcpHeaderType::Wireguard,
            KcpHeaderType::Dns,
        ] {
            roundtrip(vec![KcpMask::Header {
                kind,
                domain: "example.com".into(),
            }]);
        }
        roundtrip(vec![
            KcpMask::Header {
                kind: KcpHeaderType::Dns,
                domain: "example.com".into(),
            },
            KcpMask::Aes("pw".into()),
            KcpMask::Original,
        ]);
    }

    #[test]
    fn test_mask_order_is_wire_order() {
        let obfs = PacketObfuscator::new(&KcpSettings {
            masks: vec![
                KcpMask::Header {
                    kind: KcpHeaderType::Wireguard,
                    domain: String::new(),
                },
                KcpMask::Aes("pw".into()),
            ],
            ..Default::default()
        });
        let mut sealed = Vec::new();
        obfs.seal(b"abc", &mut sealed);
        // The header is inside the encryption, so the wire starts with the nonce.
        assert_ne!(&sealed[..4], &[0x04, 0, 0, 0]);
    }

    #[test]
    fn test_original_mask_known_vector() {
        let obfs = PacketObfuscator::new(&KcpSettings {
            masks: vec![KcpMask::Original],
            ..Default::default()
        });
        let mut sealed = Vec::new();
        obfs.seal(b"hello", &mut sealed);
        let mut expect = vec![0u8; 6];
        expect[4..6].copy_from_slice(&5u16.to_be_bytes());
        expect.extend_from_slice(b"hello");
        let hash = fnv1a_32(&expect[4..]);
        expect[..4].copy_from_slice(&hash.to_be_bytes());
        xorfwd(&mut expect);
        assert_eq!(sealed, expect);
        sealed[7] ^= 1;
        assert_eq!(obfs.open(&sealed), None);
    }

    #[test]
    fn test_segments_parse() {
        let data_seg = DataSegment {
            conv: 12345,
            opt: 0,
            timestamp: 100,
            number: 5,
            sending_next: 3,
            payload: b"hello segment".to_vec(),
            timeout: 0,
            transmit: 0,
        };
        let mut buf = Vec::new();
        data_seg.serialize(&mut buf);

        let parsed = Segment::parse_all(&buf);
        assert_eq!(parsed.len(), 1);
        if let Segment::Data(d) = &parsed[0] {
            assert_eq!(d.conv, 12345);
            assert_eq!(d.number, 5);
            assert_eq!(d.sending_next, 3);
            assert_eq!(d.payload, b"hello segment");
        } else {
            panic!("Expected DataSegment");
        }
    }
}
