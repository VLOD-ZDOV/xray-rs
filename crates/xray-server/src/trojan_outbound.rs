//! Trojan outbound supporting TCP and common transports.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use xray_proxy::trojan::{
    decode_udp_packet, encode_request_header, encode_udp_packet, TrojanAuth, UdpPacket, WireError,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::BoxedTransportStream;

use crate::outbound::Stream;
use crate::outbound_transport::ServerConnector;
use crate::vless::{resolve, Host};

pub struct TrojanOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub auth: TrojanAuth,
}

impl fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl TrojanOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (trojan): {m}");
        let connector = ServerConnector::parse(tag, "trojan", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let password = if let Some(server) = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
        {
            server
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing password in servers[0]"))?
        } else if let Some(p) = settings.get("password").and_then(Value::as_str) {
            p
        } else {
            return Err(err("missing password in settings"));
        };

        let auth = TrojanAuth::new(password).map_err(|e| err(&e.to_string()))?;

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            auth,
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<Box<dyn Stream>> {
        let mut carrier = self.connector.connect().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Tcp,
        );
        let header = encode_request_header(&self.auth, &target)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        carrier.write_all(header.as_bytes()).await?;
        carrier.flush().await?;
        Ok(Box::new(carrier))
    }

    pub async fn open_udp(&self, host: &Host, port: u16) -> io::Result<TrojanUdpLink> {
        let mut carrier = self.connector.connect().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Udp,
        );
        let header = encode_request_header(&self.auth, &target)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        carrier.write_all(header.as_bytes()).await?;
        carrier.flush().await?;
        Ok(TrojanUdpLink::new(target, carrier))
    }

    pub fn open_cone_udp(self: &Arc<Self>) -> TrojanConeUdp {
        TrojanConeUdp::new(Arc::clone(self))
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        resolve(host, port).await
    }
}

pub struct TrojanUdpLink {
    target: Target,
    writer: Mutex<tokio::io::WriteHalf<BoxedTransportStream>>,
    reader: Mutex<tokio::io::ReadHalf<BoxedTransportStream>>,
    read_buf: Mutex<Vec<u8>>,
}

impl TrojanUdpLink {
    pub fn new(target: Target, stream: BoxedTransportStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            read_buf: Mutex::new(Vec::new()),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let wire = encode_udp_packet(&UdpPacket {
            target: self.target.clone(),
            payload: data,
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut writer = self.writer.lock().await;
        writer.write_all(&wire).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = self.read_buf.lock().await;
        let mut reader = self.reader.lock().await;
        let mut temp = [0u8; 8192];
        loop {
            if !read_buf.is_empty() {
                match decode_udp_packet(&read_buf) {
                    Ok((packet, used)) => {
                        let n = packet.payload.len().min(buf.len());
                        buf[..n].copy_from_slice(&packet.payload[..n]);
                        read_buf.drain(..used);
                        return Ok(n);
                    }
                    Err(WireError::Incomplete) => {}
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("trojan udp decode: {e}"),
                        ));
                    }
                }
            }
            let n = reader.read(&mut temp).await?;
            if n == 0 {
                return Ok(0);
            }
            read_buf.extend_from_slice(&temp[..n]);
        }
    }
}

type TrojanFlow = (Arc<TrojanUdpLink>, JoinHandle<()>);

pub struct TrojanConeUdp {
    trojan: Arc<TrojanOutbound>,
    sessions: Mutex<HashMap<SocketAddr, TrojanFlow>>,
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
}

impl TrojanConeUdp {
    pub fn new(trojan: Arc<TrojanOutbound>) -> Self {
        let (tx, rx) = mpsc::channel(256);
        Self {
            trojan,
            sessions: Mutex::new(HashMap::new()),
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        self.trojan.udp_target(host, port).await
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        let mut link_opt = None;
        {
            let sessions = self.sessions.lock().await;
            if let Some((link, task)) = sessions.get(&addr) {
                if !task.is_finished() {
                    link_opt = Some(link.clone());
                }
            }
        }
        let link = match link_opt {
            Some(link) => link,
            None => {
                let new_link = Arc::new(
                    self.trojan
                        .open_udp(&Host::Ip(addr.ip()), addr.port())
                        .await?,
                );
                let (reader, tx) = (new_link.clone(), self.tx.clone());
                let task = tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    while let Ok(n) = reader.recv(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let packet = Bytes::copy_from_slice(&buf[..n]);
                        if tx.send((addr, packet)).await.is_err() {
                            break;
                        }
                    }
                });
                let mut sessions = self.sessions.lock().await;
                if let Some((existing, task_ex)) = sessions.get(&addr) {
                    if !task_ex.is_finished() {
                        task.abort();
                        existing.clone()
                    } else {
                        if let Some((_, old)) = sessions.insert(addr, (new_link.clone(), task)) {
                            old.abort();
                        }
                        new_link
                    }
                } else {
                    sessions.insert(addr, (new_link.clone(), task));
                    new_link
                }
            }
        };
        link.send(data).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (from, packet) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);
        Ok((n, from))
    }

    pub fn abort_all(&mut self) {
        for (_, task) in self.sessions.get_mut().values() {
            task.abort();
        }
    }
}

impl Drop for TrojanConeUdp {
    fn drop(&mut self) {
        self.abort_all();
    }
}
