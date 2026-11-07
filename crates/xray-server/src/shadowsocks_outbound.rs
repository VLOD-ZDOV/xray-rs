//! Shadowsocks outbound supporting AEAD 2017 and Shadowsocks 2022.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use xray_proxy::shadowsocks::aead2017::{
    Cipher, ClientStream as ClientStream2017, Method as Method2017, UdpSession as UdpSession2017,
};
use xray_proxy::shadowsocks2022::{
    ClientStream as ClientStream2022, Method as Method2022, UdpSession as UdpSession2022,
};
use xray_routing::{Network, Target, TargetAddr};

use crate::outbound::Stream;
use crate::outbound_transport::ServerConnector;
use crate::vless::{resolve, Host};

#[derive(Clone)]
pub enum ShadowsocksMethod {
    Aead2017(Arc<Method2017>),
    Ss2022(Arc<Method2022>),
}

pub struct ShadowsocksOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub method: ShadowsocksMethod,
}

impl fmt::Debug for ShadowsocksOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl ShadowsocksOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (shadowsocks): {m}");
        let connector = ServerConnector::parse(tag, "shadowsocks", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let (method_str, password) = if let Some(server) = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
        {
            let m = server
                .get("method")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing method in servers[0]"))?;
            let p = server
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing password in servers[0]"))?;
            (m, p)
        } else if let (Some(m), Some(p)) = (
            settings.get("method").and_then(Value::as_str),
            settings.get("password").and_then(Value::as_str),
        ) {
            (m, p)
        } else {
            return Err(err("missing method or password in settings"));
        };

        let method = if Cipher::parse(method_str).is_some() {
            ShadowsocksMethod::Aead2017(Arc::new(
                Method2017::new(method_str, password).map_err(|e| err(&e.to_string()))?,
            ))
        } else {
            match Method2022::new(method_str, password) {
                Ok(m) => ShadowsocksMethod::Ss2022(Arc::new(m)),
                Err(e) => {
                    return Err(err(&format!(
                        "unsupported shadowsocks method or key {method_str:?}: {e}"
                    )))
                }
            }
        };

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            method,
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<Box<dyn Stream>> {
        let carrier = self.connector.connect().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Tcp,
        );
        match &self.method {
            ShadowsocksMethod::Aead2017(m) => {
                let stream = ClientStream2017::new(carrier, m.clone(), &target)?;
                Ok(Box::new(stream))
            }
            ShadowsocksMethod::Ss2022(m) => {
                let stream = ClientStream2022::new(carrier, m.clone(), &target)?;
                Ok(Box::new(stream))
            }
        }
    }

    pub async fn server_addr(&self) -> io::Result<SocketAddr> {
        resolve(&self.connector.server.0, self.connector.server.1).await
    }

    pub async fn open_udp(&self, host: &Host, port: u16) -> io::Result<ShadowsocksUdpLink> {
        let server = self.server_addr().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Udp,
        );
        ShadowsocksUdpLink::new(server, target, self.method.clone()).await
    }

    pub async fn open_cone_udp(&self) -> io::Result<ShadowsocksConeUdp> {
        let server = self.server_addr().await?;
        ShadowsocksConeUdp::new(server, self.method.clone()).await
    }
}

pub struct ShadowsocksUdpLink {
    socket: Arc<UdpSocket>,
    target: Target,
    method: ShadowsocksMethod,
    session2022: Option<Arc<Mutex<UdpSession2022>>>,
    // Kept out of the recv future: a 64 KiB array there would grow every connection's task.
    wire_buf: Mutex<Vec<u8>>,
}

impl ShadowsocksUdpLink {
    pub async fn new(
        server_addr: SocketAddr,
        target: Target,
        method: ShadowsocksMethod,
    ) -> io::Result<Self> {
        let bind: SocketAddr = if server_addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server_addr).await?;
        let session2022 = match &method {
            ShadowsocksMethod::Aead2017(_) => None,
            ShadowsocksMethod::Ss2022(m) => {
                Some(Arc::new(Mutex::new(UdpSession2022::new(m.clone())?)))
            }
        };
        Ok(Self {
            socket: Arc::new(socket),
            target,
            method,
            session2022,
            wire_buf: Mutex::new(vec![0u8; 65535]),
        })
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let wire = match &self.method {
            ShadowsocksMethod::Aead2017(m) => {
                let mut session = UdpSession2017::new(m.clone());
                session.encode(&self.target, data)?
            }
            ShadowsocksMethod::Ss2022(_) => {
                let mut guard = self.session2022.as_ref().unwrap().lock().await;
                guard.encode(&self.target, data)?
            }
        };
        self.socket.send(&wire).await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut wire_buf = self.wire_buf.lock().await;
        loop {
            let n = self.socket.recv(&mut wire_buf).await?;
            if n == 0 {
                return Ok(0);
            }
            let payload = match &self.method {
                ShadowsocksMethod::Aead2017(m) => {
                    let mut session = UdpSession2017::new(m.clone());
                    match session.decode(&wire_buf[..n]) {
                        Ok((_, p)) => p,
                        Err(_) => continue,
                    }
                }
                ShadowsocksMethod::Ss2022(_) => {
                    let mut guard = self.session2022.as_ref().unwrap().lock().await;
                    match guard.decode(&wire_buf[..n]) {
                        Ok((_, p)) => p,
                        Err(_) => continue,
                    }
                }
            };
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);
            return Ok(len);
        }
    }
}

pub struct ShadowsocksConeUdp {
    socket: Arc<UdpSocket>,
    method: ShadowsocksMethod,
    session2022: Option<Arc<Mutex<UdpSession2022>>>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    reader_task: JoinHandle<()>,
}

impl ShadowsocksConeUdp {
    pub async fn new(server_addr: SocketAddr, method: ShadowsocksMethod) -> io::Result<Self> {
        let bind: SocketAddr = if server_addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        socket.connect(server_addr).await?;

        let session2022 = match &method {
            ShadowsocksMethod::Aead2017(_) => None,
            ShadowsocksMethod::Ss2022(m) => {
                Some(Arc::new(Mutex::new(UdpSession2022::new(m.clone())?)))
            }
        };

        let (tx, rx) = mpsc::channel(256);
        let socket_recv = socket.clone();
        let method_recv = method.clone();
        let session2022_recv = session2022.clone();
        let tx_recv = tx.clone();

        let reader_task = tokio::spawn(async move {
            let mut wire_buf = vec![0u8; 65535];
            while let Ok(n) = socket_recv.recv(&mut wire_buf).await {
                if n == 0 {
                    break;
                }
                let decoded = match &method_recv {
                    ShadowsocksMethod::Aead2017(m) => {
                        let mut session = UdpSession2017::new(m.clone());
                        session.decode(&wire_buf[..n]).ok()
                    }
                    ShadowsocksMethod::Ss2022(_) => {
                        let mut guard = session2022_recv.as_ref().unwrap().lock().await;
                        guard.decode(&wire_buf[..n]).ok()
                    }
                };
                if let Some((target, payload)) = decoded {
                    let addr_opt = match target.addr {
                        TargetAddr::Ip(ip) => Some(SocketAddr::new(ip, target.port)),
                        TargetAddr::Domain(domain) => {
                            resolve(&Host::Domain(domain), target.port).await.ok()
                        }
                    };
                    if let Some(addr) = addr_opt {
                        if tx_recv.send((addr, Bytes::from(payload))).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            socket,
            method,
            session2022,
            rx: Mutex::new(rx),
            reader_task,
        })
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        resolve(host, port).await
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Udp);
        let wire = match &self.method {
            ShadowsocksMethod::Aead2017(m) => {
                let mut session = UdpSession2017::new(m.clone());
                session.encode(&target, data)?
            }
            ShadowsocksMethod::Ss2022(_) => {
                let mut guard = self.session2022.as_ref().unwrap().lock().await;
                guard.encode(&target, data)?
            }
        };
        self.socket.send(&wire).await?;
        Ok(())
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
}

impl Drop for ShadowsocksConeUdp {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}
