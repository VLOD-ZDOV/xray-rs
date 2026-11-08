//! VMess outbound supporting TCP and common transports.

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
use uuid::Uuid;
use xray_proxy::vmess::{Account, Cipher, ClientStream, Options};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::BoxedTransportStream;

use crate::outbound::Stream;
use crate::outbound_transport::ServerConnector;
use crate::vless::{resolve, Host};

pub struct VmessOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub account: Account,
}

impl fmt::Debug for VmessOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmessOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl VmessOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (vmess): {m}");
        let connector = ServerConnector::parse(tag, "vmess", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let user = match settings.get("vnext") {
            Some(v) => {
                if settings.get("address").is_some() {
                    return Err(err("set either address or vnext, not both"));
                }
                let [vnext] = v.as_array().map(Vec::as_slice).unwrap_or_default() else {
                    return Err(err(
                        "VMess settings: \"vnext\" should have one and only one member. Multiple endpoints in \"vnext\" should use multiple VMess outbounds and routing balancer instead",
                    ));
                };
                let [user] = vnext
                    .get("users")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                else {
                    return Err(err(
                        "VMess vnext: \"users\" should have one and only one member. Multiple members in \"users\" should use multiple VMess outbounds and routing balancer instead",
                    ));
                };
                user
            }
            None => settings,
        };
        let id_str = user
            .get("id")
            .or_else(|| settings.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| err("missing user id"))?;
        let user_id = Uuid::parse_str(id_str)
            .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id_str.as_bytes()));

        let security_str = user
            .get("security")
            .or_else(|| settings.get("security"))
            .and_then(Value::as_str)
            .unwrap_or("auto");
        let cipher_name = match security_str {
            "zero" | "none" => "auto",
            other => other,
        };
        let cipher = Cipher::parse(cipher_name).map_err(|e| err(&e.to_string()))?;
        let account = Account::new(
            user_id.as_bytes(),
            cipher,
            Options {
                authenticated_length: true,
                no_termination_signal: false,
            },
        );

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            account,
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
        let stream = ClientStream::new(carrier, &self.account, &target)?;
        Ok(Box::new(stream))
    }

    pub async fn open_udp(&self, host: &Host, port: u16) -> io::Result<VmessUdpLink> {
        let carrier = self.connector.connect().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Udp,
        );
        let stream = ClientStream::new(carrier, &self.account, &target)?;
        Ok(VmessUdpLink::new(stream))
    }

    pub fn open_cone_udp(self: &Arc<Self>) -> VmessConeUdp {
        VmessConeUdp::new(Arc::clone(self))
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        resolve(host, port).await
    }
}

pub struct VmessUdpLink {
    writer: Mutex<tokio::io::WriteHalf<ClientStream<BoxedTransportStream>>>,
    reader: Mutex<tokio::io::ReadHalf<ClientStream<BoxedTransportStream>>>,
}

impl VmessUdpLink {
    pub fn new(stream: ClientStream<BoxedTransportStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        writer.write_all(data).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = self.reader.lock().await;
        reader.read(buf).await
    }
}

type VmessFlow = (Arc<VmessUdpLink>, JoinHandle<()>);

pub struct VmessConeUdp {
    vmess: Arc<VmessOutbound>,
    sessions: Mutex<HashMap<SocketAddr, VmessFlow>>,
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
}

impl VmessConeUdp {
    pub fn new(vmess: Arc<VmessOutbound>) -> Self {
        let (tx, rx) = mpsc::channel(256);
        Self {
            vmess,
            sessions: Mutex::new(HashMap::new()),
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        self.vmess.udp_target(host, port).await
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
                    self.vmess
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
                sessions.retain(|k, (_, t)| *k == addr || !t.is_finished());
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

impl Drop for VmessConeUdp {
    fn drop(&mut self) {
        self.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(settings: Value) -> Result<VmessOutbound, String> {
        VmessOutbound::parse("t", &serde_json::json!({ "settings": settings }))
    }

    #[test]
    fn vnext_and_users_must_have_one_member() {
        let id = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let user = serde_json::json!({ "id": id });
        let server = |users: Vec<Value>| serde_json::json!({"address": "192.0.2.1", "port": 443, "users": users});
        let err = outbound(serde_json::json!({ "vnext": [server(vec![user.clone()]), server(vec![user.clone()])] }))
            .unwrap_err();
        assert!(
            err.contains("\"vnext\" should have one and only one member"),
            "{err}"
        );
        let err =
            outbound(serde_json::json!({ "vnext": [server(vec![user.clone(), user.clone()])] }))
                .unwrap_err();
        assert!(
            err.contains("\"users\" should have one and only one member"),
            "{err}"
        );
        assert!(outbound(serde_json::json!({ "vnext": [server(vec![user])] })).is_ok());
    }
}
