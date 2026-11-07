//! DNS outbound for intercepting and resolving DNS queries.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use xray_config::Network;

use crate::outbound::Stream;
use crate::vless::{resolve, Host};

pub struct DnsOutbound {
    pub tag: String,
    pub address: Option<Host>,
    pub port: u16,
    pub network: Network,
    pub sockopt: Option<Arc<crate::config::SockoptSettings>>,
}

impl fmt::Debug for DnsOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsOutbound")
            .field("tag", &self.tag)
            .field("address", &self.address)
            .field("port", &self.port)
            .finish()
    }
}

impl DnsOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let settings = outbound.get("settings").unwrap_or(outbound);
        let address = settings
            .get("rewriteAddress")
            .or_else(|| settings.get("address"))
            .and_then(Value::as_str)
            .filter(|a| !a.is_empty())
            .map(|a| {
                match a
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                {
                    Ok(ip) => Host::Ip(ip),
                    Err(_) => Host::Domain(a.to_owned()),
                }
            });

        let port = settings
            .get("rewritePort")
            .or_else(|| settings.get("port"))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .unwrap_or(53);

        let network_str = settings
            .get("rewriteNetwork")
            .or_else(|| settings.get("network"))
            .and_then(Value::as_str)
            .unwrap_or("udp");

        let network = match network_str {
            "tcp" => Network::Tcp,
            _ => Network::Udp,
        };

        let sockopt = crate::config::parse_sockopt(
            outbound
                .pointer("/streamSettings/sockopt")
                .unwrap_or(&Value::Null),
            &format!("outbound {tag:?}"),
        )?
        .map(Arc::new);

        Ok(Self {
            tag: tag.to_owned(),
            address,
            port,
            network,
            sockopt,
        })
    }

    pub async fn resolve_query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS packet too short",
            ));
        }

        // If upstream rewriteAddress is configured, forward query directly
        if let Some(host) = &self.address {
            let upstream_addr = resolve(host, self.port).await?;
            let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
                ([0, 0, 0, 0], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            let socket = crate::sockopt::bind_udp(bind_addr, self.sockopt.as_deref())?;
            socket.connect(upstream_addr).await?;
            socket.send(query).await?;
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "DNS upstream query timed out")
                })??;
            buf.truncate(n);
            return Ok(buf);
        }

        // Otherwise resolve query locally using system resolver
        let id = [query[0], query[1]];
        let (qname, qtype, qend) = parse_dns_question(query)?;

        if qtype != 1 && qtype != 28 {
            // Non-A/AAAA: return empty response
            let mut resp = Vec::with_capacity(qend);
            resp.extend_from_slice(&id);
            resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Standard response, No error
            resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
            resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
            resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
            resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
            resp.extend_from_slice(&query[12..qend]);
            return Ok(resp);
        }

        let ips: Vec<IpAddr> = match crate::dns::resolve_dns_query(&qname, 0).await {
            Ok(addrs) => addrs
                .into_iter()
                .map(|a| a.ip())
                .filter(|ip| match qtype {
                    1 => ip.is_ipv4(),
                    28 => ip.is_ipv6(),
                    _ => false,
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        let mut resp = Vec::with_capacity(qend + ips.len() * 16);
        resp.extend_from_slice(&id);
        let flags: u16 = if ips.is_empty() {
            0x8183 // NXDOMAIN
        } else {
            0x8180 // NOERROR
        };
        resp.extend_from_slice(&flags.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        resp.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        resp.extend_from_slice(&query[12..qend]); // Copy Question

        for ip in ips {
            resp.extend_from_slice(&[0xC0, 0x0C]); // Pointer to QNAME at byte 12
            resp.extend_from_slice(&qtype.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes()); // Class IN
            let ttl: u32 = if crate::fakedns::is_ip_in_pool(&ip) {
                1
            } else {
                60
            };
            resp.extend_from_slice(&ttl.to_be_bytes());
            match ip {
                IpAddr::V4(v4) => {
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    resp.extend_from_slice(&16u16.to_be_bytes());
                    resp.extend_from_slice(&v6.octets());
                }
            }
        }

        Ok(resp)
    }

    pub async fn connect(&self) -> io::Result<Box<dyn Stream>> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let outbound = Arc::new(DnsOutbound {
            tag: self.tag.clone(),
            address: self.address.clone(),
            port: self.port,
            network: self.network,
            sockopt: self.sockopt.clone(),
        });

        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                if server.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut query = vec![0u8; len];
                if server.read_exact(&mut query).await.is_err() {
                    break;
                }
                match outbound.resolve_query(&query).await {
                    Ok(resp) => {
                        let resp_len = resp.len() as u16;
                        if server.write_all(&resp_len.to_be_bytes()).await.is_err() {
                            break;
                        }
                        if server.write_all(&resp).await.is_err() {
                            break;
                        }
                        let _ = server.flush().await;
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Box::new(client))
    }
}

pub struct DnsUdpSession {
    outbound: Arc<DnsOutbound>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl DnsUdpSession {
    pub fn new(outbound: Arc<DnsOutbound>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        Self {
            outbound,
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let resp = self.outbound.resolve_query(data).await?;
        let _ = self.tx.send(resp).await;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().await;
        let resp = rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "DNS channel closed"))?;
        let n = resp.len().min(buf.len());
        buf[..n].copy_from_slice(&resp[..n]);
        Ok(n)
    }
}

fn parse_dns_question(packet: &[u8]) -> io::Result<(String, u16, usize)> {
    let mut offset = 12;
    let mut labels = Vec::new();

    loop {
        if offset >= packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS name",
            ));
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if offset + len > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS label",
            ));
        }
        let label = std::str::from_utf8(&packet[offset..offset + len]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in DNS label")
        })?;
        labels.push(label.to_owned());
        offset += len;
    }

    if offset + 4 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS question",
        ));
    }

    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 4; // Skip QTYPE and QCLASS

    Ok((labels.join("."), qtype, offset))
}
