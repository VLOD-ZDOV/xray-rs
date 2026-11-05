//! SOCKS5 outbound (RFC 1928, username/password per RFC 1929): TCP CONNECT
//! with the destination name sent as is, UDP through UDP ASSOCIATE.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::vless::{resolve_all, Host, CONNECT_TIMEOUT};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USER_PASS: u8 = 2;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

#[derive(Debug)]
pub struct SocksOutbound {
    tag: String,
    server: (Host, u16),
    auth: Option<(String, String)>,
}

impl SocksOutbound {
    /// Accepts Xray's `servers: [{address, port, users: [{user, pass}]}]` and the flat
    /// `{address, port, user, pass}` form.
    pub fn parse(tag: &str, settings: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (socks): {m}");
        let server = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
            .unwrap_or(settings);
        let address = server
            .get("address")
            .and_then(Value::as_str)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| err("missing address"))?;
        let port = server
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| err("invalid port"))?;
        let user = server
            .get("users")
            .and_then(Value::as_array)
            .and_then(|u| u.first())
            .unwrap_or(server);
        let field = |key| {
            user.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (name, pass) = (field("user"), field("pass"));
        if name.len() > 255 || pass.len() > 255 {
            return Err(err("user and pass must be at most 255 bytes"));
        }
        let host = match address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(address.to_owned()),
        };
        Ok(Self {
            tag: tag.to_owned(),
            server: (host, port),
            auth: (!name.is_empty()).then_some((name, pass)),
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<TcpStream> {
        let (stream, _) = self.handshake(CMD_CONNECT, host, port).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// The control connection must stay open for as long as the association is used.
    pub async fn associate(&self) -> io::Result<SocksUdp> {
        let unspecified = Host::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let (control, mut relay) = self.handshake(CMD_UDP_ASSOCIATE, &unspecified, 0).await?;
        // Servers commonly answer 0.0.0.0, meaning "the address you reached me at".
        if relay.ip().is_unspecified() {
            relay.set_ip(control.peer_addr()?.ip());
        }
        let bind: SocketAddr = if relay.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(relay).await?;
        Ok(SocksUdp {
            _control: control,
            socket,
        })
    }

    async fn handshake(
        &self,
        command: u8,
        host: &Host,
        port: u16,
    ) -> io::Result<(TcpStream, SocketAddr)> {
        let work = async {
            let mut stream = self.dial().await?;
            let method = if self.auth.is_some() {
                USER_PASS
            } else {
                NO_AUTH
            };
            stream.write_all(&[VERSION, 1, method]).await?;
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).await?;
            if reply != [VERSION, method] {
                return Err(self.error(format!("server refused auth method {method}")));
            }
            if let Some((user, pass)) = &self.auth {
                let mut auth = vec![1, user.len() as u8];
                auth.extend_from_slice(user.as_bytes());
                auth.push(pass.len() as u8);
                auth.extend_from_slice(pass.as_bytes());
                stream.write_all(&auth).await?;
                stream.read_exact(&mut reply).await?;
                if reply[1] != 0 {
                    return Err(self.error("authentication failed".into()));
                }
            }
            let mut request = vec![VERSION, command, 0];
            put_address(&mut request, host, port)?;
            stream.write_all(&request).await?;
            let mut head = [0u8; 3];
            stream.read_exact(&mut head).await?;
            if head[1] != 0 {
                return Err(self.error(format!("server replied {}", reply_text(head[1]))));
            }
            let bound = read_address(&mut stream).await?;
            Ok((stream, bound))
        };
        timeout(CONNECT_TIMEOUT, work)
            .await
            .map_err(|_| self.error("handshake timed out".into()))?
    }

    async fn dial(&self) -> io::Result<TcpStream> {
        let mut last = None;
        for addr in resolve_all(&self.server.0, self.server.1).await? {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::ErrorKind::NotFound.into()))
    }

    fn error(&self, message: String) -> io::Error {
        io::Error::other(format!("socks outbound {:?}: {message}", self.tag))
    }
}

/// One UDP association; each datagram carries the RFC 1928 header.
#[derive(Debug)]
pub struct SocksUdp {
    _control: TcpStream,
    socket: UdpSocket,
}

impl SocksUdp {
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        let mut packet = Vec::with_capacity(data.len() + 22);
        packet.extend_from_slice(&[0, 0, 0]);
        put_address(&mut packet, &Host::Ip(addr.ip()), addr.port())?;
        packet.extend_from_slice(data);
        self.socket.send(&packet).await.map(|_| ())
    }

    /// Writes the payload to the front of `buf`.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let n = self.socket.recv(buf).await?;
            // Fragmented datagrams (non-zero FRAG) are dropped, as RFC 1928 allows.
            let Some((from, offset)) = parse_udp_header(&buf[..n]) else {
                continue;
            };
            buf.copy_within(offset..n, 0);
            return Ok((n - offset, from));
        }
    }
}

fn put_address(out: &mut Vec<u8>, host: &Host, port: u16) -> io::Result<()> {
    match host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            let len = u8::try_from(name.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "domain longer than 255 bytes")
            })?;
            out.extend_from_slice(&[3, len]);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Reads ATYP + address + port; a domain in the reply resolves to the unspecified address.
async fn read_address(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let ip = match stream.read_u8().await? {
        1 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            IpAddr::from(b)
        }
        4 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            IpAddr::from(b)
        }
        3 => {
            let len = stream.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("socks reply has address type {other}"),
            ))
        }
    };
    Ok(SocketAddr::new(ip, stream.read_u16().await?))
}

fn parse_udp_header(packet: &[u8]) -> Option<(SocketAddr, usize)> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let (ip, end) = match packet[3] {
        1 => (
            IpAddr::from(<[u8; 4]>::try_from(packet.get(4..8)?).ok()?),
            8,
        ),
        4 => (
            IpAddr::from(<[u8; 16]>::try_from(packet.get(4..20)?).ok()?),
            20,
        ),
        _ => return None,
    };
    let port = u16::from_be_bytes(packet.get(end..end + 2)?.try_into().ok()?);
    Some((SocketAddr::new(ip, port), end + 2))
}

fn reply_text(code: u8) -> String {
    let text = match code {
        1 => "general failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => return format!("error {code}"),
    };
    text.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_both_setting_forms() {
        let nested = json!({"servers": [{"address": "127.0.0.1", "port": 10109, "users": [{"user": "a", "pass": "b"}]}]});
        let s = SocksOutbound::parse("t", &nested).unwrap();
        assert_eq!(s.server.1, 10109);
        assert_eq!(s.auth, Some(("a".into(), "b".into())));
        let flat =
            SocksOutbound::parse("t", &json!({"address": "proxy.example", "port": 1080})).unwrap();
        assert!(matches!(flat.server.0, Host::Domain(_)));
        assert!(flat.auth.is_none());
        assert!(SocksOutbound::parse("t", &json!({"servers": [{"address": "x"}]})).is_err());
    }

    #[test]
    fn udp_header_round_trip() {
        let mut packet = vec![0, 0, 0];
        put_address(&mut packet, &Host::Ip("::1".parse().unwrap()), 53).unwrap();
        packet.extend_from_slice(b"hi");
        let (from, offset) = parse_udp_header(&packet).unwrap();
        assert_eq!(from, "[::1]:53".parse().unwrap());
        assert_eq!(&packet[offset..], b"hi");
        packet[2] = 1;
        assert!(parse_udp_header(&packet).is_none());
    }
}
