//! Inbound Trojan protocol handler (RFC Trojan proxy with TCP connect and UDP framing).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::PoisonError;

use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use xray_config::Network;
use xray_proxy::trojan::{decode_udp_packet, encode_udp_packet, UdpPacket, WireError};
use xray_routing::{Target, TargetAddr};

use crate::config::User;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, BlockAction};
use crate::stats;
use crate::vless::{read_first, Activity, Context, Host, RouteRequest};

const MAX_HEADER: usize = 56 + 2 + 1 + 1 + 255 + 2 + 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub user_index: usize,
    pub command: Command,
    pub host: Host,
    pub port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Incomplete,
    Invalid(&'static str),
}

/// The lowercase hex SHA-224 token of a password.
pub fn trojan_password_hash(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut token = [0u8; 56];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in digest.iter().enumerate() {
        token[2 * i] = HEX[(byte >> 4) as usize];
        token[2 * i + 1] = HEX[(byte & 0x0f) as usize];
    }
    token
}

/// Parses a Trojan request header from the incoming byte buffer.
pub fn parse_request(buf: &[u8], users: &[User]) -> Result<(Request, usize), ParseError> {
    if buf.len() < 58 {
        return Err(ParseError::Incomplete);
    }
    let token = &buf[..56];
    if &buf[56..58] != b"\r\n" {
        return Err(ParseError::Invalid("invalid password delimiter"));
    }
    let user_index = users
        .iter()
        .position(|u| u.hash.eq_ignore_ascii_case(token))
        .ok_or(ParseError::Invalid("unknown user"))?;

    let mut pos = 58;
    if buf.len() <= pos {
        return Err(ParseError::Incomplete);
    }
    let cmd = buf[pos];
    pos += 1;
    let command = match cmd {
        1 => Command::Tcp,
        3 => Command::Udp,
        _ => return Err(ParseError::Invalid("unsupported command")),
    };

    if buf.len() <= pos {
        return Err(ParseError::Incomplete);
    }
    let atype = buf[pos];
    pos += 1;
    let host = match atype {
        1 => {
            if buf.len() < pos + 4 {
                return Err(ParseError::Incomplete);
            }
            let bytes: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
            pos += 4;
            Host::Ip(IpAddr::from(bytes))
        }
        3 => {
            if buf.len() <= pos {
                return Err(ParseError::Incomplete);
            }
            let len = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + len {
                return Err(ParseError::Incomplete);
            }
            let name = std::str::from_utf8(&buf[pos..pos + len])
                .map_err(|_| ParseError::Invalid("bad domain"))?;
            pos += len;
            match name.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Domain(name.to_owned()),
            }
        }
        4 => {
            if buf.len() < pos + 16 {
                return Err(ParseError::Incomplete);
            }
            let bytes: [u8; 16] = buf[pos..pos + 16].try_into().unwrap();
            pos += 16;
            Host::Ip(IpAddr::from(bytes))
        }
        _ => return Err(ParseError::Invalid("unknown address type")),
    };

    if buf.len() < pos + 2 {
        return Err(ParseError::Incomplete);
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    if buf.len() < pos + 2 {
        return Err(ParseError::Incomplete);
    }
    if &buf[pos..pos + 2] != b"\r\n" {
        return Err(ParseError::Invalid("invalid header delimiter"));
    }
    pos += 2;

    Ok((
        Request {
            user_index,
            command,
            host,
            port,
        },
        pos,
    ))
}

pub async fn serve<R, W>(
    mut uplink: R,
    mut downlink: W,
    ctx: &Context,
    peer: SocketAddr,
    tls: &crate::fallback::TlsInfo,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let handshake_res = timeout(crate::policy::get().handshake, async {
        let mut chunk = [0u8; 512];
        loop {
            let parsed = {
                let users = ctx.users.read().unwrap_or_else(PoisonError::into_inner);
                parse_request(&buf, &users).map(|(request, len)| {
                    let user = users[request.user_index].clone();
                    (request, len, user)
                })
            };
            match parsed {
                Ok(parsed) => return Ok(parsed),
                Err(ParseError::Invalid(reason)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                }
                Err(ParseError::Incomplete) if buf.len() > MAX_HEADER => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trojan header too long",
                    ));
                }
                Err(ParseError::Incomplete) => {}
            }
            let n = uplink.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await;

    let (mut request, header_len, user) = match handshake_res {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(_)) => {
            if let Some(fb) = crate::fallback::find_fallback(&ctx.fallbacks, tls, &buf) {
                return crate::fallback::serve(uplink, downlink, fb, buf, peer, ctx.port).await;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trojan handshake failed",
            ));
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "trojan handshake timeout",
            ));
        }
    };

    let mut early = buf.split_off(header_len);
    let user_policy = crate::policy::for_level(user.level);
    let _online = stats::get().connect(&user.email, user.level, peer.ip());

    let network = match request.command {
        Command::Tcp => Network::Tcp,
        Command::Udp => Network::Udp,
    };

    if network == Network::Tcp
        && early.is_empty()
        && (ctx.router.needs_sniff() || ctx.sniffing.enabled())
    {
        read_first(&mut uplink, &mut early).await;
    }

    let payload = if network == Network::Udp {
        decode_udp_packet(&early)
            .map(|(packet, _)| packet.payload)
            .unwrap_or_default()
    } else {
        &early[..]
    };

    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: &user.email,
        peer,
        network,
        host: &request.host,
        port: request.port,
        sniffing: &ctx.sniffing,
    };

    let Some(decision) = route.allow(&ctx.router, payload).await else {
        return Ok(());
    };

    ctx.sniffing.override_host(payload, &mut request.host);

    if let Action::Block(BlockAction::Http403) = decision.action {
        if request.command == Command::Tcp {
            downlink
                .write_all(crate::routing::BLACKHOLE_HTTP_RESPONSE)
                .await?;
            downlink.flush().await?;
        }
        return Ok(());
    }

    let traffic = stats::get().traffic(&ctx.tag, &user.email, user.level, &decision.tag);

    match request.command {
        Command::Tcp => {
            let stream =
                outbound::connect(&ctx.router, &decision, &request.host, request.port).await?;
            let (mut target_r, mut target_w) = tokio::io::split(stream);
            target_w.write_all(&early).await?;
            traffic.up(early.len());
            let activity = Activity::new();
            crate::vless::relay_policy(
                crate::vless::copy_buf(
                    &mut uplink,
                    &mut target_w,
                    &activity,
                    |n| traffic.up(n),
                    user_policy.buffer_size,
                ),
                crate::vless::copy_buf(
                    &mut target_r,
                    &mut downlink,
                    &activity,
                    |n| traffic.down(n),
                    user_policy.buffer_size,
                ),
                &activity,
                user_policy,
            )
            .await
        }
        Command::Udp => {
            let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
            let activity = Activity::new();

            let up = async {
                let mut in_buf = early;
                let mut temp = [0u8; 8192];
                loop {
                    activity.touch();
                    // Process any full Trojan UDP packets currently in in_buf
                    while !in_buf.is_empty() {
                        match decode_udp_packet(&in_buf) {
                            Ok((packet, used)) => {
                                let (host, port) = match &packet.target.addr {
                                    TargetAddr::Ip(ip) => (Host::Ip(*ip), packet.target.port),
                                    TargetAddr::Domain(d) => {
                                        (Host::Domain(d.clone()), packet.target.port)
                                    }
                                };
                                let target_addr = cone.target(&host, port).await?;
                                cone.send_to(packet.payload, target_addr).await?;
                                traffic.up(packet.payload.len());
                                in_buf.drain(..used);
                            }
                            Err(WireError::Incomplete) => break,
                            Err(e) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("trojan udp decode: {e}"),
                                ));
                            }
                        }
                    }
                    let n = timeout(user_policy.conn_idle, uplink.read(&mut temp))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                    if n == 0 {
                        break;
                    }
                    in_buf.extend_from_slice(&temp[..n]);
                }
                Ok::<(), io::Error>(())
            };

            let down = async {
                let mut buf = vec![0u8; 65535];
                loop {
                    activity.touch();
                    let (n, from) = timeout(user_policy.conn_idle, cone.recv_from(&mut buf))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle"))??;
                    let target = Target::new(
                        TargetAddr::Ip(from.ip()),
                        from.port(),
                        xray_routing::Network::Udp,
                    );
                    let wire = encode_udp_packet(&UdpPacket {
                        target,
                        payload: &buf[..n],
                    })
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("trojan udp encode: {e}"),
                        )
                    })?;
                    downlink.write_all(&wire).await?;
                    downlink.flush().await?;
                    traffic.down(n);
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };

            crate::vless::relay_policy(up, down, &activity, user_policy).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_matches_sha224_hex() {
        let hash = trojan_password_hash("password");
        assert_eq!(
            std::str::from_utf8(&hash).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn parses_valid_trojan_tcp_domain_request() {
        let user = User {
            id: [0; 16],
            hash: trojan_password_hash("secret"),
            email: "alice@example.com".into(),
            level: 0,
            flow: String::new(),
        };
        let mut wire = Vec::new();
        wire.extend_from_slice(&user.hash);
        wire.extend_from_slice(b"\r\n");
        wire.push(1); // Command::Tcp
        wire.push(3); // Domain address
        wire.push(11); // len("example.com")
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&443u16.to_be_bytes());
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");

        let (req, len) = parse_request(&wire, &[user]).unwrap();
        assert_eq!(req.user_index, 0);
        assert_eq!(req.command, Command::Tcp);
        assert_eq!(req.host, Host::Domain("example.com".into()));
        assert_eq!(req.port, 443);
        assert_eq!(&wire[len..], b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn parses_valid_trojan_udp_ipv4_request() {
        let user = User {
            id: [0; 16],
            hash: trojan_password_hash("secret"),
            email: "bob@example.com".into(),
            level: 0,
            flow: String::new(),
        };
        let mut wire = Vec::new();
        wire.extend_from_slice(&user.hash);
        wire.extend_from_slice(b"\r\n");
        wire.push(3); // Command::Udp
        wire.push(1); // IPv4
        wire.extend_from_slice(&[8, 8, 8, 8]);
        wire.extend_from_slice(&53u16.to_be_bytes());
        wire.extend_from_slice(b"\r\n");

        let (req, len) = parse_request(&wire, &[user]).unwrap();
        assert_eq!(req.user_index, 0);
        assert_eq!(req.command, Command::Udp);
        assert_eq!(req.host, Host::Ip("8.8.8.8".parse().unwrap()));
        assert_eq!(req.port, 53);
        assert_eq!(len, wire.len());
    }

    #[test]
    fn rejects_unknown_user_or_invalid_delimiter() {
        let user = User {
            id: [0; 16],
            hash: trojan_password_hash("secret"),
            email: "bob@example.com".into(),
            level: 0,
            flow: String::new(),
        };
        let mut wire = Vec::new();
        wire.extend_from_slice(&[b'a'; 56]);
        wire.extend_from_slice(b"\r\n");
        wire.push(1);
        wire.push(1);
        wire.extend_from_slice(&[127, 0, 0, 1]);
        wire.extend_from_slice(&80u16.to_be_bytes());
        wire.extend_from_slice(b"\r\n");

        assert_eq!(
            parse_request(&wire, &[user]),
            Err(ParseError::Invalid("unknown user"))
        );
    }
}
