use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const PROXY_V2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
pub const PROXY_V1_PREFIX: &[u8; 6] = b"PROXY ";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolAccept {
    #[default]
    None,
    V1,
    V2,
    Any,
}

impl ProxyProtocolAccept {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Reads and decodes a PROXY protocol v1 or v2 header from an incoming stream.
/// Returns the updated client address and any leftover bytes read beyond the header.
pub async fn read_proxy_header<S>(
    stream: &mut S,
    mode: ProxyProtocolAccept,
    original_peer: SocketAddr,
) -> io::Result<(SocketAddr, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    if !mode.is_enabled() {
        return Ok((original_peer, Vec::new()));
    }

    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 128];

    loop {
        // Check if we can already parse a v2 header
        if buf.len() >= 16 && buf.starts_with(PROXY_V2_SIGNATURE) {
            if matches!(mode, ProxyProtocolAccept::V1) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "received PROXY protocol v2 but only v1 is accepted",
                ));
            }
            let total_len = 16 + (u16::from_be_bytes([buf[14], buf[15]]) as usize);
            if buf.len() >= total_len {
                let peer = parse_v2_header(&buf[..total_len], original_peer)?;
                let leftover = buf[total_len..].to_vec();
                return Ok((peer, leftover));
            }
        } else if buf.starts_with(b"PROXY ") {
            if matches!(mode, ProxyProtocolAccept::V2) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "received PROXY protocol v1 but only v2 is accepted",
                ));
            }
            if let Some(pos) = find_crlf(&buf) {
                let peer = parse_v1_header(&buf[..pos], original_peer)?;
                let leftover = buf[pos + 2..].to_vec();
                return Ok((peer, leftover));
            }
            if buf.len() > 108 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY protocol v1 header exceeds 108 bytes",
                ));
            }
        } else if buf.len() >= 12
            && !buf.starts_with(PROXY_V2_SIGNATURE)
            && !PROXY_V1_PREFIX.starts_with(&buf[..buf.len().min(6)])
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol header signature",
            ));
        }

        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while reading PROXY protocol header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn parse_v1_header(line_bytes: &[u8], original_peer: SocketAddr) -> io::Result<SocketAddr> {
    let line = std::str::from_utf8(line_bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid UTF-8 in PROXY v1 header: {e}"),
        )
    })?;

    let parts: Vec<&str> = line.split(' ').collect();
    if parts.is_empty() || parts[0] != "PROXY" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing PROXY prefix",
        ));
    }

    match parts.get(1).copied() {
        Some("UNKNOWN") => Ok(original_peer),
        Some("TCP4") | Some("TCP6") => {
            if parts.len() < 6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY v1 line has too few fields",
                ));
            }
            let src_ip: IpAddr = parts[2].parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid src IP in PROXY v1: {e}"),
                )
            })?;
            let src_port: u16 = parts[4].parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid src port in PROXY v1: {e}"),
                )
            })?;
            Ok(SocketAddr::new(src_ip, src_port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PROXY v1 protocol family",
        )),
    }
}

fn parse_v2_header(header: &[u8], original_peer: SocketAddr) -> io::Result<SocketAddr> {
    if header.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v2 header too short",
        ));
    }
    let ver_cmd = header[12];
    let fam_proto = header[13];

    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported PROXY protocol version {version}"),
        ));
    }

    let cmd = ver_cmd & 0x0f;
    if cmd == 0 {
        // LOCAL command: keep original peer
        return Ok(original_peer);
    }
    if cmd != 1 {
        // PROXY command is 1
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported PROXY v2 command {cmd}"),
        ));
    }

    let family = fam_proto >> 4;
    match family {
        0 => Ok(original_peer), // AF_UNSPEC
        1 => {
            // AF_INET (IPv4)
            if header.len() < 28 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY v2 IPv4 address block truncated",
                ));
            }
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&header[16..20]);
            let port = u16::from_be_bytes([header[24], header[25]]);
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip_bytes),
                port,
            )))
        }
        2 => {
            // AF_INET6 (IPv6)
            if header.len() < 52 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY v2 IPv6 address block truncated",
                ));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&header[16..32]);
            let port = u16::from_be_bytes([header[48], header[49]]);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip_bytes),
                port,
                0,
                0,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported PROXY v2 address family {family}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn parses_v1_tcp4_with_leftover() {
        let input = b"PROXY TCP4 198.51.100.1 203.0.113.1 54321 443\r\nGET / HTTP/1.1\r\n";
        let mut cursor = Cursor::new(input.to_vec());
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let (peer, leftover) = read_proxy_header(&mut cursor, ProxyProtocolAccept::Any, fallback)
            .await
            .unwrap();
        assert_eq!(peer, "198.51.100.1:54321".parse::<SocketAddr>().unwrap());
        assert_eq!(leftover, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn parses_v1_tcp6() {
        let input = b"PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n";
        let mut cursor = Cursor::new(input.to_vec());
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let (peer, leftover) = read_proxy_header(&mut cursor, ProxyProtocolAccept::V1, fallback)
            .await
            .unwrap();
        assert_eq!(peer, "[2001:db8::1]:54321".parse::<SocketAddr>().unwrap());
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn parses_v1_unknown() {
        let input = b"PROXY UNKNOWN\r\n";
        let mut cursor = Cursor::new(input.to_vec());
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let (peer, leftover) = read_proxy_header(&mut cursor, ProxyProtocolAccept::V1, fallback)
            .await
            .unwrap();
        assert_eq!(peer, fallback);
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn parses_v2_ipv4_with_tlv_and_leftover() {
        let mut input = Vec::new();
        input.extend_from_slice(PROXY_V2_SIGNATURE);
        input.push(0x21); // version 2, PROXY command
        input.push(0x11); // AF_INET, STREAM
        input.extend_from_slice(&16u16.to_be_bytes()); // 12 bytes addr + 4 bytes dummy TLV
        input.extend_from_slice(&[198, 51, 100, 2]); // src ip
        input.extend_from_slice(&[203, 0, 113, 2]); // dst ip
        input.extend_from_slice(&43210u16.to_be_bytes()); // src port
        input.extend_from_slice(&443u16.to_be_bytes()); // dst port
        input.extend_from_slice(&[0x01, 0x00, 0x01, 0xaa]); // TLV
        input.extend_from_slice(b"hello world");

        let mut cursor = Cursor::new(input);
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let (peer, leftover) = read_proxy_header(&mut cursor, ProxyProtocolAccept::Any, fallback)
            .await
            .unwrap();
        assert_eq!(peer, "198.51.100.2:43210".parse::<SocketAddr>().unwrap());
        assert_eq!(leftover, b"hello world");
    }

    #[tokio::test]
    async fn parses_v2_ipv6() {
        let mut input = Vec::new();
        input.extend_from_slice(PROXY_V2_SIGNATURE);
        input.push(0x21); // version 2, PROXY command
        input.push(0x21); // AF_INET6, STREAM
        input.extend_from_slice(&36u16.to_be_bytes()); // 36 bytes addr
        let src_ip: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let dst_ip: Ipv6Addr = "2001:db8::20".parse().unwrap();
        input.extend_from_slice(&src_ip.octets());
        input.extend_from_slice(&dst_ip.octets());
        input.extend_from_slice(&12345u16.to_be_bytes());
        input.extend_from_slice(&443u16.to_be_bytes());

        let mut cursor = Cursor::new(input);
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let (peer, leftover) = read_proxy_header(&mut cursor, ProxyProtocolAccept::V2, fallback)
            .await
            .unwrap();
        assert_eq!(peer, "[2001:db8::10]:12345".parse::<SocketAddr>().unwrap());
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn parses_v2_local() {
        let mut input = Vec::new();
        input.extend_from_slice(PROXY_V2_SIGNATURE);
        input.push(0x20); // version 2, LOCAL command
        input.push(0x00); // AF_UNSPEC
        input.extend_from_slice(&0u16.to_be_bytes());

        let mut cursor = Cursor::new(input);
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let (peer, leftover) = read_proxy_header(&mut cursor, ProxyProtocolAccept::V2, fallback)
            .await
            .unwrap();
        assert_eq!(peer, fallback);
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn rejects_mismatched_version() {
        let input = b"PROXY TCP4 198.51.100.1 203.0.113.1 54321 443\r\n";
        let mut cursor = Cursor::new(input.to_vec());
        let fallback: SocketAddr = "127.0.0.1:80".parse().unwrap();

        let result = read_proxy_header(&mut cursor, ProxyProtocolAccept::V2, fallback).await;
        assert!(result.is_err());
    }
}
