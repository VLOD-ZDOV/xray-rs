//! Capsule Protocol (RFC 9297) and CONNECT-IP (RFC 9484) encapsulation.

use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const CAPSULE_DATAGRAM: u64 = 0;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 2;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

/// Encodes an RFC 9000 variable-length integer into a buffer.
pub fn encode_varint(val: u64, buf: &mut Vec<u8>) {
    if val < 64 {
        buf.push(val as u8);
    } else if val < 16384 {
        buf.extend_from_slice(&((val as u16) | 0x4000).to_be_bytes());
    } else if val < 1073741824 {
        buf.extend_from_slice(&((val as u32) | 0x8000_0000).to_be_bytes());
    } else if val < (1 << 62) {
        buf.extend_from_slice(&(val | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        panic!("varint value overflow: {val}");
    }
}

/// Decodes an RFC 9000 variable-length integer from a slice.
/// Returns (value, bytes_consumed).
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let tag = first >> 6;
    match tag {
        0 => Some(((first & 0x3f) as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return None;
            }
            let val = u16::from_be_bytes([first & 0x3f, buf[1]]);
            Some((val as u64, 2))
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let val = u32::from_be_bytes([first & 0x3f, buf[1], buf[2], buf[3]]);
            Some((val as u64, 4))
        }
        3 => {
            if buf.len() < 8 {
                return None;
            }
            let val = u64::from_be_bytes([
                first & 0x3f,
                buf[1],
                buf[2],
                buf[3],
                buf[4],
                buf[5],
                buf[6],
                buf[7],
            ]);
            Some((val, 8))
        }
        _ => unreachable!(),
    }
}

/// Reads an RFC 9000 variable-length integer asynchronously from a stream.
pub async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    match tag {
        0 => Ok((first[0] & 0x3f) as u64),
        1 => {
            let mut rest = [0u8; 1];
            reader.read_exact(&mut rest).await?;
            let val = u16::from_be_bytes([first[0] & 0x3f, rest[0]]);
            Ok(val as u64)
        }
        2 => {
            let mut rest = [0u8; 3];
            reader.read_exact(&mut rest).await?;
            let val = u32::from_be_bytes([first[0] & 0x3f, rest[0], rest[1], rest[2]]);
            Ok(val as u64)
        }
        3 => {
            let mut rest = [0u8; 7];
            reader.read_exact(&mut rest).await?;
            let val = u64::from_be_bytes([
                first[0] & 0x3f,
                rest[0],
                rest[1],
                rest[2],
                rest[3],
                rest[4],
                rest[5],
                rest[6],
            ]);
            Ok(val)
        }
        _ => unreachable!(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub capsule_type: u64,
    pub value: Vec<u8>,
}

const MAX_CAPSULE_LEN: u64 = 65536 * 2;

/// Reads a single RFC 9297 Capsule from an async reader. Capsules over the
/// length limit are skipped without buffering, as Xray does for unknown and
/// oversized capsules, and the next one is returned.
pub async fn read_capsule<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Capsule> {
    loop {
        let capsule_type = read_varint(reader).await?;
        let length = read_varint(reader).await?;
        if length > MAX_CAPSULE_LEN {
            let skipped =
                tokio::io::copy(&mut (&mut *reader).take(length), &mut tokio::io::sink()).await?;
            if skipped < length {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            continue;
        }
        let mut value = vec![0u8; length as usize];
        reader.read_exact(&mut value).await?;
        return Ok(Capsule {
            capsule_type,
            value,
        });
    }
}

/// Encodes an RFC 9297 Capsule into wire format.
pub fn encode_capsule(capsule_type: u64, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + value.len());
    encode_varint(capsule_type, &mut buf);
    encode_varint(value.len() as u64, &mut buf);
    buf.extend_from_slice(value);
    buf
}

/// Encodes a raw IP packet into an RFC 9484 DATAGRAM Capsule (type 0, context_id 0).
pub fn encode_datagram_capsule(packet: &[u8]) -> Vec<u8> {
    let mut val = Vec::with_capacity(1 + packet.len());
    encode_varint(0, &mut val); // Context ID = 0
    val.extend_from_slice(packet);
    encode_capsule(CAPSULE_DATAGRAM, &val)
}

/// Decodes the payload of a DATAGRAM Capsule, checking that Context ID == 0.
pub fn decode_datagram_value(value: &[u8]) -> Option<&[u8]> {
    let (context_id, offset) = decode_varint(value)?;
    if context_id == 0 {
        Some(&value[offset..])
    } else {
        None
    }
}

/// Encodes an ADDRESS_ASSIGN capsule (type 1).
pub fn encode_address_assign_capsule(addresses: &[(u64, IpAddr, u8)]) -> Vec<u8> {
    let mut val = Vec::new();
    for (req_id, ip, prefix_len) in addresses {
        encode_varint(*req_id, &mut val);
        match ip {
            IpAddr::V4(v4) => {
                val.push(4);
                val.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                val.push(6);
                val.extend_from_slice(&v6.octets());
            }
        }
        val.push(*prefix_len);
    }
    encode_capsule(CAPSULE_ADDRESS_ASSIGN, &val)
}

/// Decodes an ADDRESS_ASSIGN capsule value into a list of (request_id, ip, prefix_len).
pub fn decode_address_assign_value(mut data: &[u8]) -> Result<Vec<(u64, IpAddr, u8)>, String> {
    let mut addrs = Vec::new();
    while !data.is_empty() {
        let (req_id, offset) = decode_varint(data).ok_or("truncated request id")?;
        data = &data[offset..];
        if data.is_empty() {
            return Err("truncated address version".into());
        }
        let version = data[0];
        data = &data[1..];
        let ip = match version {
            4 => {
                if data.len() < 4 {
                    return Err("truncated ipv4 address".into());
                }
                let octets: [u8; 4] = data[..4].try_into().unwrap();
                data = &data[4..];
                IpAddr::V4(octets.into())
            }
            6 => {
                if data.len() < 16 {
                    return Err("truncated ipv6 address".into());
                }
                let octets: [u8; 16] = data[..16].try_into().unwrap();
                data = &data[16..];
                IpAddr::V6(octets.into())
            }
            _ => return Err(format!("unknown ip version {version}")),
        };
        if data.is_empty() {
            return Err("truncated prefix length".into());
        }
        let prefix_len = data[0];
        data = &data[1..];
        let bits: u8 = if ip.is_ipv4() { 32 } else { 128 };
        if prefix_len > bits {
            return Err(format!(
                "prefix length {prefix_len} exceeds IP address length ({bits})"
            ));
        }
        let raw = match ip {
            IpAddr::V4(v) => u128::from(u32::from(v)) << 96,
            IpAddr::V6(v) => u128::from(v),
        };
        let host_mask = u128::MAX.checked_shr(u32::from(prefix_len)).unwrap_or(0);
        if raw & host_mask != 0 {
            return Err("lower bits not covered by prefix length are not all zero".into());
        }
        addrs.push((req_id, ip, prefix_len));
    }
    Ok(addrs)
}

/// Returns the first address that is not a rejected request (0.0.0.0/32 or ::/128).
pub fn first_assigned_ip(addrs: &[(u64, IpAddr, u8)]) -> Option<IpAddr> {
    addrs
        .iter()
        .find(|(_, ip, len)| !(ip.is_unspecified() && *len == if ip.is_ipv4() { 32 } else { 128 }))
        .map(|(_, ip, _)| *ip)
}

/// Encodes a ROUTE_ADVERTISEMENT capsule (type 3).
pub fn encode_route_advertisement_capsule(routes: &[(IpAddr, IpAddr, u8)]) -> Vec<u8> {
    let mut val = Vec::new();
    for (start, end, proto) in routes {
        match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                val.push(4);
                val.extend_from_slice(&s.octets());
                val.extend_from_slice(&e.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                val.push(6);
                val.extend_from_slice(&s.octets());
                val.extend_from_slice(&e.octets());
            }
            _ => panic!("mixed ip versions in route range"),
        }
        val.push(*proto);
    }
    encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &val)
}

/// Default CONNECT-IP request path (RFC 9484 template with both variables set to `*`).
pub const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";

/// Xray's MasqueConfig path handling: URI-template variables become `*`, and
/// the result must be an absolute path without leftover braces.
pub fn normalize_path(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Ok(DEFAULT_PATH.to_owned());
    }
    let path = path
        .replace("{target}", "*")
        .replace("{ipproto}", "*")
        .replace("{?target,ipproto}", "?target=*&ipproto=*")
        .replace("{?ipproto,target}", "?ipproto=*&target=*")
        .replace("{&target,ipproto}", "&target=*&ipproto=*")
        .replace("{&ipproto,target}", "&ipproto=*&target=*");
    if !path.starts_with('/') || path.contains(['{', '}']) {
        return Err(format!(
            "invalid \"path\": {path}, only the variables {{target}} and {{ipproto}} are supported"
        ));
    }
    Ok(path)
}

fn percent_decode(s: &str, plus: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
                continue;
            }
            b'+' if plus => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn parse_query(q: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut m = std::collections::BTreeMap::<String, Vec<String>>::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Some(k), Some(v)) = (percent_decode(k, true), percent_decode(v, true)) {
            m.entry(k).or_default().push(v);
        }
    }
    m
}

/// Xray's pathMatcher: the decoded path and the parsed query must both equal
/// the configured ones.
pub fn path_matches(request: &str, configured: &str) -> bool {
    let split = |s: &str| {
        let (p, q) = s.split_once('?').unwrap_or((s, ""));
        (percent_decode(p, false), parse_query(q))
    };
    let (rp, rq) = split(request);
    let (cp, cq) = split(configured);
    rp.is_some() && rp == cp && rq == cq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_rfc9000_examples() {
        // 37 -> 0x25
        let mut buf = Vec::new();
        encode_varint(37, &mut buf);
        assert_eq!(buf, vec![0x25]);
        assert_eq!(decode_varint(&buf), Some((37, 1)));

        // 15293 -> 0x7bbd
        buf.clear();
        encode_varint(15293, &mut buf);
        assert_eq!(buf, vec![0x7b, 0xbd]);
        assert_eq!(decode_varint(&buf), Some((15293, 2)));

        // 494878333 -> 0x9d7f3e7d
        buf.clear();
        encode_varint(494878333, &mut buf);
        assert_eq!(buf, vec![0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(decode_varint(&buf), Some((494878333, 4)));

        // 15125122882 -> 0xc000000385870f42
        buf.clear();
        encode_varint(15125122882, &mut buf);
        assert_eq!(buf, vec![0xc0, 0x00, 0x00, 0x03, 0x85, 0x87, 0x0f, 0x42]);
        assert_eq!(decode_varint(&buf), Some((15125122882, 8)));
    }

    #[tokio::test]
    async fn test_capsule_roundtrip() {
        let payload = b"hello masque";
        let capsule_bytes = encode_datagram_capsule(payload);

        let mut cursor = std::io::Cursor::new(capsule_bytes);
        let cap = read_capsule(&mut cursor).await.unwrap();
        assert_eq!(cap.capsule_type, CAPSULE_DATAGRAM);

        let decoded = decode_datagram_value(&cap.value).unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn oversized_capsule_is_skipped() {
        let big = vec![7u8; 200_000];
        let mut bytes = encode_capsule(0x99, &big);
        bytes.extend(encode_capsule(CAPSULE_ADDRESS_REQUEST, &[1, 2]));
        let mut cursor = std::io::Cursor::new(bytes);
        let cap = read_capsule(&mut cursor).await.unwrap();
        assert_eq!(cap.capsule_type, CAPSULE_ADDRESS_REQUEST);
        assert_eq!(cap.value, vec![1, 2]);
    }

    #[test]
    fn path_normalize_and_match() {
        assert_eq!(
            normalize_path("/.well-known/masque/ip/{target}/{ipproto}/").unwrap(),
            DEFAULT_PATH
        );
        assert!(normalize_path("masque").is_err());
        assert!(normalize_path("/a/{x}/").is_err());
        assert!(path_matches("/.well-known/masque/ip/*/*/", DEFAULT_PATH));
        assert!(path_matches(
            "/.well-known/masque/ip/%2A/%2A/",
            DEFAULT_PATH
        ));
        assert!(!path_matches("/.well-known/masque/ip/*/*", DEFAULT_PATH));
        assert!(!path_matches("/.well-known/masque/ip/*foo", DEFAULT_PATH));
        assert!(!path_matches(
            "/.well-known/masque/ip/*/*/?x=1",
            DEFAULT_PATH
        ));
    }

    #[test]
    fn address_assign_validation() {
        let bad_len = encode_address_assign_capsule(&[(1, "10.0.0.2".parse().unwrap(), 40)]);
        assert!(decode_address_assign_value(&bad_len[2..]).is_err());
        let host_bits = encode_address_assign_capsule(&[(1, "10.0.0.2".parse().unwrap(), 24)]);
        assert!(decode_address_assign_value(&host_bits[2..]).is_err());
        let ok = [
            (1, "0.0.0.0".parse().unwrap(), 32),
            (2, "10.0.0.2".parse().unwrap(), 32),
        ];
        assert_eq!(first_assigned_ip(&ok), Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_address_assign_roundtrip() {
        let addrs = vec![
            (0, "10.14.0.2".parse().unwrap(), 32),
            (0, "fd14::2".parse().unwrap(), 128),
        ];
        let bytes = encode_address_assign_capsule(&addrs);
        let (_ty, offset) = decode_varint(&bytes).unwrap();
        let (_len, offset2) = decode_varint(&bytes[offset..]).unwrap();
        let value = &bytes[offset + offset2..];

        let decoded = decode_address_assign_value(value).unwrap();
        assert_eq!(decoded, addrs);
    }
}
