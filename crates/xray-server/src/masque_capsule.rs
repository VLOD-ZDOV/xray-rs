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

/// Reads a single RFC 9297 Capsule from an async reader.
pub async fn read_capsule<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Capsule> {
    let capsule_type = read_varint(reader).await?;
    let length = read_varint(reader).await?;
    if length > 65536 * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capsule exceeds maximum allowed length",
        ));
    }
    let mut value = vec![0u8; length as usize];
    reader.read_exact(&mut value).await?;
    Ok(Capsule {
        capsule_type,
        value,
    })
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
        addrs.push((req_id, ip, prefix_len));
    }
    Ok(addrs)
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
