//! Fallback routing for VLESS and Trojan when authentication or protocol validation fails.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::config::{Fallback, FallbackDest};
use crate::vless::{copy, relay, Activity, Host};

/// Picks the fallback the way Xray does: an exact `path` match on an HTTP/1 request
/// line, else the entry without a path.
pub fn find_fallback<'a>(fallbacks: &'a [Fallback], first: &[u8]) -> Option<&'a Fallback> {
    request_path(first)
        .and_then(|path| fallbacks.iter().find(|fb| fb.path == path))
        .or_else(|| fallbacks.iter().find(|fb| fb.path.is_empty()))
}

/// Xray's scan: the path starts within bytes 5..=9 and ends at ' ' or '?' before byte 64.
fn request_path(first: &[u8]) -> Option<&str> {
    if first.len() < 18 || first[4] == b'*' {
        return None;
    }
    let start = (4..=8).find(|&i| first[i] == b'/' && first[i - 1] == b' ')?;
    let end = first[start + 1..first.len().min(64)]
        .iter()
        .take_while(|&&k| k != b'\r' && k != b'\n')
        .position(|&k| k == b' ' || k == b'?')?
        + start
        + 1;
    std::str::from_utf8(&first[start..end]).ok()
}

pub async fn serve<R, W>(
    mut client_r: R,
    mut client_w: W,
    fallback: &Fallback,
    early: Vec<u8>,
    peer: SocketAddr,
    inbound_port: u16,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut dest: Box<dyn Stream> = match &fallback.dest {
        FallbackDest::Tcp(host, port) => {
            let stream = match host {
                Host::Ip(ip) => TcpStream::connect((*ip, *port)).await?,
                Host::Domain(name) => TcpStream::connect((name.as_str(), *port)).await?,
            };
            stream.set_nodelay(true)?;
            Box::new(stream)
        }
        FallbackDest::Unix(path) => Box::new(connect_unix(path).await?),
    };
    write_proxy_header(&mut dest, fallback.xver, peer, inbound_port).await?;
    dest.write_all(&early).await?;
    let (mut dest_r, mut dest_w) = tokio::io::split(dest);
    let activity = Activity::new();
    relay(
        copy(&mut client_r, &mut dest_w, &activity, |_| ()),
        copy(&mut dest_r, &mut client_w, &activity, |_| ()),
        &activity,
    )
    .await
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[cfg(target_os = "linux")]
async fn connect_unix(path: &str) -> io::Result<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as UnixAddr, UnixStream as StdUnixStream};

    let name = if let Some(name) = path.strip_prefix("@@") {
        // Go pads the name to the full sun_path, and Xray keeps that for "@@".
        let mut padded = name.as_bytes().to_vec();
        padded.resize(107, 0);
        padded
    } else if let Some(name) = path.strip_prefix('@') {
        name.as_bytes().to_vec()
    } else {
        return UnixStream::connect(path).await;
    };
    let stream = StdUnixStream::connect_addr(&UnixAddr::from_abstract_name(name)?)?;
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

#[cfg(all(unix, not(target_os = "linux")))]
async fn connect_unix(path: &str) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}

async fn write_proxy_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    xver: u8,
    peer: SocketAddr,
    inbound_port: u16,
) -> io::Result<()> {
    match xver {
        1 => {
            let proto = if peer.is_ipv4() { "TCP4" } else { "TCP6" };
            let local_ip = if peer.is_ipv4() { "127.0.0.1" } else { "::1" };
            let line = format!(
                "PROXY {proto} {} {local_ip} {} {}\r\n",
                peer.ip(),
                peer.port(),
                inbound_port
            );
            writer.write_all(line.as_bytes()).await?;
        }
        2 => {
            let sig = b"\r\n\r\n\x00\r\nQUIT\n";
            writer.write_all(sig).await?;
            match peer {
                SocketAddr::V4(v4) => {
                    let mut hdr = [0u8; 16];
                    hdr[0] = 0x21;
                    hdr[1] = 0x11;
                    hdr[2..4].copy_from_slice(&12u16.to_be_bytes());
                    hdr[4..8].copy_from_slice(&v4.ip().octets());
                    hdr[8..12].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
                    hdr[12..14].copy_from_slice(&v4.port().to_be_bytes());
                    hdr[14..16].copy_from_slice(&inbound_port.to_be_bytes());
                    writer.write_all(&hdr).await?;
                }
                SocketAddr::V6(v6) => {
                    let mut hdr = [0u8; 40];
                    hdr[0] = 0x21;
                    hdr[1] = 0x21;
                    hdr[2..4].copy_from_slice(&36u16.to_be_bytes());
                    hdr[4..20].copy_from_slice(&v6.ip().octets());
                    hdr[20..36].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                    hdr[36..38].copy_from_slice(&v6.port().to_be_bytes());
                    hdr[38..40].copy_from_slice(&inbound_port.to_be_bytes());
                    writer.write_all(&hdr).await?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fallback(path: &str, port: u16) -> Fallback {
        Fallback {
            path: path.to_owned(),
            dest: FallbackDest::Tcp(Host::Domain("localhost".into()), port),
            xver: 0,
        }
    }

    #[test]
    fn matches_paths_like_xray() {
        let fbs = [fallback("/ws", 1), fallback("", 2)];
        let pick = |first: &[u8]| find_fallback(&fbs, first).map(|fb| fb.path.as_str());
        assert_eq!(pick(b"GET /ws HTTP/1.1\r\nHost: a\r\n"), Some("/ws"));
        assert_eq!(pick(b"POST /ws?x=1 HTTP/1.1\r\nHost: a\r\n"), Some("/ws"));
        assert_eq!(pick(b"GET /wsx HTTP/1.1\r\nHost: a\r\n"), Some(""));
        assert_eq!(pick(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Some(""));
        assert_eq!(pick(b"\x16\x03\x01\x02\x00"), Some(""));
        assert!(find_fallback(&fbs[..1], b"GET /other HTTP/1.1\r\n\r\n").is_none());
    }
}
