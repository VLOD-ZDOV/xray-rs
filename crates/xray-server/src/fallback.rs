//! Fallback routing for VLESS and Trojan when authentication or protocol validation fails.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::config::{Fallback, FallbackDest};
use crate::vless::{copy, relay, Activity, Host};

/// SNI and ALPN of the TLS or REALITY handshake, lowercased as Xray reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsInfo {
    pub name: String,
    pub alpn: String,
    /// TLS 1.3 or REALITY right on the connection, which XTLS Vision needs.
    pub vision_capable: bool,
}

impl TlsInfo {
    pub fn new(name: &str, alpn: &[u8]) -> Self {
        Self {
            name: name.to_ascii_lowercase(),
            alpn: String::from_utf8_lossy(alpn).to_ascii_lowercase(),
            vision_capable: true,
        }
    }
}

type PathMap<'a> = HashMap<&'a str, &'a Fallback>;
type AlpnMap<'a> = HashMap<&'a str, PathMap<'a>>;

/// Picks the fallback as Xray's VLESS and Trojan inbounds do: by `name`
/// (the longest one the SNI contains), then `alpn`, then the request
/// `path`, each falling back to the empty entry. Entries without a name or
/// alpn fill the gaps of the others, as Xray merges its fallback maps.
pub fn find_fallback<'a>(
    fallbacks: &'a [Fallback],
    tls: &TlsInfo,
    first: &[u8],
) -> Option<&'a Fallback> {
    let mut napfb: HashMap<&str, AlpnMap<'a>> = HashMap::new();
    for fb in fallbacks {
        napfb
            .entry(fb.name.as_str())
            .or_default()
            .entry(fb.alpn.as_str())
            .or_default()
            .insert(fb.path.as_str(), fb);
    }
    let default = napfb.get("").cloned();
    if let Some(default) = &default {
        for (_, apfb) in napfb.iter_mut().filter(|(n, _)| !n.is_empty()) {
            for alpn in default.keys() {
                apfb.entry(alpn).or_default();
            }
        }
    }
    for apfb in napfb.values_mut() {
        if let Some(any_alpn) = apfb.get("").cloned() {
            for (_, pfb) in apfb.iter_mut().filter(|(a, _)| !a.is_empty()) {
                for (path, fb) in &any_alpn {
                    pfb.entry(path).or_insert(fb);
                }
            }
        }
    }
    // Xray reads the unnamed entries again here, after the step above filled them.
    let default = napfb.get("").cloned();
    if let Some(default) = &default {
        for (_, apfb) in napfb.iter_mut().filter(|(n, _)| !n.is_empty()) {
            for (alpn, pfb) in default {
                let target = apfb.entry(alpn).or_default();
                for (path, fb) in pfb {
                    target.entry(path).or_insert(fb);
                }
            }
        }
    }

    let mut name = tls.name.as_str();
    if (napfb.len() > 1 || !napfb.contains_key("")) && !name.is_empty() && !napfb.contains_key(name)
    {
        name = napfb
            .keys()
            .filter(|n| !n.is_empty() && tls.name.contains(**n))
            .max_by_key(|n| n.len())
            .copied()
            .unwrap_or("");
    }
    let apfb = napfb.get(name).or_else(|| napfb.get(""))?;
    let pfb = apfb.get(tls.alpn.as_str()).or_else(|| apfb.get(""))?;
    let path = if pfb.len() > 1 || !pfb.contains_key("") {
        request_path(first)
            .filter(|p| pfb.contains_key(p))
            .unwrap_or("")
    } else {
        ""
    };
    pfb.get(path).copied()
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
            // Xray: retry.ExponentialBackoff(5, 100)
            let mut delay = Duration::from_millis(100);
            let mut attempt = 1;
            let stream = loop {
                let connected = match host {
                    Host::Ip(ip) => TcpStream::connect((*ip, *port)).await,
                    Host::Domain(name) => TcpStream::connect((name.as_str(), *port)).await,
                };
                match connected {
                    Ok(stream) => break stream,
                    Err(e) if attempt >= 5 => return Err(e),
                    Err(_) => {
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        attempt += 1;
                    }
                }
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

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[cfg(target_os = "linux")]
pub(crate) async fn connect_unix(path: &str) -> io::Result<UnixStream> {
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
    // A full backlog blocks connect(2), so keep it off the async workers.
    let stream = tokio::task::spawn_blocking(move || {
        StdUnixStream::connect_addr(&UnixAddr::from_abstract_name(name)?)
    })
    .await
    .map_err(io::Error::other)??;
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) async fn connect_unix(path: &str) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}

#[cfg(not(unix))]
pub(crate) async fn connect_unix(_: &str) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unix sockets are not supported on this platform",
    ))
}

pub(crate) async fn write_proxy_header<W: AsyncWrite + Unpin>(
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
            name: String::new(),
            alpn: String::new(),
            path: path.to_owned(),
            dest: FallbackDest::Tcp(Host::Domain("localhost".into()), port),
            xver: 0,
        }
    }

    #[test]
    fn matches_paths_like_xray() {
        let fbs = [fallback("/ws", 1), fallback("", 2)];
        let none = TlsInfo::default();
        let pick = |first: &[u8]| find_fallback(&fbs, &none, first).map(|fb| fb.path.as_str());
        assert_eq!(pick(b"GET /ws HTTP/1.1\r\nHost: a\r\n"), Some("/ws"));
        assert_eq!(pick(b"POST /ws?x=1 HTTP/1.1\r\nHost: a\r\n"), Some("/ws"));
        assert_eq!(pick(b"GET /wsx HTTP/1.1\r\nHost: a\r\n"), Some(""));
        assert_eq!(pick(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Some(""));
        assert_eq!(pick(b"\x16\x03\x01\x02\x00"), Some(""));
        assert!(find_fallback(&fbs[..1], &none, b"GET /other HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn matches_name_and_alpn_like_xray() {
        let entry = |name: &str, alpn: &str, path: &str, port| Fallback {
            name: name.into(),
            alpn: alpn.into(),
            ..fallback(path, port)
        };
        let fbs = [
            entry("", "", "", 1),
            entry("", "h2", "", 2),
            entry("a.example", "", "", 3),
            entry("example", "", "/ws", 4),
        ];
        let port = |name: &str, alpn: &[u8], first: &[u8]| match find_fallback(
            &fbs,
            &TlsInfo::new(name, alpn),
            first,
        )
        .map(|fb| &fb.dest)
        {
            Some(FallbackDest::Tcp(_, port)) => *port,
            other => panic!("unexpected {other:?}"),
        };
        let get = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(port("", b"", get), 1);
        assert_eq!(port("", b"h2", get), 2);
        // The longest name the SNI contains wins. Its own alpn "" entry fills its
        // h2 gap before the unnamed entries do, as in Xray's merge order.
        assert_eq!(port("A.Example", b"", get), 3);
        assert_eq!(port("x.a.example.com", b"h2", get), 3);
        assert_eq!(port("b.example", b"", b"GET /ws HTTP/1.1\r\n\r\n"), 4);
        assert_eq!(port("b.example", b"", get), 1);
        assert_eq!(port("other.net", b"http/1.1", get), 1);

        // An alpn entry with only a path gets the unnamed alpn "" entry, and named
        // entries see that merged result.
        let fbs = [
            entry("", "", "", 1),
            entry("", "http/1.1", "/api", 5),
            entry("example", "", "/ws", 4),
        ];
        let pick = |name: &str| match find_fallback(&fbs, &TlsInfo::new(name, b"http/1.1"), get) {
            Some(fb) => fb.path.clone(),
            None => "none".into(),
        };
        assert_eq!(pick("b.example"), "");
    }
}
