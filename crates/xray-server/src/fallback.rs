//! Fallback routing for VLESS and Trojan when authentication or protocol validation fails.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::config::{Fallback, FallbackDest};
use crate::vless::{copy, relay, Activity, Host};

pub fn find_fallback<'a>(fallbacks: &'a [Fallback], buf: &[u8]) -> Option<&'a Fallback> {
    if fallbacks.is_empty() {
        return None;
    }
    let req_path = extract_http_path(buf);
    if let Some(path) = req_path {
        for fb in fallbacks {
            if !fb.path.is_empty() && path.starts_with(&fb.path) {
                return Some(fb);
            }
        }
    }
    for fb in fallbacks {
        if fb.path.is_empty() {
            return Some(fb);
        }
    }
    fallbacks.first()
}

fn extract_http_path(buf: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(buf).ok()?;
    let line = s.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if matches!(
        method,
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT"
    ) {
        return parts.next();
    }
    None
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
    match &fallback.dest {
        FallbackDest::Tcp(host, port) => {
            let addr_str = match host {
                Host::Ip(ip) => format!("{}:{}", ip, port),
                Host::Domain(d) => format!("{}:{}", d, port),
            };
            let mut dest_stream = TcpStream::connect(&addr_str).await?;
            dest_stream.set_nodelay(true)?;
            write_proxy_header(&mut dest_stream, fallback.xver, peer, inbound_port).await?;
            if !early.is_empty() {
                dest_stream.write_all(&early).await?;
            }
            let (mut dest_r, mut dest_w) = tokio::io::split(dest_stream);
            let activity = Activity::new();
            relay(
                copy(&mut client_r, &mut dest_w, &activity, |_| ()),
                copy(&mut dest_r, &mut client_w, &activity, |_| ()),
                &activity,
            )
            .await
        }
        #[cfg(unix)]
        FallbackDest::Unix(path) => {
            let mut dest_stream = UnixStream::connect(path).await?;
            write_proxy_header(&mut dest_stream, fallback.xver, peer, inbound_port).await?;
            if !early.is_empty() {
                dest_stream.write_all(&early).await?;
            }
            let (mut dest_r, mut dest_w) = tokio::io::split(dest_stream);
            let activity = Activity::new();
            relay(
                copy(&mut client_r, &mut dest_w, &activity, |_| ()),
                copy(&mut dest_r, &mut client_w, &activity, |_| ()),
                &activity,
            )
            .await
        }
    }
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
