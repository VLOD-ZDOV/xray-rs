//! HTTPUpgrade server transport: RFC 7230 Upgrade handshake without WebSocket frames.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout_at;

const MAX_HEADER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUpgradeSettings {
    pub path: String,
    pub host: Option<String>,
}

pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    consumed: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            consumed: 0,
        }
    }

    fn drain_prefix(&mut self, output: &mut ReadBuf<'_>) -> bool {
        if self.consumed >= self.prefix.len() {
            return false;
        }
        let take = (self.prefix.len() - self.consumed).min(output.remaining());
        output.put_slice(&self.prefix[self.consumed..self.consumed + take]);
        self.consumed += take;
        if self.consumed == self.prefix.len() {
            self.prefix = Vec::new();
            self.consumed = 0;
        }
        true
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.drain_prefix(buf) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> xray_proxy::vless::VisionStreamIo for PrefixedStream<S> {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, input)
    }
}

pub async fn accept<S>(
    mut stream: S,
    settings: &HttpUpgradeSettings,
    trusted_xff: &[String],
    peer: std::net::SocketAddr,
) -> io::Result<(PrefixedStream<S>, std::net::SocketAddr)>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut header_buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 1024];
    // One deadline for the whole header, like Xray's absolute read deadline.
    let deadline = tokio::time::Instant::now() + crate::policy::get().handshake;

    let header_end = loop {
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if header_buf.len() >= MAX_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "httpupgrade header too large",
            ));
        }
        let n = match timeout_at(deadline, stream.read(&mut temp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout")),
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof reading httpupgrade header",
            ));
        }
        header_buf.extend_from_slice(&temp[..n]);
    };

    let leftover = header_buf[header_end + 4..].to_vec();
    let header_str = std::str::from_utf8(&header_buf[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8 http header"))?;

    let mut lines = header_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty request line"))?;

    // Like Xray, every rejection closes the connection without a reply.
    let req_path = req_line.split_whitespace().nth(1).unwrap_or_default();
    let target_path = req_path.split('?').next().unwrap_or("/");

    let mut connection = None;
    let mut upgrade_hdr = None;
    let mut host_hdr = None;
    let mut sec_key = None;
    let mut header_pairs = Vec::new();

    for line in lines {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        header_pairs.push((key, val));

        let slot = if key.eq_ignore_ascii_case("connection") {
            &mut connection
        } else if key.eq_ignore_ascii_case("upgrade") {
            &mut upgrade_hdr
        } else if key.eq_ignore_ascii_case("host") {
            &mut host_hdr
        } else if key.eq_ignore_ascii_case("sec-websocket-key") {
            &mut sec_key
        } else {
            continue;
        };
        if slot.is_none() {
            *slot = Some(val.to_owned());
        }
    }

    let peer = crate::sockopt::apply_trusted_x_forwarded_for_raw(header_pairs, trusted_xff, peer);

    if let Some(expected_host) = &settings.host {
        let h = host_hdr.unwrap_or_default();
        if !is_valid_http_host(&h, expected_host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "httpupgrade host mismatch: got {}, expected {expected_host}",
                    h.escape_debug()
                ),
            ));
        }
    }

    if target_path != settings.path {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "httpupgrade path mismatch: got {}, expected {}",
                target_path.escape_debug(),
                settings.path
            ),
        ));
    }

    let is_upgrade = connection.is_some_and(|c| c.eq_ignore_ascii_case("upgrade"))
        && upgrade_hdr.is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
    if !is_upgrade {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unrecognized httpupgrade request",
        ));
    }

    let mut resp = String::from("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n");
    if let Some(key) = sec_key.filter(|k| !k.is_empty()) {
        resp.push_str(&format!(
            "Sec-WebSocket-Accept: {}\r\n",
            crate::ws::accept_key_for(&key)
        ));
    }
    resp.push_str("Upgrade: websocket\r\n\r\n");
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    Ok((PrefixedStream::new(stream, leftover), peer))
}

/// Mirrors Xray's internet.IsValidHTTPHost.
pub(crate) fn is_valid_http_host(request: &str, config: &str) -> bool {
    let r = request.to_ascii_lowercase();
    let c = config.to_ascii_lowercase();
    if r.contains(':') {
        return split_host_port(&r).is_some_and(|h| h == c);
    }
    r == c
}

fn split_host_port(s: &str) -> Option<&str> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let tail = rest[end + 1..].strip_prefix(':')?;
        if tail.contains(':') {
            return None;
        }
        return Some(&rest[..end]);
    }
    let i = s.rfind(':')?;
    let host = &s[..i];
    if host.contains([':', '[', ']']) {
        return None;
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_validation_matches_xray() {
        assert!(is_valid_http_host("Example.com", "example.com"));
        assert!(is_valid_http_host("example.com:443", "example.com"));
        assert!(is_valid_http_host("[::1]:443", "::1"));
        assert!(!is_valid_http_host("::1", "::1"));
        assert!(!is_valid_http_host("other.com", "example.com"));
        assert!(!is_valid_http_host("", "example.com"));
    }
}
