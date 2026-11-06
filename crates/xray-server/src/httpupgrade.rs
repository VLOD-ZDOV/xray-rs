//! HTTPUpgrade server transport: RFC 7230 Upgrade handshake without WebSocket frames.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

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
) -> io::Result<PrefixedStream<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut header_buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 1024];

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
        let n = match timeout(crate::policy::get().handshake, stream.read(&mut temp)).await {
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

    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next().unwrap_or_default();
    let req_path = req_parts.next().unwrap_or_default();

    if !method.eq_ignore_ascii_case("GET") {
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("method {method} not allowed for httpupgrade"),
        ));
    }

    let target_path = req_path.split('?').next().unwrap_or("/");
    let clean_target = normalize_path(target_path);
    let clean_config = normalize_path(&settings.path);

    if clean_target != clean_config {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "httpupgrade path mismatch: got {target_path}, expected {}",
                settings.path
            ),
        ));
    }

    let mut connection_ok = false;
    let mut upgrade_hdr = None;
    let mut host_hdr = None;

    for line in lines {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();

        if key.eq_ignore_ascii_case("connection") && val.to_ascii_lowercase().contains("upgrade") {
            connection_ok = true;
        } else if key.eq_ignore_ascii_case("upgrade") {
            upgrade_hdr = Some(val.to_owned());
        } else if key.eq_ignore_ascii_case("host") {
            host_hdr = Some(val.to_owned());
        }
    }

    if let Some(expected_host) = &settings.host {
        let h = host_hdr.unwrap_or_default();
        let host_only = h.split(':').next().unwrap_or("");
        if !host_only.eq_ignore_ascii_case(expected_host) {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("httpupgrade host mismatch: got {host_only}, expected {expected_host}"),
            ));
        }
    }

    let Some(upgrade_proto) = upgrade_hdr else {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Upgrade header",
        ));
    };

    if !connection_ok {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Connection: upgrade header",
        ));
    }

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {upgrade_proto}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    Ok(PrefixedStream::new(stream, leftover))
}

fn normalize_path(p: &str) -> &str {
    let stripped = p.trim_end_matches('/');
    if stripped.is_empty() {
        "/"
    } else {
        stripped
    }
}
