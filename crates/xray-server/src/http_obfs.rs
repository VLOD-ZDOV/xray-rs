//! TCP HTTP header obfuscation (streamSettings.tcpSettings.header: { type: "http" }).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

const MAX_HEADER_SIZE: usize = 8192;

#[derive(Clone, Debug)]
pub struct HttpObfsSettings {
    pub response: Vec<u8>,
}

impl Default for HttpObfsSettings {
    fn default() -> Self {
        Self {
            response: b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nPragma: no-cache\r\n\r\n".to_vec(),
        }
    }
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

pub async fn accept<S>(mut stream: S, settings: &HttpObfsSettings) -> io::Result<PrefixedStream<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut header_buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 1024];

    let mut scanned = 0usize;
    let header_end = loop {
        // Only the new bytes plus a possible split terminator need scanning.
        let from = scanned.saturating_sub(3);
        if let Some(pos) = header_buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            break from + pos;
        }
        scanned = header_buf.len();
        if header_buf.len() >= MAX_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tcp http obfs header too large",
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
                "eof reading tcp http obfs header",
            ));
        }
        header_buf.extend_from_slice(&temp[..n]);
    };

    if header_end + 4 > MAX_HEADER_SIZE || !is_request_line(&header_buf[..header_end]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tcp http obfs: not an http request",
        ));
    }

    let leftover = header_buf[header_end + 4..].to_vec();

    // Send HTTP response header to client
    stream.write_all(&settings.response).await?;
    stream.flush().await?;

    Ok(PrefixedStream::new(stream, leftover))
}

/// Checks that the first line looks like `METHOD target HTTP/x.y`.
fn is_request_line(head: &[u8]) -> bool {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !method.is_empty()
        && method.iter().all(u8::is_ascii_uppercase)
        && !target.is_empty()
        && version.starts_with(b"HTTP/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn request_line_check() {
        assert!(is_request_line(b"GET / HTTP/1.1\r\nHost: a"));
        assert!(!is_request_line(b"hello\r\nworld"));
        assert!(!is_request_line(b"GET / HTTP/1.1 x"));
    }

    #[tokio::test]
    async fn rejects_non_http_and_oversized_headers() {
        let (mut c, s) = duplex(64 * 1024);
        c.write_all(b"junk\r\n\r\n").await.unwrap();
        assert!(accept(s, &HttpObfsSettings::default()).await.is_err());

        let (mut c, s) = duplex(64 * 1024);
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.resize(MAX_HEADER_SIZE + 10, b'a');
        c.write_all(&big).await.unwrap();
        assert!(accept(s, &HttpObfsSettings::default()).await.is_err());
    }

    #[tokio::test]
    async fn accepts_split_terminator() {
        let (mut c, s) = duplex(64 * 1024);
        c.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r")
            .await
            .unwrap();
        let h =
            tokio::spawn(async move { accept(s, &HttpObfsSettings::default()).await.map(|_| ()) });
        tokio::task::yield_now().await;
        c.write_all(b"\nbody").await.unwrap();
        assert!(h.await.unwrap().is_ok());
    }
}
