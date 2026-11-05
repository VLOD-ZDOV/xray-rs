//! TCP HTTP header obfuscation (streamSettings.tcpSettings.header: { type: "http" }).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

const MAX_HEADER_SIZE: usize = 16 * 1024;

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

pub async fn accept<S>(mut stream: S, settings: &HttpObfsSettings) -> io::Result<PrefixedStream<S>>
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

    let leftover = header_buf[header_end + 4..].to_vec();

    // Send HTTP response header to client
    stream.write_all(&settings.response).await?;
    stream.flush().await?;

    Ok(PrefixedStream::new(stream, leftover))
}
