use std::io::{self, IoSlice, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;
use xray_proxy::vless::VisionStreamIo;

const TLS_READ_CHUNK_LIMIT: usize = 8 * 1024;

pub struct CapturedStream<S> {
    stream: S,
    tls_read_limiter: TlsRecordReadLimiter,
    limiter_released: bool,
}

impl<S> CapturedStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            tls_read_limiter: TlsRecordReadLimiter::new(),
            limiter_released: false,
        }
    }

    pub fn release_record_alignment(&mut self) {
        self.limiter_released = true;
    }
}

struct TlsRecordReadLimiter {
    header: [u8; 5],
    header_len: usize,
    payload_remaining: usize,
}

impl TlsRecordReadLimiter {
    fn new() -> Self {
        Self {
            header: [0; 5],
            header_len: 0,
            payload_remaining: 0,
        }
    }

    fn next_limit(&self, requested: usize) -> usize {
        if self.header_len < self.header.len() {
            requested.min(self.header.len() - self.header_len)
        } else {
            requested.min(self.payload_remaining)
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        if self.header_len < self.header.len() {
            let len = (self.header.len() - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + len].copy_from_slice(&bytes[..len]);
            self.header_len += len;
            if self.header_len == self.header.len() {
                self.payload_remaining =
                    u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if self.payload_remaining == 0 {
                    self.header_len = 0;
                }
            }
            return;
        }

        self.payload_remaining = self.payload_remaining.saturating_sub(bytes.len());
        if self.payload_remaining == 0 {
            self.header_len = 0;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CapturedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.limiter_released {
            return Pin::new(&mut this.stream).poll_read(cx, output);
        }

        let limit = this
            .tls_read_limiter
            .next_limit(output.remaining())
            .min(TLS_READ_CHUNK_LIMIT);
        let unfilled = output.initialize_unfilled_to(limit);
        let mut limited = ReadBuf::new(unfilled);
        match Pin::new(&mut this.stream).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let filled_len = limited.filled().len();
                output.advance(filled_len);
                let filled_start = output.filled().len() - filled_len;
                let filled = &output.filled()[filled_start..];
                this.tls_read_limiter.observe(filled);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CapturedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, input)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, inputs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

enum ServerPenetratingTlsState<S> {
    Tls(Option<Box<TlsStream<CapturedStream<S>>>>),
    ReadDirect {
        stream: Box<TlsStream<CapturedStream<S>>>,
        pending_plaintext: BytesMut,
    },
}

pub struct ServerPenetratingTlsStream<S> {
    state: ServerPenetratingTlsState<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ServerPenetratingTlsStream<S> {
    pub fn new(stream: TlsStream<CapturedStream<S>>) -> Self {
        Self {
            state: ServerPenetratingTlsState::Tls(Some(Box::new(stream))),
        }
    }

    /// SNI and ALPN, which select a fallback.
    pub fn handshake_info(&self) -> crate::fallback::TlsInfo {
        let stream = match &self.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => stream,
            ServerPenetratingTlsState::Tls(None) => return Default::default(),
        };
        let conn = stream.get_ref().1;
        crate::fallback::TlsInfo::new(
            conn.server_name().unwrap_or_default(),
            conn.alpn_protocol().unwrap_or_default(),
        )
    }

    fn ensure_read_direct(&mut self) -> io::Result<()> {
        let ServerPenetratingTlsState::Tls(tls) = &mut self.state else {
            return Ok(());
        };
        let mut tls = tls
            .take()
            .ok_or_else(|| io::Error::other("TLS stream was already taken"))?;
        let mut pending_plaintext = BytesMut::new();
        let mut scratch = [0u8; 8192];

        {
            let (captured, session) = tls.as_mut().get_mut();
            loop {
                match session.reader().read(&mut scratch) {
                    Ok(0) => break,
                    Ok(len) => pending_plaintext.extend_from_slice(&scratch[..len]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            captured.release_record_alignment();
        }

        self.state = ServerPenetratingTlsState::ReadDirect {
            stream: tls,
            pending_plaintext,
        };
        Ok(())
    }

    fn poll_read_direct_mode(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.ensure_read_direct()?;
        let ServerPenetratingTlsState::ReadDirect {
            stream,
            pending_plaintext,
        } = &mut self.state
        else {
            unreachable!("ensure_read_direct transitions TLS state to read-direct");
        };

        if !pending_plaintext.is_empty() {
            let len = output.remaining().min(pending_plaintext.len());
            output.put_slice(&pending_plaintext.split_to(len));
            return Poll::Ready(Ok(()));
        }

        let (captured, _) = stream.as_mut().get_mut();
        Pin::new(captured).poll_read(cx, output)
    }

    fn poll_write_direct_mode(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                let (raw_stream, _) = stream.as_mut().get_mut();
                Pin::new(raw_stream).poll_write(cx, input)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ServerPenetratingTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream)) => Pin::new(stream).poll_read(cx, output),
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            ServerPenetratingTlsState::ReadDirect { .. } => this.poll_read_direct_mode(cx, output),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ServerPenetratingTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                Pin::new(stream).poll_write(cx, input)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                Pin::new(stream).poll_write_vectored(cx, inputs)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => stream.is_write_vectored(),
            ServerPenetratingTlsState::Tls(None) => false,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                Pin::new(stream).poll_flush(cx)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                Pin::new(stream).poll_shutdown(cx)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStreamIo for ServerPenetratingTlsStream<S> {
    fn release_record_alignment(&mut self) {
        if let ServerPenetratingTlsState::Tls(Some(stream)) = &mut self.state {
            let (captured, _) = stream.as_mut().get_mut();
            captured.release_record_alignment();
        }
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_direct_mode(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_direct_mode(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                let (raw_stream, _) = stream.as_mut().get_mut();
                Pin::new(raw_stream).poll_flush(cx)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            ServerPenetratingTlsState::Tls(Some(stream))
            | ServerPenetratingTlsState::ReadDirect { stream, .. } => {
                let (raw_stream, _) = stream.as_mut().get_mut();
                Pin::new(raw_stream).poll_shutdown(cx)
            }
            ServerPenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
        }
    }
}
