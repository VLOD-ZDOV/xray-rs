//! RFC 6455 WebSocket inbound server transport.
//!
//! Handles HTTP Upgrade handshake, Sec-WebSocket-Key acceptance,
//! Sec-WebSocket-Protocol early data, and masked/unmasked frame codec.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_SIZE: usize = 16 * 1024;
const CHUNK_SIZE: usize = 4096;
// Xray clients send one frame per write (a few KiB at most).
const MAX_FRAME_SIZE: usize = 1 << 20;
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn accept_key_for(client_key: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    STANDARD.encode(hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsSettings {
    pub path: String,
    pub host: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameEvent {
    Payload(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

#[derive(Debug, Default)]
pub struct ServerFrameDecoder {
    buffer: Vec<u8>,
    consumed: usize,
}

impl ServerFrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn next_event(&mut self) -> io::Result<Option<FrameEvent>> {
        loop {
            let Some((event, length)) = self.parse_frame()? else {
                self.compact();
                return Ok(None);
            };
            self.consumed += length;

            match event {
                FrameEvent::Payload(data) if data.is_empty() => continue,
                event => return Ok(Some(event)),
            }
        }
    }

    fn compact(&mut self) {
        if self.consumed > 0 {
            self.buffer.drain(..self.consumed);
            self.consumed = 0;
        }
    }

    fn parse_frame(&self) -> io::Result<Option<(FrameEvent, usize)>> {
        let bytes = &self.buffer[self.consumed..];
        if bytes.len() < 2 {
            return Ok(None);
        }

        let b0 = bytes[0];
        let b1 = bytes[1];
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        let len_code = b1 & 0x7F;

        // RFC 6455 §5.1: A client MUST mask all frames that it sends to the server.
        // A server MUST close a connection upon receiving a frame that is not masked.
        if !masked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client websocket frame must be masked",
            ));
        }

        let (payload_len, header_len) = match len_code {
            126 => {
                if bytes.len() < 4 {
                    return Ok(None);
                }
                (u16::from_be_bytes([bytes[2], bytes[3]]) as usize, 4)
            }
            127 => {
                if bytes.len() < 10 {
                    return Ok(None);
                }
                let mut len_bytes = [0u8; 8];
                len_bytes.copy_from_slice(&bytes[2..10]);
                let len = u64::from_be_bytes(len_bytes);
                (usize::try_from(len).unwrap_or(usize::MAX), 10)
            }
            len => (len as usize, 2),
        };
        // Frames are buffered whole before unmasking, so their size must be bounded.
        if payload_len > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket frame too large",
            ));
        }

        let total_header = header_len + 4; // header + 4 bytes mask key
        if bytes.len() < total_header + payload_len {
            return Ok(None);
        }

        let mask_key: [u8; 4] = bytes[header_len..total_header].try_into().unwrap();
        let payload_start = total_header;
        let payload_end = total_header + payload_len;
        let mut payload = bytes[payload_start..payload_end].to_vec();

        // Unmask
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }

        let total_frame_len = payload_end;
        let event = match opcode {
            0x0..=0x2 => FrameEvent::Payload(payload),
            0x8 => FrameEvent::Close,
            0x9 => FrameEvent::Pong(payload),
            0xA => FrameEvent::Payload(Vec::new()), // Pong: ignore
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported websocket opcode: 0x{other:x}"),
                ))
            }
        };

        Ok(Some((event, total_frame_len)))
    }
}

pub fn encode_server_binary_frames(out: &mut Vec<u8>, payload: &[u8]) {
    if payload.is_empty() {
        encode_server_frame(out, 0x82, &[]);
        return;
    }
    let chunks = payload.chunks(CHUNK_SIZE);
    let count = chunks.len();
    for (i, chunk) in chunks.enumerate() {
        let fin = i == count - 1;
        let opcode = if i == 0 { 0x02 } else { 0x00 };
        let b0 = if fin { 0x80 | opcode } else { opcode };
        encode_server_frame(out, b0, chunk);
    }
}

pub fn encode_server_frame(out: &mut Vec<u8>, b0: u8, payload: &[u8]) {
    out.push(b0);
    let len = payload.len();
    if len < 126 {
        out.push(len as u8);
    } else if let Ok(l16) = u16::try_from(len) {
        out.push(126);
        out.extend_from_slice(&l16.to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
}

pub struct WebSocketStream<S> {
    inner: S,
    decoder: ServerFrameDecoder,
    pending: Vec<u8>,
    pending_pos: usize,
    out: Vec<u8>,
    out_pos: usize,
    peer_closed: bool,
}

fn flush_buffer<S: AsyncWrite + Unpin>(
    inner: &mut S,
    out: &mut Vec<u8>,
    out_pos: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *out_pos < out.len() {
        let written = match Pin::new(&mut *inner).poll_write(cx, &out[*out_pos..]) {
            Poll::Ready(Ok(w)) => w,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        if written == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        *out_pos += written;
    }
    out.clear();
    *out_pos = 0;
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    pub fn new(inner: S, leftover: Vec<u8>, early_data: Vec<u8>) -> Self {
        let mut decoder = ServerFrameDecoder::new();
        decoder.extend(&leftover);
        Self {
            inner,
            decoder,
            pending: early_data,
            pending_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            peer_closed: false,
        }
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        flush_buffer(&mut self.inner, &mut self.out, &mut self.out_pos, cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let WebSocketStream {
            inner,
            decoder,
            pending,
            pending_pos,
            out,
            out_pos,
            peer_closed,
        } = &mut *self;

        // Try flushing any buffered outgoing frames (e.g. Pong)
        let _ = flush_buffer(inner, out, out_pos, cx);

        // Deliver any pending payload data
        if *pending_pos < pending.len() {
            let to_copy = (pending.len() - *pending_pos).min(buf.remaining());
            buf.put_slice(&pending[*pending_pos..*pending_pos + to_copy]);
            *pending_pos += to_copy;
            if *pending_pos == pending.len() {
                pending.clear();
                *pending_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if *peer_closed {
            return Poll::Ready(Ok(()));
        }

        loop {
            match decoder.next_event() {
                Ok(Some(FrameEvent::Payload(data))) => {
                    if !data.is_empty() {
                        let to_copy = data.len().min(buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        if to_copy < data.len() {
                            *pending = data;
                            *pending_pos = to_copy;
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
                Ok(Some(FrameEvent::Pong(ping_data))) => {
                    encode_server_frame(out, 0x8A, &ping_data);
                    let _ = flush_buffer(inner, out, out_pos, cx);
                }
                Ok(Some(FrameEvent::Close)) => {
                    *peer_closed = true;
                    encode_server_frame(out, 0x88, &[]);
                    let _ = flush_buffer(inner, out, out_pos, cx);
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            let mut read_slice = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut read_slice);
            match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        *peer_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    decoder.extend(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    let _ = flush_buffer(inner, out, out_pos, cx);
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.poll_flush_out(cx)?.is_pending() {
            return Poll::Pending;
        }

        encode_server_binary_frames(&mut this.out, buf);
        let _ = this.poll_flush_out(cx)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.poll_flush_out(cx)?.is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let _ = this.poll_flush_out(cx);
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn accept<S>(mut stream: S, settings: &WsSettings) -> io::Result<WebSocketStream<S>>
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
                "websocket header too large",
            ));
        }
        let n = match timeout(HANDSHAKE_TIMEOUT, stream.read(&mut temp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout")),
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof reading websocket header",
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
            format!("method {method} not allowed for websocket"),
        ));
    }

    // Match path: strip query parameters for comparison
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
                "websocket path mismatch: got {target_path}, expected {}",
                settings.path
            ),
        ));
    }

    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut sec_key = None;
    let mut sec_proto = None;
    let mut host_hdr = None;

    for line in lines {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();

        if key.eq_ignore_ascii_case("upgrade") && val.to_ascii_lowercase().contains("websocket") {
            upgrade_ok = true;
        } else if key.eq_ignore_ascii_case("connection")
            && val.to_ascii_lowercase().contains("upgrade")
        {
            connection_ok = true;
        } else if key.eq_ignore_ascii_case("sec-websocket-key") {
            sec_key = Some(val.to_owned());
        } else if key.eq_ignore_ascii_case("sec-websocket-protocol") {
            sec_proto = Some(val.to_owned());
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
                format!("websocket host mismatch: got {host_only}, expected {expected_host}"),
            ));
        }
    }

    let Some(key) = sec_key else {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Sec-WebSocket-Key",
        ));
    };

    if !upgrade_ok || !connection_ok {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing websocket Upgrade or Connection headers",
        ));
    }

    let accept_key = accept_key_for(&key);

    // Parse early data if Sec-WebSocket-Protocol is provided
    let early_data = if let Some(proto) = &sec_proto {
        decode_early_data(proto)
    } else {
        Vec::new()
    };

    let mut resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n"
    );
    if let Some(proto) = &sec_proto {
        resp.push_str(&format!("Sec-WebSocket-Protocol: {proto}\r\n"));
    }
    resp.push_str("\r\n");

    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    Ok(WebSocketStream::new(stream, leftover, early_data))
}

fn normalize_path(p: &str) -> &str {
    let stripped = p.trim_end_matches('/');
    if stripped.is_empty() {
        "/"
    } else {
        stripped
    }
}

fn decode_early_data(val: &str) -> Vec<u8> {
    let clean = val.trim();
    if let Ok(data) = URL_SAFE_NO_PAD.decode(clean) {
        return data;
    }
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_masked_client_frame() {
        let mut decoder = ServerFrameDecoder::new();
        // Masked binary frame with payload "hello"
        // FIN | binary = 0x82
        // Masked | 5 = 0x85
        // Mask key: [1, 2, 3, 4]
        // "hello" masked with [1, 2, 3, 4]
        let mask = [1u8, 2, 3, 4];
        let plain = b"hello";
        let masked_payload: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();

        let mut frame = vec![0x82, 0x85];
        frame.extend_from_slice(&mask);
        frame.extend_from_slice(&masked_payload);

        decoder.extend(&frame);
        let event = decoder.next_event().unwrap().unwrap();
        assert_eq!(event, FrameEvent::Payload(b"hello".to_vec()));
    }

    #[test]
    fn encodes_server_frames_unmasked() {
        let mut out = Vec::new();
        encode_server_binary_frames(&mut out, b"world");
        assert_eq!(out[0], 0x82); // FIN | BINARY
        assert_eq!(out[1], 5); // length 5, unmasked (bit 7 is 0)
        assert_eq!(&out[2..], b"world");
    }

    #[test]
    fn rejects_oversized_frames() {
        let mut decoder = ServerFrameDecoder::new();
        let mut frame = vec![0x82, 0xFF];
        frame.extend_from_slice(&u64::MAX.to_be_bytes());
        decoder.extend(&frame);
        assert!(decoder.next_event().is_err());
    }
}
