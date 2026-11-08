//! gRPC Gun transport for VLESS and Trojan over HTTP/2.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use http::header::{HeaderValue, CONTENT_TYPE, HOST};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::{log, trojan, vless};

pub type Body = BoxBody<Bytes, io::Error>;

const PIPE_SIZE: usize = 256 * 1024;
// grpc-go's default receive limit, which Xray's server inherits.
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcSettings {
    pub service_name: String,
    pub multi_mode: bool,
    pub authority: Option<String>,
}

#[derive(Clone)]
pub enum GrpcProtocol {
    Vless(Arc<vless::Context>),
    Trojan(Arc<vless::Context>),
}

pub struct Handler {
    settings: GrpcSettings,
    protocol: GrpcProtocol,
    trusted_x_forwarded_for: Vec<String>,
}

impl Handler {
    pub fn new(settings: GrpcSettings, protocol: GrpcProtocol) -> Arc<Self> {
        Arc::new(Self {
            settings,
            protocol,
            trusted_x_forwarded_for: Vec::new(),
        })
    }

    pub fn with_trusted_x_forwarded_for(self: &mut Arc<Self>, trusted: Vec<String>) {
        if let Some(handler) = Arc::get_mut(self) {
            handler.trusted_x_forwarded_for = trusted;
        } else {
            *self = Arc::new(Self {
                settings: self.settings.clone(),
                protocol: self.protocol.clone(),
                trusted_x_forwarded_for: trusted,
            });
        }
    }

    pub async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<Body> {
        let peer = crate::sockopt::apply_trusted_x_forwarded_for(
            req.headers(),
            &self.trusted_x_forwarded_for,
            peer,
        );
        if req.method() != Method::POST {
            log::debug(format!(
                "grpc: non-POST method {:?} from {}",
                req.method(),
                log::mask(peer)
            ));
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }

        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with("application/grpc") {
            log::debug(format!(
                "grpc: invalid content-type {:?} from {}",
                content_type,
                log::mask(peer)
            ));
            return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }

        if let Some(ref authority) = self.settings.authority {
            if !host_matches(&req, authority) {
                log::debug(format!("grpc: authority mismatch from {}", log::mask(peer)));
                return status(StatusCode::NOT_FOUND);
            }
        }

        let path = req.uri().path();
        if !path_matches(path, &self.settings.service_name) {
            log::debug(format!(
                "grpc: path mismatch {:?} from {}",
                path,
                log::mask(peer)
            ));
            return status(StatusCode::NOT_FOUND);
        }

        let (duplex_a, duplex_b) = tokio::io::duplex(PIPE_SIZE);
        let (client_r, client_w) = tokio::io::split(duplex_a);
        let (mut duplex_r, mut duplex_w) = tokio::io::split(duplex_b);

        match &self.protocol {
            GrpcProtocol::Vless(ctx) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = vless::serve(client_r, client_w, &ctx, peer).await {
                        log::info(format!("vless-grpc from {} rejected: {e}", log::mask(peer)));
                    }
                });
            }
            GrpcProtocol::Trojan(ctx) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        trojan::serve(client_r, client_w, &ctx, peer, &Default::default()).await
                    {
                        log::info(format!(
                            "trojan-grpc from {} rejected: {e}",
                            log::mask(peer)
                        ));
                    }
                });
            }
        }

        let uplink = tokio::spawn(async move {
            let mut incoming_buf = BytesMut::with_capacity(32 * 1024);
            let mut body = req.into_body();

            'read: while let Some(Ok(frame)) = body.frame().await {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                incoming_buf.extend_from_slice(&data);
                while incoming_buf.len() >= 5 {
                    let compressed = incoming_buf[0];
                    let msg_len = u32::from_be_bytes([
                        incoming_buf[1],
                        incoming_buf[2],
                        incoming_buf[3],
                        incoming_buf[4],
                    ]) as usize;
                    if compressed != 0 || msg_len > MAX_MESSAGE_SIZE {
                        log::debug(format!(
                            "grpc message rejected: compressed {compressed}, {msg_len} bytes"
                        ));
                        break 'read;
                    }
                    if incoming_buf.len() < 5 + msg_len {
                        break;
                    }
                    incoming_buf.advance(5);
                    let payload = incoming_buf.split_to(msg_len);
                    if let Err(e) = decode_hunk_payload(&payload, &mut duplex_w).await {
                        log::debug(format!("error decoding hunk: {e}"));
                        break 'read;
                    }
                }
            }
            let _ = duplex_w.shutdown().await;
        });

        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(32);
        tokio::spawn(async move {
            // Stop reading the request body once the session is over.
            let _uplink_guard = AbortOnDrop(uplink);
            let mut buf = vec![0u8; 16384];
            loop {
                match duplex_r.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let frame_bytes = encode_hunk_frame(&buf[..n]);
                        if tx.send(Ok(Frame::data(frame_bytes))).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", HeaderValue::from_static("0"));
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                        break;
                    }
                    Err(e) => {
                        log::debug(format!("grpc downlink read error: {e}"));
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", HeaderValue::from_static("0"));
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                        break;
                    }
                }
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/grpc")
            .body(channel_body(rx))
            .unwrap()
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn serve<I>(io: I, peer: SocketAddr, handler: Arc<Handler>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler.handle(req, peer).await) }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http2()
        .initial_stream_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .max_concurrent_streams(1024);
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(4));
    if let Err(e) = builder.serve_connection(TokioIo::new(io), service).await {
        log::debug(format!(
            "grpc connection from {} ended: {e}",
            log::mask(peer)
        ));
    }
}

fn channel_body(rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>) -> Body {
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    BodyExt::boxed(StreamBody::new(stream))
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn status(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(empty()).unwrap()
}

fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~$&+=:@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// Mirrors Xray's getServiceName / getTunStreamName / getTunMultiStreamName
// (server side) and matches the full gRPC method path exactly.
fn path_matches(req_path: &str, service_name: &str) -> bool {
    let (service, tun, multi) = if let Some(rest) = service_name.strip_prefix('/') {
        let last = service_name.rfind('/').unwrap_or(0);
        let raw = &service_name[1..last.max(1)];
        let service = raw
            .split('/')
            .map(path_escape)
            .collect::<Vec<_>>()
            .join("/");
        let ending = &rest[rest.rfind('/').map_or(0, |i| i + 1)..];
        let mut names = ending.split('|');
        let tun = path_escape(names.next().unwrap_or(""));
        let multi = names.next().map_or_else(|| tun.clone(), path_escape);
        (service, tun, multi)
    } else {
        (path_escape(service_name), "Tun".into(), "TunMulti".into())
    };
    let Some(rest) = req_path.strip_prefix('/') else {
        return false;
    };
    let Some(method) = rest
        .strip_prefix(service.as_str())
        .and_then(|r| r.strip_prefix('/'))
    else {
        return false;
    };
    method == tun || method == multi
}

fn host_matches(req: &Request<Incoming>, expected: &str) -> bool {
    let host = req.uri().host().map(str::to_owned).or_else(|| {
        let value = req.headers().get(HOST)?.to_str().ok()?;
        Some(strip_port(value).to_owned())
    });
    host.is_some_and(|h| h.eq_ignore_ascii_case(expected))
}

fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

fn encode_hunk_frame(data: &[u8]) -> Bytes {
    let mut proto_varint = [0u8; 10];
    let n_varint = encode_varint(data.len(), &mut proto_varint);
    let proto_len = 1 + n_varint + data.len();

    let mut frame = Vec::with_capacity(5 + proto_len);
    frame.push(0x00);
    frame.extend_from_slice(&(proto_len as u32).to_be_bytes());

    // Protobuf field 1, wire type 2 (length-delimited): tag 0x0a
    frame.push(0x0a);
    frame.extend_from_slice(&proto_varint[..n_varint]);
    frame.extend_from_slice(data);

    Bytes::from(frame)
}

fn encode_varint(mut val: usize, out: &mut [u8; 10]) -> usize {
    let mut i = 0;
    while val >= 0x80 {
        out[i] = ((val & 0x7f) as u8) | 0x80;
        val >>= 7;
        i += 1;
    }
    out[i] = val as u8;
    i + 1
}

fn decode_varint(data: &[u8]) -> io::Result<(usize, usize)> {
    let mut val: usize = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint overflow",
            ));
        }
        val |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((val, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "incomplete varint",
    ))
}

fn skip_field(data: &[u8], pos: usize, wire_type: u8) -> io::Result<usize> {
    match wire_type {
        0 => {
            let (_, n) = decode_varint(&data[pos..])?;
            Ok(pos + n)
        }
        1 => {
            if pos + 8 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated fixed64",
                ));
            }
            Ok(pos + 8)
        }
        2 => {
            let (len, n) = decode_varint(&data[pos..])?;
            let start = pos + n;
            // `len` comes from the peer; `start + len` could wrap.
            if start > data.len() || len > data.len() - start {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated length-delimited",
                ));
            }
            Ok(start + len)
        }
        5 => {
            if pos + 4 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated fixed32",
                ));
            }
            Ok(pos + 4)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported protobuf wire type",
        )),
    }
}

async fn decode_hunk_payload<W>(payload: &[u8], writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut pos = 0;
    while pos < payload.len() {
        let tag = payload[pos];
        pos += 1;
        let wire_type = tag & 0x07;
        let field_num = tag >> 3;
        if field_num == 1 && wire_type == 2 {
            let (len, n) = decode_varint(&payload[pos..])?;
            pos += n;
            if len > payload.len() - pos {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated hunk data",
                ));
            }
            let chunk = &payload[pos..pos + len];
            pos += len;
            writer.write_all(chunk).await?;
        } else {
            pos = skip_field(payload, pos, wire_type)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_huge_length_is_truncated_data_not_a_wrap() {
        // field 2, length-delimited, length u64::MAX
        let mut field = vec![0x12];
        field.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(skip_field(&field, 1, 2).is_err());
        let mut hunk = vec![0x0a];
        hunk.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        let mut sink = Vec::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(rt.block_on(decode_hunk_payload(&hunk, &mut sink)).is_err());
    }

    #[test]
    fn varint_roundtrips() {
        for val in [0, 1, 127, 128, 255, 16383, 16384, 65535, 1_000_000] {
            let mut buf = [0u8; 10];
            let n = encode_varint(val, &mut buf);
            let (decoded, read_bytes) = decode_varint(&buf[..n]).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(read_bytes, n);
        }
    }

    #[test]
    fn encodes_valid_hunk_frame() {
        let payload = b"hello grpc";
        let frame = encode_hunk_frame(payload);
        assert_eq!(frame[0], 0x00); // uncompressed
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(len, frame.len() - 5);
        assert_eq!(frame[5], 0x0a); // field 1, wire type 2
        let (proto_len, n) = decode_varint(&frame[6..]).unwrap();
        assert_eq!(proto_len, payload.len());
        assert_eq!(&frame[6 + n..], payload);
    }

    #[test]
    fn path_matches_service_variations() {
        assert!(path_matches("/GunService/Tun", "GunService"));
        assert!(path_matches("/GunService/TunMulti", "GunService"));
        assert!(!path_matches("GunService/Tun", "GunService"));
        assert!(!path_matches("/x/GunService/Tun", "GunService"));
        assert!(!path_matches("/OtherService/Tun", "GunService"));
        assert!(path_matches("//Tun", ""));
        assert!(path_matches("/a/b/Tun", "/a/b/Tun"));
        assert!(!path_matches("/a/b/Tun/Tun", "/a/b/Tun"));
        assert!(path_matches("/a/b/S", "/a/b/S|M"));
        assert!(path_matches("/a/b/M", "/a/b/S|M"));
        assert!(!path_matches("/a/b/X", "/a/b/S|M"));
    }

    #[tokio::test]
    async fn hunk_payload_rejects_overflowing_length() {
        let mut p = vec![0x0a];
        p.extend_from_slice(&[0xFF; 9]);
        p.push(0x01);
        let mut out = Vec::new();
        assert!(decode_hunk_payload(&p, &mut out).await.is_err());
    }

    #[tokio::test]
    async fn hunk_payload_decodes_correctly() {
        let data = b"some proxy data from client";
        let mut proto = vec![0x0a];
        let mut var = [0u8; 10];
        let n = encode_varint(data.len(), &mut var);
        proto.extend_from_slice(&var[..n]);
        proto.extend_from_slice(data);

        let mut out = Vec::new();
        decode_hunk_payload(&proto, &mut out).await.unwrap();
        assert_eq!(out, data);
    }
}
