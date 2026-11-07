//! XHTTP (splithttp) server side: stream-one, stream-up and packet-up modes over
//! HTTP/1.1, HTTP/2, and HTTP/3, mirroring Xray-core's transport/internet/splithttp/hub.go.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use http::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, REFERER, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use quinn::Runtime;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::config::{Inbound, Meta, Placement, XhttpSettings};
use crate::{log, padding, vless};
use xray_transport::stream::{H3Congestion, H3QuicConfig};

pub type Body = BoxBody<Bytes, io::Error>;
pub type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const PIPE_SIZE: usize = 256 * 1024;
const SESSION_TTL: Duration = Duration::from_secs(30);

pub struct Handler {
    settings: XhttpSettings,
    vless: Arc<vless::Context>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    trusted_x_forwarded_for: Vec<String>,
}

struct Session {
    uploads: mpsc::Sender<Upload>,
    // Taken by the GET request that carries the downlink.
    uplink: Mutex<Option<DuplexStream>>,
    connected: AtomicBool,
}

enum Upload {
    Packet(u64, Bytes),
    Raw(Bytes),
}

impl Handler {
    pub fn new(settings: XhttpSettings, vless: Arc<vless::Context>) -> Arc<Self> {
        Arc::new(Self {
            settings,
            vless,
            sessions: Mutex::new(HashMap::new()),
            trusted_x_forwarded_for: Vec::new(),
        })
    }

    pub fn with_trusted_x_forwarded_for(self: &mut Arc<Self>, trusted: Vec<String>) {
        if let Some(handler) = Arc::get_mut(self) {
            handler.trusted_x_forwarded_for = trusted;
        } else {
            *self = Arc::new(Self {
                settings: self.settings.clone(),
                vless: self.vless.clone(),
                sessions: Mutex::new(HashMap::new()),
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
        let s = &self.settings;
        if !s.host.is_empty() && !host_matches(&req, &s.host) {
            log::debug(format!("xhttp: host mismatch from {}", log::mask(peer)));
            return status(StatusCode::NOT_FOUND);
        }
        let path = req.uri().path().to_owned();
        let Some(rest) = path.strip_prefix(s.path.as_str()) else {
            log::debug(format!(
                "xhttp: path mismatch {path:?} from {}",
                log::mask(peer)
            ));
            return status(StatusCode::NOT_FOUND);
        };

        let mut response = self.response_headers(&req);

        // A real CORS preflight carries Access-Control-Request-Method; a bare OPTIONS is an uplink.
        if req.method() == Method::OPTIONS
            && req.headers().contains_key("Access-Control-Request-Method")
        {
            return finish(response, StatusCode::OK, empty());
        }

        let referer = req
            .headers()
            .get(REFERER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let pad = self.request_padding(&req, referer.as_deref());
        let tokenish = s.padding_obfs.as_ref().is_some_and(|o| o.tokenish);
        if !padding::is_valid(&pad, s.padding, tokenish) {
            log::debug(format!(
                "xhttp: invalid padding (length {}) from {}",
                pad.len(),
                log::mask(peer)
            ));
            return status(StatusCode::BAD_REQUEST);
        }
        let obfs_padding_accepted = s.padding_obfs.is_some();

        let mut parts = rest.split('/');
        let session_id = meta(&req, &s.session, &mut parts);
        let seq = meta(&req, &s.seq, &mut parts);
        let mode = s.mode.as_str();
        let allowed = |m: &str| mode == "auto" || mode == m;

        if session_id.is_empty() && !allowed("stream-one") && !allowed("stream-up") {
            return status(StatusCode::BAD_REQUEST);
        }
        let is_uplink = req.method() != Method::GET || !seq.is_empty();

        if is_uplink && !session_id.is_empty() {
            let session = self.upsert(&session_id);
            if seq.is_empty() {
                if !allowed("stream-up") {
                    return status(StatusCode::BAD_REQUEST);
                }
                let send_padding =
                    (referer.is_some() || obfs_padding_accepted) && s.stream_up_secs.1 > 0;
                let body = stream_up(
                    req.into_body(),
                    session,
                    send_padding,
                    s.padding,
                    s.stream_up_secs,
                );
                response = response
                    .header("X-Accel-Buffering", "no")
                    .header(CACHE_CONTROL, "no-store");
                return finish(response, StatusCode::OK, body);
            }
            if !allowed("packet-up") {
                return status(StatusCode::BAD_REQUEST);
            }
            let Ok(seq) = seq.parse::<u64>() else {
                return status(StatusCode::INTERNAL_SERVER_ERROR);
            };
            let data = &s.uplink_data;
            let mut payload = Vec::new();
            for (placement, chunks) in [
                (Placement::Header, header_chunks(&req, &data.key)),
                (Placement::Cookie, cookie_chunks(&req, &data.key)),
            ] {
                if data.placement == placement || data.placement == Placement::Auto {
                    match URL_SAFE_NO_PAD.decode(chunks) {
                        Ok(decoded) => payload.extend_from_slice(&decoded),
                        Err(_) => return status(StatusCode::BAD_REQUEST),
                    }
                }
            }
            let mut body_empty = true;
            if matches!(data.placement, Placement::Body | Placement::Auto) {
                let body = match Limited::new(req.into_body(), s.max_each_post)
                    .collect()
                    .await
                {
                    Ok(collected) => collected.to_bytes(),
                    Err(_) => return status(StatusCode::PAYLOAD_TOO_LARGE),
                };
                body_empty = body.is_empty();
                payload.extend_from_slice(&body);
            }
            if payload.len() > s.max_each_post {
                return status(StatusCode::PAYLOAD_TOO_LARGE);
            }
            if body_empty {
                // Methods without a body are usually cached by default.
                response = response.header(CACHE_CONTROL, "no-store");
            }
            let payload = Bytes::from(payload);
            if session
                .uploads
                .send(Upload::Packet(seq, payload))
                .await
                .is_err()
            {
                return status(StatusCode::INTERNAL_SERVER_ERROR);
            }
            return finish(response, StatusCode::OK, empty());
        }

        if req.method() != Method::GET && !session_id.is_empty() {
            return status(StatusCode::NOT_FOUND);
        }

        // Downlink: GET for stream-up/packet-up sessions, or the single stream-one request.
        let (uplink, session) = if session_id.is_empty() {
            let (mut writer, reader) = tokio::io::duplex(PIPE_SIZE);
            let mut body = req.into_body();
            tokio::spawn(async move {
                while let Some(Ok(frame)) = body.frame().await {
                    if let Ok(data) = frame.into_data() {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                }
                let _ = writer.shutdown().await;
            });
            (reader, None)
        } else {
            let session = self.upsert(&session_id);
            session.connected.store(true, Ordering::Relaxed);
            let Some(uplink) = lock(&session.uplink).take() else {
                return status(StatusCode::CONFLICT);
            };
            (uplink, Some(session))
        };

        let (downlink, reader) = tokio::io::duplex(PIPE_SIZE);
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = vless::serve(uplink, downlink, &this.vless, peer).await {
                log::info(format!("from {} rejected: {e}", log::mask(peer)));
            }
            if let Some(session) = session {
                this.remove(&session_id, &session);
            }
        });

        response = response
            .header("X-Accel-Buffering", "no")
            .header(CACHE_CONTROL, "no-store");
        if !s.no_sse_header {
            response = response.header(CONTENT_TYPE, "text/event-stream");
        }
        finish(response, StatusCode::OK, reader_body(reader))
    }

    pub async fn handle_h3(
        self: Arc<Self>,
        req: Request<()>,
        mut stream: H3Stream,
        peer: SocketAddr,
    ) {
        let peer = crate::sockopt::apply_trusted_x_forwarded_for(
            req.headers(),
            &self.trusted_x_forwarded_for,
            peer,
        );
        let s = &self.settings;
        if !s.host.is_empty() && !host_matches(&req, &s.host) {
            log::debug(format!("xhttp: host mismatch from {}", log::mask(peer)));
            let _ = stream.send_response(h3_status(StatusCode::NOT_FOUND)).await;
            let _ = stream.finish().await;
            return;
        }
        let path = req.uri().path().to_owned();
        let Some(rest) = path.strip_prefix(s.path.as_str()) else {
            log::debug(format!(
                "xhttp: path mismatch {path:?} from {}",
                log::mask(peer)
            ));
            let _ = stream.send_response(h3_status(StatusCode::NOT_FOUND)).await;
            let _ = stream.finish().await;
            return;
        };

        let mut response = self.response_headers(&req);

        // A real CORS preflight carries Access-Control-Request-Method; a bare OPTIONS is an uplink.
        if req.method() == Method::OPTIONS
            && req.headers().contains_key("Access-Control-Request-Method")
        {
            let resp = h3_response(response, StatusCode::OK);
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
            return;
        }

        let referer = req
            .headers()
            .get(REFERER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let pad = self.request_padding(&req, referer.as_deref());
        let tokenish = s.padding_obfs.as_ref().is_some_and(|o| o.tokenish);
        if !padding::is_valid(&pad, s.padding, tokenish) {
            log::debug(format!(
                "xhttp: invalid padding (length {}) from {}",
                pad.len(),
                log::mask(peer)
            ));
            let _ = stream
                .send_response(h3_status(StatusCode::BAD_REQUEST))
                .await;
            let _ = stream.finish().await;
            return;
        }
        let obfs_padding_accepted = s.padding_obfs.is_some();

        let mut parts = rest.split('/');
        let session_id = meta(&req, &s.session, &mut parts);
        let seq = meta(&req, &s.seq, &mut parts);
        let mode = s.mode.as_str();
        let allowed = |m: &str| mode == "auto" || mode == m;

        if session_id.is_empty() && !allowed("stream-one") && !allowed("stream-up") {
            let _ = stream
                .send_response(h3_status(StatusCode::BAD_REQUEST))
                .await;
            let _ = stream.finish().await;
            return;
        }
        let is_uplink = req.method() != Method::GET || !seq.is_empty();

        if is_uplink && !session_id.is_empty() {
            let session = self.upsert(&session_id);
            if seq.is_empty() {
                if !allowed("stream-up") {
                    let _ = stream
                        .send_response(h3_status(StatusCode::BAD_REQUEST))
                        .await;
                    let _ = stream.finish().await;
                    return;
                }
                let send_padding =
                    (referer.is_some() || obfs_padding_accepted) && s.stream_up_secs.1 > 0;
                response = response
                    .header("X-Accel-Buffering", "no")
                    .header(CACHE_CONTROL, "no-store");
                let resp = h3_response(response, StatusCode::OK);
                if stream.send_response(resp).await.is_err() {
                    return;
                }

                let padding_secs = s.stream_up_secs;
                let padding_range = s.padding;
                let delay = move || {
                    Duration::from_secs(padding::draw((
                        padding_secs.0 as usize,
                        padding_secs.1 as usize,
                    )) as u64)
                };
                let mut next_padding = delay();
                let uploads = session.uploads.clone();

                loop {
                    tokio::select! {
                        recv = stream.recv_data() => {
                            match recv {
                                Ok(Some(mut data)) => {
                                    while data.has_remaining() {
                                        let chunk = data.chunk();
                                        let bytes = Bytes::copy_from_slice(chunk);
                                        let consumed = chunk.len();
                                        data.advance(consumed);
                                        if uploads.send(Upload::Raw(bytes)).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                                _ => break,
                            }
                        }
                        _ = tokio::time::sleep(next_padding), if send_padding => {
                            let pad = padding::generate(false, padding::draw(padding_range));
                            if stream.send_data(Bytes::from(pad)).await.is_err() {
                                break;
                            }
                            next_padding = delay();
                        }
                    }
                }
                let _ = stream.finish().await;
                return;
            }

            if !allowed("packet-up") {
                let _ = stream
                    .send_response(h3_status(StatusCode::BAD_REQUEST))
                    .await;
                let _ = stream.finish().await;
                return;
            }
            let Ok(seq) = seq.parse::<u64>() else {
                let _ = stream
                    .send_response(h3_status(StatusCode::INTERNAL_SERVER_ERROR))
                    .await;
                let _ = stream.finish().await;
                return;
            };
            let data = &s.uplink_data;
            let mut payload = Vec::new();
            for (placement, chunks) in [
                (Placement::Header, header_chunks(&req, &data.key)),
                (Placement::Cookie, cookie_chunks(&req, &data.key)),
            ] {
                if data.placement == placement || data.placement == Placement::Auto {
                    match URL_SAFE_NO_PAD.decode(chunks) {
                        Ok(decoded) => payload.extend_from_slice(&decoded),
                        Err(_) => {
                            let _ = stream
                                .send_response(h3_status(StatusCode::BAD_REQUEST))
                                .await;
                            let _ = stream.finish().await;
                            return;
                        }
                    }
                }
            }
            let mut body_empty = true;
            if matches!(data.placement, Placement::Body | Placement::Auto) {
                let mut body_bytes = Vec::new();
                while let Ok(Some(mut data)) = stream.recv_data().await {
                    while data.has_remaining() {
                        if body_bytes.len() + data.remaining() > s.max_each_post {
                            let _ = stream
                                .send_response(h3_status(StatusCode::PAYLOAD_TOO_LARGE))
                                .await;
                            let _ = stream.finish().await;
                            return;
                        }
                        let chunk = data.chunk();
                        body_bytes.extend_from_slice(chunk);
                        let consumed = chunk.len();
                        data.advance(consumed);
                    }
                }
                body_empty = body_bytes.is_empty();
                payload.extend_from_slice(&body_bytes);
            }
            if payload.len() > s.max_each_post {
                let _ = stream
                    .send_response(h3_status(StatusCode::PAYLOAD_TOO_LARGE))
                    .await;
                let _ = stream.finish().await;
                return;
            }
            if body_empty {
                response = response.header(CACHE_CONTROL, "no-store");
            }
            let payload = Bytes::from(payload);
            if session
                .uploads
                .send(Upload::Packet(seq, payload))
                .await
                .is_err()
            {
                let _ = stream
                    .send_response(h3_status(StatusCode::INTERNAL_SERVER_ERROR))
                    .await;
                let _ = stream.finish().await;
                return;
            }
            let resp = h3_response(response, StatusCode::OK);
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
            return;
        }

        if req.method() != Method::GET && !session_id.is_empty() {
            let _ = stream.send_response(h3_status(StatusCode::NOT_FOUND)).await;
            let _ = stream.finish().await;
            return;
        }

        response = response
            .header("X-Accel-Buffering", "no")
            .header(CACHE_CONTROL, "no-store");
        if !s.no_sse_header {
            response = response.header(CONTENT_TYPE, "text/event-stream");
        }
        let resp = h3_response(response, StatusCode::OK);
        if stream.send_response(resp).await.is_err() {
            return;
        }

        if session_id.is_empty() {
            let (mut uplink_writer, uplink_reader) = tokio::io::duplex(PIPE_SIZE);
            let (downlink_writer, mut downlink_reader) = tokio::io::duplex(PIPE_SIZE);

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    vless::serve(uplink_reader, downlink_writer, &this.vless, peer).await
                {
                    log::info(format!("from {} rejected: {e}", log::mask(peer)));
                }
            });

            let (mut send_stream, mut recv_stream) = stream.split();

            let recv_task = tokio::spawn(async move {
                while let Ok(Some(mut data)) = recv_stream.recv_data().await {
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        if uplink_writer.write_all(chunk).await.is_err() {
                            return;
                        }
                        let consumed = chunk.len();
                        data.advance(consumed);
                    }
                }
                let _ = uplink_writer.shutdown().await;
            });

            let mut buf = BytesMut::with_capacity(32 * 1024);
            while let Ok(n) = downlink_reader.read_buf(&mut buf).await {
                if n == 0 {
                    break;
                }
                let chunk = buf.split().freeze();
                if send_stream.send_data(chunk).await.is_err() {
                    break;
                }
            }
            let _ = send_stream.finish().await;
            let _ = recv_task.await;
            return;
        }

        let session = self.upsert(&session_id);
        session.connected.store(true, Ordering::Relaxed);
        let Some(uplink) = lock(&session.uplink).take() else {
            let _ = stream.send_response(h3_status(StatusCode::CONFLICT)).await;
            let _ = stream.finish().await;
            return;
        };

        let (downlink, mut downlink_reader) = tokio::io::duplex(PIPE_SIZE);
        let this = self.clone();
        let sess = session.clone();
        let sess_id = session_id.clone();
        tokio::spawn(async move {
            if let Err(e) = vless::serve(uplink, downlink, &this.vless, peer).await {
                log::info(format!("from {} rejected: {e}", log::mask(peer)));
            }
            this.remove(&sess_id, &sess);
        });

        let mut buf = BytesMut::with_capacity(32 * 1024);
        while let Ok(n) = downlink_reader.read_buf(&mut buf).await {
            if n == 0 {
                break;
            }
            let chunk = buf.split().freeze();
            if stream.send_data(chunk).await.is_err() {
                break;
            }
        }
        let _ = stream.finish().await;
    }

    fn response_headers<B>(&self, req: &Request<B>) -> http::response::Builder {
        let s = &self.settings;
        let mut response = Response::builder().header("Access-Control-Allow-Origin", origin(req));
        for (name, val) in &s.response_headers {
            response = response.header(name, val);
        }
        let cookie_used = [&s.session, &s.seq, &s.uplink_data]
            .iter()
            .any(|m| m.placement == Placement::Cookie)
            || s.padding_obfs
                .as_ref()
                .is_some_and(|o| o.placement == Placement::Cookie);
        if cookie_used {
            response = response.header("Access-Control-Allow-Credentials", "true");
        }
        if req.method() == Method::OPTIONS {
            let echo = |name: &str| {
                req.headers()
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| HeaderValue::from_static("*"))
            };
            response = response
                .header(
                    "Access-Control-Allow-Methods",
                    echo("Access-Control-Request-Method"),
                )
                .header(
                    "Access-Control-Allow-Headers",
                    echo("Access-Control-Request-Headers"),
                );
        }
        let length = padding::draw(s.padding);
        match &s.padding_obfs {
            None => response.header("X-Padding", padding::generate(false, length)),
            Some(obfs) => {
                let value = padding::generate(obfs.tokenish, length);
                match obfs.placement {
                    Placement::Header => response.header(obfs.header.as_str(), value),
                    // Xray formats an empty URL carrying only the query.
                    Placement::QueryInHeader => {
                        response.header(obfs.header.as_str(), format!("?{}={value}", obfs.key))
                    }
                    Placement::Cookie => {
                        response.header(SET_COOKIE, format!("{}={value}; Path=/", obfs.key))
                    }
                    _ => response,
                }
            }
        }
    }

    /// The padding the client sent, looked up the way Xray's ExtractXPaddingFromRequest does.
    fn request_padding<B>(&self, req: &Request<B>, referer: Option<&str>) -> String {
        let request_query = req.uri().query().unwrap_or_default();
        let Some(obfs) = &self.settings.padding_obfs else {
            let query = referer.map_or(request_query, |r| r.split_once('?').map_or("", |(_, q)| q));
            return query_value(query, "x_padding")
                .unwrap_or_default()
                .to_owned();
        };
        if let Some(value) = cookie(req, &obfs.key).filter(|v| !v.is_empty()) {
            return value;
        }
        if let Some(value) = req
            .headers()
            .get(obfs.header.as_str())
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
        {
            if obfs.placement == Placement::Header {
                return value.to_owned();
            }
            return query_value(value.split_once('?').map_or("", |(_, q)| q), &obfs.key)
                .unwrap_or_default()
                .to_owned();
        }
        query_value(request_query, &obfs.key)
            .unwrap_or_default()
            .to_owned()
    }

    fn upsert(self: &Arc<Self>, id: &str) -> Arc<Session> {
        let mut sessions = lock(&self.sessions);
        if let Some(session) = sessions.get(id) {
            return session.clone();
        }
        let (writer, reader) = tokio::io::duplex(PIPE_SIZE);
        let (tx, rx) = mpsc::channel(self.settings.max_buffered_posts);
        tokio::spawn(upload_task(rx, writer, self.settings.max_buffered_posts));
        let session = Arc::new(Session {
            uploads: tx,
            uplink: Mutex::new(Some(reader)),
            connected: AtomicBool::new(false),
        });
        sessions.insert(id.to_owned(), session.clone());

        let this = self.clone();
        let (id, reaped) = (id.to_owned(), session.clone());
        tokio::spawn(async move {
            tokio::time::sleep(SESSION_TTL).await;
            if !reaped.connected.load(Ordering::Relaxed) {
                this.remove(&id, &reaped);
            }
        });
        session
    }

    fn remove(&self, id: &str, session: &Arc<Session>) {
        let mut sessions = lock(&self.sessions);
        if sessions
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            sessions.remove(id);
        }
    }
}

/// Writes uploads into the session pipe, reordering packet-up posts by seq.
async fn upload_task(
    mut rx: mpsc::Receiver<Upload>,
    mut writer: DuplexStream,
    max_buffered: usize,
) {
    let mut next = 0u64;
    let mut pending = BTreeMap::new();
    while let Some(upload) = rx.recv().await {
        match upload {
            Upload::Raw(data) => {
                if writer.write_all(&data).await.is_err() {
                    return;
                }
            }
            Upload::Packet(seq, data) => {
                if seq < next {
                    continue;
                }
                pending.insert(seq, data);
                if pending.len() > max_buffered {
                    log::info("xhttp: packet queue is too large");
                    return;
                }
                while let Some(data) = pending.remove(&next) {
                    if writer.write_all(&data).await.is_err() {
                        return;
                    }
                    next += 1;
                }
            }
        }
    }
}

/// Forwards a stream-up body into the session and keeps the response open
/// until the upload ends, with periodic padding for clients that expect it.
fn stream_up(
    mut body: Incoming,
    session: Arc<Session>,
    send_padding: bool,
    range: (usize, usize),
    secs: (u64, u64),
) -> Body {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(4);
    tokio::spawn(async move {
        let delay =
            || Duration::from_secs(padding::draw((secs.0 as usize, secs.1 as usize)) as u64);
        let mut next_padding = delay();
        loop {
            tokio::select! {
                frame = body.frame() => {
                    let Some(Ok(frame)) = frame else { break };
                    if let Ok(data) = frame.into_data() {
                        if session.uploads.send(Upload::Raw(data)).await.is_err() {
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(next_padding), if send_padding => {
                    let pad = padding::generate(false, padding::draw(range));
                    if tx.send(Ok(Frame::data(Bytes::from(pad)))).await.is_err() {
                        break;
                    }
                    next_padding = delay();
                }
            }
        }
    });
    channel_body(rx)
}

fn channel_body(rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>) -> Body {
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    BodyExt::boxed(StreamBody::new(stream))
}

fn reader_body(reader: DuplexStream) -> Body {
    let stream = futures_util::stream::unfold(reader, |mut reader| async move {
        let mut buf = BytesMut::with_capacity(32 * 1024);
        match reader.read_buf(&mut buf).await {
            Ok(n) if n > 0 => Some((Ok(Frame::data(buf.freeze())), reader)),
            _ => None,
        }
    });
    BodyExt::boxed(StreamBody::new(stream))
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn status(code: StatusCode) -> Response<Body> {
    finish(Response::builder(), code, empty())
}

fn finish(builder: http::response::Builder, code: StatusCode, body: Body) -> Response<Body> {
    builder.status(code).body(body).unwrap_or_else(|_| {
        let mut fallback = Response::new(empty());
        *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

/// Session ID or seq; path placements consume the next path segment.
fn meta<'a, B>(req: &Request<B>, meta: &Meta, path: &mut impl Iterator<Item = &'a str>) -> String {
    match meta.placement {
        Placement::Path => path.next().unwrap_or_default().to_owned(),
        Placement::Query => query_value(req.uri().query().unwrap_or_default(), &meta.key)
            .unwrap_or_default()
            .to_owned(),
        Placement::Header => req
            .headers()
            .get(meta.key.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        Placement::Cookie => cookie(req, &meta.key).unwrap_or_default(),
        _ => String::new(),
    }
}

fn cookie<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then(|| value.trim_matches('"').to_owned())
        })
}

/// Uplink data split over `KEY-0`, `KEY-1`, ... headers.
fn header_chunks<B>(req: &Request<B>, key: &str) -> String {
    (0..)
        .map_while(|i| {
            req.headers()
                .get(format!("{key}-{i}"))
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
        })
        .collect()
}

/// Uplink data split over `KEY_0`, `KEY_1`, ... cookies.
fn cookie_chunks<B>(req: &Request<B>, key: &str) -> String {
    (0..)
        .map_while(|i| cookie(req, &format!("{key}_{i}")))
        .collect()
}

fn origin<B>(req: &Request<B>) -> HeaderValue {
    req.headers()
        .get("Origin")
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("*"))
}

fn host_matches<B>(req: &Request<B>, expected: &str) -> bool {
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

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    let query = query.split('#').next().unwrap_or_default();
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn h3_status(code: StatusCode) -> Response<()> {
    Response::builder().status(code).body(()).unwrap()
}

fn h3_response(builder: http::response::Builder, code: StatusCode) -> Response<()> {
    builder
        .status(code)
        .body(())
        .unwrap_or_else(|_| h3_status(code))
}

pub(crate) fn build_quic_transport_config(
    config: &H3QuicConfig,
) -> Result<quinn::TransportConfig, String> {
    let mut transport = quinn::TransportConfig::default();

    let idle_timeout = config
        .max_idle_timeout
        .try_into()
        .map_err(|_| "invalid maxIdleTimeout".to_string())?;
    transport.max_idle_timeout(Some(idle_timeout));

    if let Some(keep_alive) = config.keep_alive_interval {
        transport.keep_alive_interval(Some(keep_alive));
    }

    let stream_win = quinn::VarInt::try_from(config.initial_stream_receive_window)
        .map_err(|_| "initStreamReceiveWindow too large".to_string())?;
    transport.stream_receive_window(stream_win);

    let conn_win = quinn::VarInt::try_from(config.initial_connection_receive_window)
        .map_err(|_| "initConnectionReceiveWindow too large".to_string())?;
    transport.receive_window(conn_win);

    let max_incoming = if config.max_incoming_bidirectional_streams > 0 {
        quinn::VarInt::try_from(config.max_incoming_bidirectional_streams)
            .map_err(|_| "maxIncomingStreams too large".to_string())?
    } else {
        1024u32.into()
    };
    transport.max_concurrent_bidi_streams(max_incoming);
    transport.max_concurrent_uni_streams(1024u32.into());
    transport.send_window(20_971_520);

    if config.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    transport.enable_segmentation_offload(!config.disable_gso);

    match config.congestion {
        H3Congestion::Reno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        _ => {
            let bbr = quinn::congestion::BbrConfig::default();
            transport.congestion_controller_factory(Arc::new(bbr));
        }
    }

    Ok(transport)
}

pub async fn start_h3(
    inbound: &Inbound,
    ctx: Arc<vless::Context>,
    settings: XhttpSettings,
) -> Result<tokio::task::AbortHandle, String> {
    if inbound.has_udphop {
        let addr_str = if inbound.listen.is_empty() {
            "0.0.0.0"
        } else {
            &inbound.listen
        };
        return Err(format!(
            "failed to listen on address: {}:{} > transport/internet/finalmask/udphop: udphop: client only",
            addr_str, inbound.port
        ));
    }

    let tls_settings = inbound.tls.as_ref().ok_or("XHTTP/3 requires TLS")?;
    let rustls_config =
        crate::build_rustls_server_config(tls_settings, vec![b"h3".to_vec()], true)?;
    let quic_server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))
            .map_err(|e| format!("quic server tls: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));

    let h3_config = crate::xhttp_outbound::xhttp_h3_quic_config(inbound.quic_params.as_ref())?;
    let transport_config = build_quic_transport_config(&h3_config)?;
    server_config.transport_config(Arc::new(transport_config));

    let listen_addr: SocketAddr = if inbound.listen.is_empty() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), inbound.port)
    } else {
        inbound
            .listen
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, inbound.port))
            .map_err(|e| format!("invalid listen address: {e}"))?
    };

    let tokio_socket = crate::sockopt::bind_udp(listen_addr, inbound.sockopt.as_ref())
        .map_err(|e| format!("failed to listen UDP for XHTTP/3 on {}: {e}", listen_addr))?;
    let std_socket = tokio_socket
        .into_std()
        .map_err(|e| format!("failed to convert UDP socket on {}: {e}", listen_addr))?;
    let tokio_socket = quinn::TokioRuntime
        .wrap_udp_socket(std_socket)
        .map_err(|e| e.to_string())?;

    let abstract_socket: Arc<dyn quinn::AsyncUdpSocket> =
        if let Some(pwd) = &inbound.hysteria_salamander {
            Arc::new(crate::hysteria::ServerCarrierSocket::new(
                tokio_socket,
                Arc::new(zeroize::Zeroizing::new(pwd.clone())),
                inbound.hysteria_gecko,
            ))
        } else {
            tokio_socket
        };

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        abstract_socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| format!("failed to listen QUIC for XHTTP/3 on {}: {e}", listen_addr))?;

    crate::log::info(format!("listening {} on {}", inbound.tag, listen_addr));

    let mut handler = Handler::new(settings, ctx);
    let trusted_xff = inbound
        .sockopt
        .as_ref()
        .map(|s| s.trusted_x_forwarded_for.clone())
        .unwrap_or_default();
    handler.with_trusted_x_forwarded_for(trusted_xff);
    let task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let connection = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    crate::log::debug(format!("quic handshake failed: {e}"));
                    continue;
                }
            };
            let h = handler.clone();
            tokio::spawn(async move {
                let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(
                    connection.clone(),
                ))
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        crate::log::debug(format!("h3 handshake failed: {e}"));
                        return;
                    }
                };
                let peer = connection.remote_address();
                loop {
                    let resolver = match h3_conn.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) => break,
                        Err(e) => {
                            crate::log::debug(format!("h3 accept failed: {e}"));
                            break;
                        }
                    };
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            crate::log::debug(format!("h3 resolve request failed: {e}"));
                            continue;
                        }
                    };
                    let h = h.clone();
                    tokio::spawn(async move {
                        h.handle_h3(req, stream, peer).await;
                    });
                }
            });
        }
    });

    Ok(task.abort_handle())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_query_values() {
        assert_eq!(query_value("a=1&x_padding=XXX", "x_padding"), Some("XXX"));
        assert_eq!(query_value("x_padding=XX#frag", "x_padding"), Some("XX"));
        assert_eq!(query_value("x_paddingz=1", "x_padding"), None);
    }

    #[test]
    fn strips_ports() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("[::1]:443"), "::1");
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn test_xhttp_inbound_h3_detection() {
        let raw = serde_json::json!({
            "inbounds": [{
                "tag": "xhttp-h3",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["h3"],
                        "certificates": [{"certificate": ["CERT"], "key": ["KEY"]}]
                    },
                    "quicParams": {
                        "congestion": "bbr",
                        "initStreamReceiveWindow": 65536
                    },
                    "xhttpSettings": {
                        "path": "/xh"
                    }
                }
            }]
        });
        let parsed = crate::config::parse(&raw.to_string()).unwrap();
        let inbound = &parsed.inbounds[0];
        assert_eq!(inbound.tls.as_ref().unwrap().alpn, vec!["h3"]);
        assert!(matches!(
            inbound.transport,
            crate::config::InboundTransport::Xhttp(_)
        ));
        let qp = inbound.quic_params.as_ref().unwrap();
        assert_eq!(qp.init_stream_receive_window, 65536);
    }
}
