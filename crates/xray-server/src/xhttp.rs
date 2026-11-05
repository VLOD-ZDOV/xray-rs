//! XHTTP (splithttp) server side: stream-one, stream-up and packet-up modes over
//! HTTP/1.1 and HTTP/2, mirroring Xray-core's transport/internet/splithttp/hub.go.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use http::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, REFERER, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::config::{Meta, Placement, XhttpSettings};
use crate::{log, padding, vless};

pub type Body = BoxBody<Bytes, io::Error>;

const PIPE_SIZE: usize = 256 * 1024;
const SESSION_TTL: Duration = Duration::from_secs(30);

pub struct Handler {
    settings: XhttpSettings,
    vless: Arc<vless::Context>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
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
        })
    }

    pub async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<Body> {
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

    fn response_headers(&self, req: &Request<Incoming>) -> http::response::Builder {
        let s = &self.settings;
        let mut response = Response::builder().header("Access-Control-Allow-Origin", origin(req));
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
    fn request_padding(&self, req: &Request<Incoming>, referer: Option<&str>) -> String {
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
fn meta<'a>(
    req: &Request<Incoming>,
    meta: &Meta,
    path: &mut impl Iterator<Item = &'a str>,
) -> String {
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

fn cookie(req: &Request<Incoming>, name: &str) -> Option<String> {
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
fn header_chunks(req: &Request<Incoming>, key: &str) -> String {
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
fn cookie_chunks(req: &Request<Incoming>, key: &str) -> String {
    (0..)
        .map_while(|i| cookie(req, &format!("{key}_{i}")))
        .collect()
}

fn origin(req: &Request<Incoming>) -> HeaderValue {
    req.headers()
        .get("Origin")
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("*"))
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
}
