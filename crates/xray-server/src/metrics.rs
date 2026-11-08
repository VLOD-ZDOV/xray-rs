//! The `metrics` section: Xray's `/debug/vars` with traffic counters and the
//! observatory status, on its own listener and as an outbound tag.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::observatory::Observatory;
use crate::{log, stats};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub tag: String,
    pub listen: Option<SocketAddr>,
}

pub fn parse(root: &Value) -> Result<Option<Settings>, String> {
    let Some(section) = root.get("metrics").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let text = |key: &str| match section.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(format!("metrics: {key} must be a string")),
    };
    let tag = text("tag")?;
    let listen = text("listen")?;
    if tag.is_empty() && listen.is_empty() {
        return Err("Metrics must have a tag or listen address.".into());
    }
    let listen = match listen {
        "" => None,
        addr => Some(match addr.parse() {
            Ok(a) => a,
            Err(_) => std::net::ToSocketAddrs::to_socket_addrs(addr)
                .ok()
                .and_then(|mut it| it.next())
                .ok_or_else(|| format!("metrics: invalid listen {addr:?}"))?,
        }),
    };
    Ok(Some(Settings {
        // Xray names the outbound "Metrics" when only listen is set.
        tag: if tag.is_empty() { "Metrics" } else { tag }.to_owned(),
        listen,
    }))
}

static OBSERVATORY: OnceLock<Option<Arc<Observatory>>> = OnceLock::new();

pub fn init(observatory: Option<Arc<Observatory>>) {
    let _ = OBSERVATORY.set(observatory);
}

pub async fn listen(addr: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("metrics: failed to listen on {addr}: {e}"))?;
    log::info(format!("Metrics server listening on {addr}"));
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(serve(stream));
                }
                Err(e) => {
                    log::warn(format!("metrics accept failed: {e}"));
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(())
}

/// Serves HTTP/1 on one connection: a socket, or the inner end of the
/// metrics outbound.
pub async fn serve<S>(io: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async move {
        Ok::<_, Infallible>(respond(req.uri().path()))
    });
    // hyper ignores header_read_timeout unless a timer is set.
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(30))
        .serve_connection(TokioIo::new(io), service)
        .await;
}

fn respond(path: &str) -> Response<Full<Bytes>> {
    // pprof is the Go runtime's profiler; there is nothing like it to serve.
    if path != "/debug/vars" {
        let mut not_found = Response::new(Full::new(Bytes::from_static(b"404 page not found\n")));
        *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
        not_found.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return not_found;
    }
    let mut response = Response::new(Full::new(Bytes::from(debug_vars().to_string())));
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

/// Xray's `/debug/vars`: Go's expvar `cmdline`, then `stats` split from the
/// `type>>>tag>>>traffic>>>direction` counter names, and `observatory`.
/// Go's `memstats` describes its own runtime and is left out.
fn debug_vars() -> Value {
    let mut grouped: BTreeMap<String, BTreeMap<String, BTreeMap<String, i64>>> =
        ["inbound", "outbound", "user"]
            .into_iter()
            .map(|kind| (kind.to_owned(), BTreeMap::new()))
            .collect();
    for (name, value) in stats::get().query("", false) {
        let parts: Vec<&str> = name.split(">>>").collect();
        if parts.len() < 4 {
            continue;
        }
        grouped
            .entry(parts[0].to_owned())
            .or_default()
            .entry(parts[1].to_owned())
            .or_default()
            .insert(parts[3].to_owned(), value);
    }
    let observatory = match OBSERVATORY.get().and_then(Option::as_ref) {
        None => Value::Null,
        Some(observatory) => json!(observatory
            .get_observation()
            .into_iter()
            .map(|status| (status.outbound_tag.clone(), outbound_status(&status)))
            .collect::<BTreeMap<_, _>>()),
    };
    json!({
        "cmdline": std::env::args_os()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        "observatory": observatory,
        "stats": grouped,
    })
}

/// The protobuf struct as Go's encoding/json writes it: snake_case names,
/// zero values left out.
fn outbound_status(status: &crate::observatory::OutboundStatus) -> Value {
    let mut out = Map::new();
    let mut put = |key: &str, value: Value, keep: bool| {
        if keep {
            out.insert(key.to_owned(), value);
        }
    };
    put("alive", json!(status.alive), status.alive);
    put("delay", json!(status.delay), status.delay != 0);
    put(
        "last_error_reason",
        json!(status.last_error_reason),
        !status.last_error_reason.is_empty(),
    );
    put(
        "outbound_tag",
        json!(status.outbound_tag),
        !status.outbound_tag.is_empty(),
    );
    put(
        "last_seen_time",
        json!(status.last_seen_time),
        status.last_seen_time != 0,
    );
    put(
        "last_try_time",
        json!(status.last_try_time),
        status.last_try_time != 0,
    );
    if let Some(ping) = &status.health_ping {
        let mut health = Map::new();
        for (key, value) in [
            ("all", ping.all),
            ("fail", ping.fail),
            ("deviation", ping.deviation),
            ("average", ping.average),
            ("max", ping.max),
            ("min", ping.min),
        ] {
            if value != 0 {
                health.insert(key.to_owned(), json!(value));
            }
        }
        put("health_ping", Value::Object(health), true);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_accepts_a_hostname() {
        let root = json!({"metrics": {"listen": "localhost:11111"}});
        let settings = parse(&root).unwrap().unwrap();
        assert_eq!(settings.listen.unwrap().port(), 11111);
        assert!(parse(&json!({"metrics": {"listen": "no port"}})).is_err());
    }
}
