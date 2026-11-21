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
use crate::stats;

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
    crate::log::info!("Metrics server listening on {addr}");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(serve(stream));
                }
                Err(e) => {
                    crate::log::warn!("metrics accept failed: {e}");
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
    match path {
        "/debug/vars" => {
            let mut response = Response::new(Full::new(Bytes::from(debug_vars().to_string())));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json; charset=utf-8"),
            );
            response
        }
        "/metrics" => {
            let mut response = Response::new(Full::new(Bytes::from(prometheus_metrics())));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            response
        }
        _ => {
            let mut not_found =
                Response::new(Full::new(Bytes::from_static(b"404 page not found\n")));
            *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
            not_found.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            not_found
        }
    }
}

/// Prometheus text exposition format (/metrics) for monitoring and Grafana scraping.
fn prometheus_metrics() -> String {
    let mut out = String::new();
    out.push_str("# HELP xray_uptime_seconds Process uptime in seconds\n");
    out.push_str("# TYPE xray_uptime_seconds gauge\n");
    out.push_str(&format!(
        "xray_uptime_seconds {}\n\n",
        stats::get().uptime_secs()
    ));

    out.push_str("# HELP xray_traffic_bytes_total Total bytes transferred\n");
    out.push_str("# TYPE xray_traffic_bytes_total counter\n");
    for (name, val) in stats::get().query("", false) {
        let parts: Vec<&str> = name.split(">>>").collect();
        if parts.len() >= 4 && parts[2] == "traffic" {
            let kind = parts[0];
            let tag = parts[1];
            let direction = parts[3];
            out.push_str(&format!(
                "xray_traffic_bytes_total{{kind=\"{kind}\",tag=\"{tag}\",direction=\"{direction}\"}} {val}\n"
            ));
        }
    }
    out.push('\n');

    let online = stats::get().online_users();
    if !online.is_empty() {
        out.push_str("# HELP xray_user_online_connections Active connection count per user\n");
        out.push_str("# TYPE xray_user_online_connections gauge\n");
        for (email, ips) in online {
            out.push_str(&format!(
                "xray_user_online_connections{{user=\"{email}\"}} {}\n",
                ips.len()
            ));
        }
        out.push('\n');
    }

    if let Some(Some(observatory)) = OBSERVATORY.get() {
        let statuses = observatory.get_observation();
        if !statuses.is_empty() {
            out.push_str("# HELP xray_observatory_alive Whether outbound is reachable\n");
            out.push_str("# TYPE xray_observatory_alive gauge\n");
            for s in &statuses {
                let alive = if s.alive { 1 } else { 0 };
                out.push_str(&format!(
                    "xray_observatory_alive{{outbound=\"{}\"}} {alive}\n",
                    s.outbound_tag
                ));
            }
            out.push_str("\n# HELP xray_observatory_delay_ms Outbound delay in milliseconds\n");
            out.push_str("# TYPE xray_observatory_delay_ms gauge\n");
            for s in &statuses {
                out.push_str(&format!(
                    "xray_observatory_delay_ms{{outbound=\"{}\"}} {}\n",
                    s.outbound_tag, s.delay
                ));
            }
            out.push('\n');
        }
    }

    out
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

    #[test]
    fn absent_metrics_section_disables_metrics() {
        assert_eq!(parse(&json!({})).unwrap(), None);
    }
    #[test]
    fn null_metrics_section_disables_metrics() {
        assert_eq!(parse(&json!({"metrics": null})).unwrap(), None);
    }
    #[test]
    fn empty_metrics_section_requires_a_destination() {
        assert!(parse(&json!({"metrics": {}})).is_err());
    }
    #[test]
    fn tag_alone_is_valid() {
        assert_eq!(
            parse(&json!({"metrics": {"tag": "stats"}}))
                .unwrap()
                .unwrap()
                .tag,
            "stats"
        );
    }
    #[test]
    fn listen_only_uses_xray_default_tag() {
        assert_eq!(
            parse(&json!({"metrics": {"listen": "127.0.0.1:1234"}}))
                .unwrap()
                .unwrap()
                .tag,
            "Metrics"
        );
    }
    #[test]
    fn explicit_tag_is_preserved_with_listener() {
        assert_eq!(
            parse(&json!({"metrics": {"tag": "custom", "listen": "127.0.0.1:80"}}))
                .unwrap()
                .unwrap()
                .tag,
            "custom"
        );
    }
    #[test]
    fn metrics_tag_must_be_a_string() {
        assert!(parse(&json!({"metrics": {"tag": 7}}))
            .unwrap_err()
            .contains("tag must be a string"));
    }
    #[test]
    fn metrics_listen_must_be_a_string() {
        assert!(parse(&json!({"metrics": {"tag": "x", "listen": false}}))
            .unwrap_err()
            .contains("listen must be a string"));
    }
    #[test]
    fn empty_tag_is_treated_as_missing() {
        assert!(parse(&json!({"metrics": {"tag": ""}})).is_err());
    }
    #[test]
    fn empty_listener_with_tag_is_allowed() {
        assert_eq!(
            parse(&json!({"metrics": {"tag": "x", "listen": ""}}))
                .unwrap()
                .unwrap()
                .listen,
            None
        );
    }
    #[test]
    fn ipv4_listener_address_is_parsed() {
        assert_eq!(
            parse(&json!({"metrics": {"listen": "192.0.2.1:3000"}}))
                .unwrap()
                .unwrap()
                .listen
                .unwrap()
                .port(),
            3000
        );
    }
    #[test]
    fn ipv6_listener_address_is_parsed() {
        assert_eq!(
            parse(&json!({"metrics": {"listen": "[::1]:3001"}}))
                .unwrap()
                .unwrap()
                .listen
                .unwrap()
                .port(),
            3001
        );
    }
    #[test]
    fn unsupported_listener_scheme_is_rejected() {
        assert!(parse(&json!({"metrics": {"listen": "http://localhost"}})).is_err());
    }
    #[test]
    fn debug_vars_route_is_json() {
        assert_eq!(
            respond("/debug/vars").headers()[hyper::header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
    }
    #[test]
    fn metrics_route_is_prometheus_format() {
        let resp = respond("/metrics");
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(
            resp.headers()[hyper::header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }
    #[test]
    fn unknown_metrics_route_is_not_found() {
        assert_eq!(
            respond("/debug/pprof").status(),
            hyper::StatusCode::NOT_FOUND
        );
    }
    #[test]
    fn unknown_route_has_xray_plain_text_body() {
        let r = respond("/");
        assert_eq!(
            r.headers()[hyper::header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
    }
    #[test]
    fn empty_outbound_status_omits_zero_values() {
        let status = crate::observatory::OutboundStatus {
            alive: false,
            delay: 0,
            last_error_reason: String::new(),
            outbound_tag: String::new(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        };
        assert!(outbound_status(&status).as_object().unwrap().is_empty());
    }
    #[test]
    fn outbound_status_keeps_nonzero_delay() {
        let status = crate::observatory::OutboundStatus {
            alive: false,
            delay: 23,
            last_error_reason: String::new(),
            outbound_tag: String::new(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        };
        assert_eq!(outbound_status(&status)["delay"], 23);
    }
    #[test]
    fn outbound_status_keeps_nonempty_error() {
        let status = crate::observatory::OutboundStatus {
            alive: false,
            delay: 0,
            last_error_reason: "offline".into(),
            outbound_tag: String::new(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        };
        assert_eq!(outbound_status(&status)["last_error_reason"], "offline");
    }
    #[test]
    fn outbound_status_keeps_health_ping_even_when_all_zero() {
        let status = crate::observatory::OutboundStatus {
            alive: false,
            delay: 0,
            last_error_reason: String::new(),
            outbound_tag: String::new(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: Some(crate::observatory::HealthPingStats::default()),
        };
        assert!(outbound_status(&status).get("health_ping").is_some());
    }
    #[test]
    fn outbound_status_keeps_alive_true() {
        let status = crate::observatory::OutboundStatus {
            alive: true,
            delay: 0,
            last_error_reason: String::new(),
            outbound_tag: String::new(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        };
        assert_eq!(outbound_status(&status)["alive"], true);
    }
}
