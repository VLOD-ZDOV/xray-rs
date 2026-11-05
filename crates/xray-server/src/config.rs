//! Subset of the Xray JSON config that this server understands. Unknown or
//! unsupported entries are skipped with a warning so a full 3x-ui config loads.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde_json::Value;
use uuid::Uuid;

use crate::log;
use crate::routing::Router;
use crate::stats;

pub struct Config {
    pub log: log::Settings,
    /// gRPC API address from the inbound tagged like `api.tag` (or `api.listen`).
    pub api: Option<SocketAddr>,
    pub stats: stats::Policy,
    pub inbounds: Vec<Inbound>,
    pub router: Router,
}

#[derive(Debug)]
pub struct Inbound {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub users: Vec<User>,
    pub tls: Option<TlsSettings>,
    pub xhttp: XhttpSettings,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: [u8; 16],
    pub email: String,
}

/// Like Xray, a non-UUID id maps to UUIDv5 in the nil namespace.
pub fn user_id(id: &str) -> [u8; 16] {
    *Uuid::parse_str(id).unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id.as_bytes())).as_bytes()
}

#[derive(Debug)]
pub struct TlsSettings {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct XhttpSettings {
    pub path: String,
    pub host: String,
    pub mode: String,
    pub padding: (usize, usize),
    pub no_sse_header: bool,
    pub max_each_post: usize,
    pub max_buffered_posts: usize,
}

pub fn load(path: &str) -> Result<Config, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    parse(&raw)
}

pub fn parse(raw: &str) -> Result<Config, String> {
    let root: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let api_tag = root.get("api").map(|api| str_field(api, "tag")).filter(|t| !t.is_empty());
    let mut api = match root.get("api").map(|a| str_field(a, "listen")) {
        Some(listen) if !listen.is_empty() => Some(listen.parse().map_err(|_| format!("invalid api.listen {listen:?}"))?),
        _ => None,
    };
    let mut inbounds = Vec::new();
    for (index, item) in array(&root, "inbounds").iter().enumerate() {
        let tag = str_field(item, "tag").to_owned();
        if api.is_none() && api_tag == Some(tag.as_str()) {
            let port = parse_port(item.get("port")).ok_or("api inbound: invalid port")?;
            let listen = match str_field(item, "listen") {
                "" => "127.0.0.1",
                addr => addr,
            };
            let ip = listen.parse().map_err(|_| format!("api inbound: invalid listen {listen:?}"))?;
            api = Some(SocketAddr::new(ip, port));
            continue;
        }
        let label = if tag.is_empty() { format!("#{index}") } else { tag.clone() };
        match parse_inbound(item, tag) {
            Ok(Some(inbound)) => inbounds.push(inbound),
            Ok(None) => {}
            Err(e) => return Err(format!("inbound {label}: {e}")),
        }
    }
    let router = Router::build(&root, &asset_dirs())?;
    let section = root.get("log").unwrap_or(&Value::Null);
    let log = log::Settings {
        level: str_field(section, "loglevel").to_owned(),
        access: str_field(section, "access").to_owned(),
        error: str_field(section, "error").to_owned(),
        mask_address: str_field(section, "maskAddress").to_owned(),
    };
    Ok(Config { log, api, stats: stats::Policy::from_config(&root), inbounds, router })
}

fn parse_inbound(item: &Value, tag: String) -> Result<Option<Inbound>, String> {
    let protocol = str_field(item, "protocol");
    let stream = item.get("streamSettings").unwrap_or(&Value::Null);
    let network = str_field(stream, "network");
    let security = str_field(stream, "security");

    let supported_network = matches!(network, "xhttp" | "splithttp");
    let supported_security = matches!(security, "" | "none" | "tls");
    if protocol != "vless" || !supported_network || !supported_security {
        log::warn(format!(
            "skipping inbound {tag:?}: {protocol}/{}/{} is not supported yet",
            if network.is_empty() { "tcp" } else { network },
            if security.is_empty() { "none" } else { security },
        ));
        return Ok(None);
    }

    let port = parse_port(item.get("port")).ok_or("invalid or missing port")?;
    let listen = match str_field(item, "listen") {
        "" => String::new(),
        addr if addr.starts_with('/') || addr.starts_with('@') => {
            return Err("unix socket listen is not supported".into());
        }
        addr => addr.to_owned(),
    };

    let settings = item.get("settings").unwrap_or(&Value::Null);
    let decryption = str_field(settings, "decryption");
    if !decryption.is_empty() && decryption != "none" {
        return Err("VLESS encryption (decryption != none) is not supported".into());
    }
    let mut users = Vec::new();
    for client in array(settings, "clients") {
        let flow = str_field(client, "flow");
        if !flow.is_empty() {
            log::warn(format!("inbound {tag:?}: flow {flow:?} is ignored for xhttp"));
        }
        users.push(User { id: user_id(str_field(client, "id")), email: str_field(client, "email").to_owned() });
    }

    let tls = if security == "tls" { Some(parse_tls(stream.get("tlsSettings").unwrap_or(&Value::Null))?) } else { None };
    let xhttp = parse_xhttp(stream.get("xhttpSettings").or_else(|| stream.get("splithttpSettings")).unwrap_or(&Value::Null))?;

    Ok(Some(Inbound { tag, listen, port, users, tls, xhttp }))
}

fn parse_tls(tls: &Value) -> Result<TlsSettings, String> {
    let cert = array(tls, "certificates").first().ok_or("tlsSettings.certificates is empty")?;
    let cert_pem = inline_or_file(cert, "certificate", "certificateFile")?;
    let key_pem = inline_or_file(cert, "key", "keyFile")?;
    let alpn = array(tls, "alpn").iter().filter_map(Value::as_str).map(str::to_owned).collect();
    Ok(TlsSettings { cert_pem, key_pem, alpn })
}

fn inline_or_file(cert: &Value, inline_key: &str, file_key: &str) -> Result<Vec<u8>, String> {
    let lines: Vec<&str> = array(cert, inline_key).iter().filter_map(Value::as_str).collect();
    if !lines.is_empty() {
        return Ok(lines.join("\n").into_bytes());
    }
    let path = str_field(cert, file_key);
    if path.is_empty() {
        return Err(format!("certificate needs {inline_key} or {file_key}"));
    }
    fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))
}

fn parse_xhttp(x: &Value) -> Result<XhttpSettings, String> {
    let mut path = str_field(x, "path").split('?').next().unwrap_or_default().to_owned();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    let mode = match str_field(x, "mode") {
        "" => "auto",
        m @ ("auto" | "packet-up" | "stream-up" | "stream-one") => m,
        other => return Err(format!("unknown xhttp mode {other:?}")),
    };
    for key in ["xPaddingObfsMode"] {
        if x.get(key).and_then(Value::as_bool).unwrap_or(false) {
            return Err(format!("xhttpSettings.{key} is not supported yet"));
        }
    }
    let padding = parse_range(x.get("xPaddingBytes")).filter(|r| r.1 > 0).unwrap_or((100, 1000));
    let max_each_post = parse_range(x.get("scMaxEachPostBytes")).filter(|r| r.1 > 0).map_or(1_000_000, |r| r.1);
    let max_buffered_posts = x.get("scMaxBufferedPosts").and_then(Value::as_u64).filter(|n| *n > 0).unwrap_or(30) as usize;
    Ok(XhttpSettings {
        path,
        host: str_field(x, "host").to_owned(),
        mode: mode.to_owned(),
        padding,
        no_sse_header: x.get("noSSEHeader").and_then(Value::as_bool).unwrap_or(false),
        max_each_post,
        max_buffered_posts,
    })
}

/// Xray accepts ranges as `123`, `"100-1000"` or `{"from":..,"to":..}`.
fn parse_range(value: Option<&Value>) -> Option<(usize, usize)> {
    match value? {
        Value::Number(n) => n.as_u64().map(|n| (n as usize, n as usize)),
        Value::String(s) => {
            let (from, to) = s.split_once('-').unwrap_or((s, s));
            Some((from.trim().parse().ok()?, to.trim().parse().ok()?))
        }
        Value::Object(o) => {
            let get = |k: &str| o.get(k).and_then(Value::as_u64).unwrap_or(0) as usize;
            Some((get("from"), get("to")))
        }
        _ => None,
    }
}

fn parse_port(value: Option<&Value>) -> Option<u16> {
    match value? {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Where geoip.dat/geosite.dat live; the parser also adds the binary's directory.
fn asset_dirs() -> Vec<PathBuf> {
    std::env::var_os("XRAY_LOCATION_ASSET").map(PathBuf::from).into_iter().collect()
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANEL_LIKE: &str = r#"{
      "log": {"loglevel": "warning"},
      "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
      "inbounds": [
        {"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}},
        {"tag": "inbound-443", "listen": null, "port": 443, "protocol": "vless",
         "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "user1", "flow": ""}], "decryption": "none"},
         "streamSettings": {"network": "xhttp", "security": "tls",
           "tlsSettings": {"alpn": ["h2", "http/1.1"], "certificates": [{"certificate": ["CERT"], "key": ["KEY"]}]},
           "xhttpSettings": {"path": "/xh", "host": "", "mode": "auto", "xPaddingBytes": "100-1000"}}},
        {"tag": "inbound-8443", "port": 8443, "protocol": "vless",
         "streamSettings": {"network": "tcp", "security": "reality"}}
      ],
      "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}],
      "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                            {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]}]}
    }"#;

    #[test]
    fn loads_panel_config_and_skips_unsupported() {
        let config = parse(PANEL_LIKE).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.port, 443);
        assert_eq!(inbound.xhttp.path, "/xh/");
        assert_eq!(inbound.xhttp.padding, (100, 1000));
        assert_eq!(inbound.users[0].email, "user1");
        assert_eq!(inbound.tls.as_ref().unwrap().cert_pem, b"CERT");
    }

    #[test]
    fn parses_range_forms() {
        assert_eq!(parse_range(Some(&serde_json::json!(5))), Some((5, 5)));
        assert_eq!(parse_range(Some(&serde_json::json!("10-20"))), Some((10, 20)));
        assert_eq!(parse_range(Some(&serde_json::json!({"from": 1, "to": 2}))), Some((1, 2)));
    }
}
