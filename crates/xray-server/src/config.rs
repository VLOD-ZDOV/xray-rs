//! Subset of the Xray JSON config that this server understands. Unknown or
//! unsupported entries are skipped with a warning so a full 3x-ui config loads.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use http::{HeaderName, HeaderValue};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundTransport {
    Tcp,
    Websocket(crate::ws::WsSettings),
    HttpUpgrade(crate::httpupgrade::HttpUpgradeSettings),
    Grpc(crate::grpc::GrpcSettings),
    Xhttp(Box<XhttpSettings>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundProtocol {
    Vless,
    Trojan,
    Vmess,
    Socks,
    Http,
    Shadowsocks,
    Dokodemo,
}

#[derive(Clone, Debug)]
pub struct DokodemoSettings {
    pub address: Option<crate::vless::Host>,
    pub port: Option<u16>,
    #[allow(dead_code)]
    pub follow_redirect: bool,
}

#[derive(Clone, Debug)]
pub enum ShadowsocksMethod {
    Aead2017(Arc<xray_proxy::shadowsocks::aead2017::Method>),
    Ss2022(Arc<xray_proxy::shadowsocks2022::Method>),
}

#[derive(Clone, Debug)]
pub struct ShadowsocksUser {
    pub method: ShadowsocksMethod,
    pub email: String,
}

#[derive(Clone, Debug)]
pub struct Fallback {
    pub path: String,
    pub dest: FallbackDest,
    pub xver: u8,
}

#[derive(Clone, Debug)]
pub enum FallbackDest {
    Tcp(crate::vless::Host, u16),
    /// A socket path; `@name` is abstract and `@@name` abstract padded like Xray.
    Unix(String),
}

#[derive(Debug)]
pub struct Inbound {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub protocol: InboundProtocol,
    pub users: Vec<User>,
    pub shadowsocks_users: Vec<ShadowsocksUser>,
    pub fallbacks: Vec<Fallback>,
    pub socks_auth: xray_proxy::inbound::SocksInboundAuth,
    pub udp: bool,
    pub sniffing: crate::vless::Sniffing,
    pub dokodemo: Option<DokodemoSettings>,
    pub http_obfs: Option<crate::http_obfs::HttpObfsSettings>,
    pub tls: Option<TlsSettings>,
    pub transport: InboundTransport,
    pub accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: [u8; 16],
    pub hash: [u8; 56],
    pub email: String,
}

/// Like Xray, a non-UUID id maps to UUIDv5 in the nil namespace.
pub fn user_id(id: &str) -> [u8; 16] {
    *Uuid::parse_str(id)
        .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id.as_bytes()))
        .as_bytes()
}

#[derive(Debug, Clone)]
pub struct TlsSettings {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
    pub server_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpSettings {
    pub path: String,
    pub host: String,
    pub mode: String,
    pub padding: (usize, usize),
    /// `xPaddingObfsMode`; `None` keeps the legacy Referer/query `x_padding`.
    pub padding_obfs: Option<PaddingObfs>,
    pub session: Meta,
    pub seq: Meta,
    pub uplink_data: Meta,
    pub stream_up_secs: (u64, u64),
    pub no_sse_header: bool,
    pub max_each_post: usize,
    pub max_buffered_posts: usize,
    pub response_headers: Vec<(HeaderName, HeaderValue)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    QueryInHeader,
    Body,
    Auto,
}

/// Where a piece of XHTTP metadata travels and under which name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub placement: Placement,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingObfs {
    pub key: String,
    pub header: String,
    pub placement: Placement,
    pub tokenish: bool,
}

pub fn load(path: &str) -> Result<Config, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    parse(&raw)
}

pub fn parse(raw: &str) -> Result<Config, String> {
    let root: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let api_tag = root
        .get("api")
        .map(|api| str_field(api, "tag"))
        .filter(|t| !t.is_empty());
    let mut api = match root.get("api").map(|a| str_field(a, "listen")) {
        Some(listen) if !listen.is_empty() => Some(
            listen
                .parse()
                .map_err(|_| format!("invalid api.listen {listen:?}"))?,
        ),
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
            let ip = listen
                .parse()
                .map_err(|_| format!("api inbound: invalid listen {listen:?}"))?;
            api = Some(SocketAddr::new(ip, port));
            continue;
        }
        let label = if tag.is_empty() {
            format!("#{index}")
        } else {
            tag.clone()
        };
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
    Ok(Config {
        log,
        api,
        stats: stats::Policy::from_config(&root),
        inbounds,
        router,
    })
}

fn parse_inbound(item: &Value, tag: String) -> Result<Option<Inbound>, String> {
    let protocol = match str_field(item, "protocol") {
        "vless" => InboundProtocol::Vless,
        "trojan" => InboundProtocol::Trojan,
        "vmess" => InboundProtocol::Vmess,
        "socks" => InboundProtocol::Socks,
        "http" => InboundProtocol::Http,
        "shadowsocks" => InboundProtocol::Shadowsocks,
        "dokodemo-door" | "dokodemo" => InboundProtocol::Dokodemo,
        other => {
            log::warn(format!(
                "skipping inbound {tag:?}: protocol {other:?} is not supported yet"
            ));
            return Ok(None);
        }
    };
    let stream = item.get("streamSettings").unwrap_or(&Value::Null);
    let network = str_field(stream, "network");
    let security = str_field(stream, "security");

    let is_tcp = matches!(network, "" | "tcp" | "raw");
    let is_ws = matches!(network, "ws" | "websocket");
    let is_httpupgrade = network == "httpupgrade";
    let is_grpc = matches!(network, "grpc" | "gun");
    let is_xhttp = matches!(network, "xhttp" | "splithttp");
    let supported_security = matches!(security, "" | "none" | "tls");
    if (!is_tcp && !is_ws && !is_httpupgrade && !is_grpc && !is_xhttp) || !supported_security {
        log::warn(format!(
            "skipping inbound {tag:?}: {:?}/{}/{} is not supported yet",
            protocol,
            if network.is_empty() { "tcp" } else { network },
            if security.is_empty() {
                "none"
            } else {
                security
            },
        ));
        return Ok(None);
    }
    let raw = stream
        .get("rawSettings")
        .or_else(|| stream.get("tcpSettings"));
    let header = raw.and_then(|r| r.get("header")).unwrap_or(&Value::Null);
    let header_type = str_field(header, "type");
    let http_obfs = if is_tcp && header_type == "http" {
        Some(parse_http_obfs(header))
    } else if is_tcp && !matches!(header_type, "" | "none") {
        log::warn(format!(
            "skipping inbound {tag:?}: tcp header obfuscation {header_type:?} is not supported yet"
        ));
        return Ok(None);
    } else {
        None
    };

    let port = parse_port(item.get("port")).ok_or("invalid or missing port")?;
    let listen = match str_field(item, "listen") {
        "" => String::new(),
        addr if addr.starts_with('/') || addr.starts_with('@') => {
            return Err("unix socket listen is not supported".into());
        }
        addr => addr.to_owned(),
    };

    let settings = item.get("settings").unwrap_or(&Value::Null);
    if protocol == InboundProtocol::Vless {
        let decryption = str_field(settings, "decryption");
        if !decryption.is_empty() && decryption != "none" {
            return Err("VLESS encryption (decryption != none) is not supported".into());
        }
    }
    let mut users = Vec::new();
    for client in array(settings, "clients") {
        let flow = str_field(client, "flow");
        if !flow.is_empty() {
            log::warn(format!("inbound {tag:?}: flow {flow:?} is ignored"));
        }
        let id_str = str_field(client, "id");
        let pass_str = str_field(client, "password");
        let key = if !pass_str.is_empty() {
            pass_str
        } else {
            id_str
        };
        users.push(User {
            id: user_id(key),
            hash: crate::trojan::trojan_password_hash(key),
            email: str_field(client, "email").to_owned(),
        });
    }

    let mut socks_accounts = Vec::new();
    for account in array(settings, "accounts") {
        let u = str_field(account, "user");
        let p = str_field(account, "pass");
        if let Some(acc) = xray_proxy::inbound::SocksAccount::new(u.as_bytes(), p.as_bytes()) {
            socks_accounts.push(acc);
        }
    }
    let auth_str = str_field(settings, "auth");
    let socks_auth = if auth_str == "password" || !socks_accounts.is_empty() {
        xray_proxy::inbound::SocksInboundAuth::Password(socks_accounts)
    } else {
        xray_proxy::inbound::SocksInboundAuth::NoAuth
    };
    let net_str = str_field(settings, "network");
    let udp = settings
        .get("udp")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || net_str.contains("udp");

    let mut shadowsocks_users = Vec::new();
    if protocol == InboundProtocol::Shadowsocks {
        let top_method = str_field(settings, "method");
        let top_password = str_field(settings, "password");
        let clients = array(settings, "clients");
        let is_ss2022 = top_method.starts_with("2022-blake3-");

        if is_ss2022 {
            if clients.is_empty() {
                let m = match xray_proxy::shadowsocks2022::Method::new(top_method, top_password) {
                    Ok(m) => m,
                    Err(e) => {
                        log::warn(format!(
                            "skipping inbound {tag:?}: shadowsocks 2022 {top_method:?}: {e}"
                        ));
                        return Ok(None);
                    }
                };
                shadowsocks_users.push(ShadowsocksUser {
                    method: ShadowsocksMethod::Ss2022(Arc::new(m)),
                    email: str_field(settings, "email").to_owned(),
                });
            } else {
                for entry in clients {
                    let method = match str_field(entry, "method") {
                        "" => top_method,
                        m => m,
                    };
                    let password = str_field(entry, "password");
                    let full_password = if top_password.is_empty() {
                        password.to_string()
                    } else {
                        format!("{top_password}:{password}")
                    };
                    let m = match xray_proxy::shadowsocks2022::Method::new(method, &full_password) {
                        Ok(m) => m,
                        Err(e) => {
                            log::warn(format!(
                                "skipping inbound {tag:?}: shadowsocks 2022 {method:?}: {e}"
                            ));
                            return Ok(None);
                        }
                    };
                    shadowsocks_users.push(ShadowsocksUser {
                        method: ShadowsocksMethod::Ss2022(Arc::new(m)),
                        email: str_field(entry, "email").to_owned(),
                    });
                }
            }
        } else {
            let entries: Vec<&Value> = if clients.is_empty() {
                vec![settings]
            } else {
                clients.iter().collect()
            };
            for entry in entries {
                let method = match str_field(entry, "method") {
                    "" => top_method,
                    m => m,
                };
                let password = str_field(entry, "password");
                let m = match xray_proxy::shadowsocks::aead2017::Method::new(method, password) {
                    Ok(m) => m,
                    Err(e) => {
                        log::warn(format!(
                            "skipping inbound {tag:?}: shadowsocks {method:?}: {e}"
                        ));
                        return Ok(None);
                    }
                };
                shadowsocks_users.push(ShadowsocksUser {
                    method: ShadowsocksMethod::Aead2017(Arc::new(m)),
                    email: str_field(entry, "email").to_owned(),
                });
            }
        }
    }

    let tls = if security == "tls" {
        Some(parse_tls(
            stream.get("tlsSettings").unwrap_or(&Value::Null),
        )?)
    } else {
        None
    };
    let transport = if is_tcp {
        InboundTransport::Tcp
    } else if is_ws {
        InboundTransport::Websocket(parse_ws(stream.get("wsSettings").unwrap_or(&Value::Null))?)
    } else if is_httpupgrade {
        InboundTransport::HttpUpgrade(parse_httpupgrade(
            stream.get("httpupgradeSettings").unwrap_or(&Value::Null),
        )?)
    } else if is_grpc {
        InboundTransport::Grpc(parse_grpc(
            stream
                .get("grpcSettings")
                .or_else(|| stream.get("gunSettings"))
                .unwrap_or(&Value::Null),
        )?)
    } else {
        InboundTransport::Xhttp(Box::new(parse_xhttp(
            stream
                .get("xhttpSettings")
                .or_else(|| stream.get("splithttpSettings"))
                .unwrap_or(&Value::Null),
        )?))
    };

    let sniffing = parse_sniffing(item.get("sniffing").unwrap_or(&Value::Null), &tag);

    let mut fallbacks = Vec::new();
    for (i, fb) in array(settings, "fallbacks").iter().enumerate() {
        match parse_fallback(fb) {
            Ok(f) => fallbacks.push(f),
            Err(e) => log::warn(format!("inbound {tag:?}: fallback {i} skipped: {e}")),
        }
    }

    let dokodemo = if protocol == InboundProtocol::Dokodemo {
        let addr_str = str_field(settings, "address");
        let address = if !addr_str.is_empty() {
            Some(match addr_str.parse::<std::net::IpAddr>() {
                Ok(ip) => crate::vless::Host::Ip(ip),
                Err(_) => crate::vless::Host::Domain(addr_str.to_owned()),
            })
        } else {
            None
        };
        let port = parse_port(settings.get("port"));
        let follow_redirect = settings
            .get("followRedirect")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Some(DokodemoSettings {
            address,
            port,
            follow_redirect,
        })
    } else {
        None
    };

    let sockopt = stream
        .get("sockopt")
        .or_else(|| item.get("sockopt"))
        .unwrap_or(&Value::Null);
    let accept_proxy_protocol = parse_accept_proxy_protocol(sockopt.get("acceptProxyProtocol"));

    Ok(Some(Inbound {
        tag,
        listen,
        port,
        protocol,
        users,
        shadowsocks_users,
        fallbacks,
        socks_auth,
        udp,
        sniffing,
        dokodemo,
        http_obfs,
        tls,
        transport,
        accept_proxy_protocol,
    }))
}

fn parse_http_obfs(header: &Value) -> crate::http_obfs::HttpObfsSettings {
    let response = header.get("response").unwrap_or(&Value::Null);
    if response.is_null() {
        return crate::http_obfs::HttpObfsSettings::default();
    }
    let version = match str_field(response, "version") {
        "" => "1.1",
        v => v,
    };
    let status = match str_field(response, "status") {
        "" => "200",
        s => s,
    };
    let reason = match str_field(response, "reason") {
        "" => "OK",
        r => r,
    };
    let mut resp = format!("HTTP/{version} {status} {reason}\r\n");
    if let Some(headers) = response.get("headers").and_then(Value::as_object) {
        for (k, v) in headers {
            if let Some(arr) = v.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        resp.push_str(&format!("{k}: {s}\r\n"));
                    }
                }
            } else if let Some(s) = v.as_str() {
                resp.push_str(&format!("{k}: {s}\r\n"));
            }
        }
    } else {
        resp.push_str("Content-Type: application/octet-stream\r\nConnection: keep-alive\r\nPragma: no-cache\r\n");
    }
    resp.push_str("\r\n");
    crate::http_obfs::HttpObfsSettings {
        response: resp.into_bytes(),
    }
}

fn parse_accept_proxy_protocol(val: Option<&Value>) -> crate::proxy_proto::ProxyProtocolAccept {
    match val {
        Some(Value::Bool(true)) => crate::proxy_proto::ProxyProtocolAccept::Any,
        Some(Value::Number(n)) => match n.as_u64() {
            Some(1) => crate::proxy_proto::ProxyProtocolAccept::V1,
            Some(2) => crate::proxy_proto::ProxyProtocolAccept::V2,
            _ => crate::proxy_proto::ProxyProtocolAccept::None,
        },
        _ => crate::proxy_proto::ProxyProtocolAccept::None,
    }
}

fn parse_tls(tls: &Value) -> Result<TlsSettings, String> {
    let cert = array(tls, "certificates")
        .first()
        .ok_or("tlsSettings.certificates is empty")?;
    let cert_pem = inline_or_file(cert, "certificate", "certificateFile")?;
    let key_pem = inline_or_file(cert, "key", "keyFile")?;
    let alpn = array(tls, "alpn")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let reject_unknown_sni = tls
        .get("rejectUnknownSni")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut server_names = Vec::new();
    if let Some(sn) = tls.get("serverName").and_then(Value::as_str) {
        if !sn.is_empty() {
            server_names.push(sn.to_ascii_lowercase());
        }
    }
    for name in array(tls, "serverNames").iter().filter_map(Value::as_str) {
        if !name.is_empty() {
            server_names.push(name.to_ascii_lowercase());
        }
    }
    Ok(TlsSettings {
        cert_pem,
        key_pem,
        alpn,
        reject_unknown_sni,
        server_names,
    })
}

fn inline_or_file(cert: &Value, inline_key: &str, file_key: &str) -> Result<Vec<u8>, String> {
    let lines: Vec<&str> = array(cert, inline_key)
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if !lines.is_empty() {
        return Ok(lines.join("\n").into_bytes());
    }
    let path = str_field(cert, file_key);
    if path.is_empty() {
        return Err(format!("certificate needs {inline_key} or {file_key}"));
    }
    fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))
}

fn parse_sniffing(item: &Value, tag: &str) -> crate::vless::Sniffing {
    let mut sniffing = crate::vless::Sniffing::default();
    let flag = |key| item.get(key).and_then(Value::as_bool).unwrap_or(false);
    if !flag("enabled") {
        return sniffing;
    }
    sniffing.metadata_only = flag("metadataOnly");
    sniffing.route_only = flag("routeOnly");
    let mut ignored = Vec::new();
    for name in array(item, "destOverride").iter().filter_map(Value::as_str) {
        match name {
            "http" => sniffing.http = true,
            "tls" => sniffing.tls = true,
            "quic" => sniffing.quic = true,
            "fakedns" | "fakedns+others" => {} // reserved for future fakedns
            other => ignored.push(other),
        }
    }
    let mut excluded = Vec::new();
    for ex in array(item, "domainsExcluded").iter().filter_map(Value::as_str) {
        excluded.push(ex.to_owned());
    }
    sniffing.domains_excluded = std::sync::Arc::new(excluded);
    if !ignored.is_empty() {
        log::warn(format!(
            "inbound {tag:?}: sniffing {} ignored",
            ignored.join(", ")
        ));
    }
    sniffing
}

fn parse_fallback(item: &Value) -> Result<Fallback, String> {
    // name and alpn select a fallback by the TLS handshake, which is not tracked here.
    for key in ["name", "alpn"] {
        if !str_field(item, key).is_empty() {
            return Err(format!("{key} is not supported"));
        }
    }
    let localhost = |port| FallbackDest::Tcp(crate::vless::Host::Domain("localhost".into()), port);
    let dest = match item.get("dest") {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .map(localhost)
            .ok_or("invalid dest port")?,
        Some(Value::String(s)) if s.starts_with('/') || s.starts_with('@') => {
            if cfg!(unix) {
                FallbackDest::Unix(s.clone())
            } else {
                return Err("unix sockets are not supported on this platform".into());
            }
        }
        Some(Value::String(s)) => match s.parse::<u16>() {
            Ok(port) => localhost(port),
            Err(_) => {
                let (host, port) = s.rsplit_once(':').ok_or("dest needs host:port")?;
                let port = port.parse::<u16>().map_err(|_| "invalid dest port")?;
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let host = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => crate::vless::Host::Ip(ip),
                    Err(_) => crate::vless::Host::Domain(host.to_owned()),
                };
                FallbackDest::Tcp(host, port)
            }
        },
        _ => return Err("missing dest".into()),
    };
    let xver = match item.get("xver").and_then(Value::as_u64).unwrap_or(0) {
        x @ 0..=2 => x as u8,
        x => return Err(format!("xver {x} is not 0, 1 or 2")),
    };
    Ok(Fallback {
        path: str_field(item, "path").to_owned(),
        dest,
        xver,
    })
}

fn parse_xhttp(x: &Value) -> Result<XhttpSettings, String> {
    // Like Xray, `extra` replaces everything except host, path and mode.
    let merged;
    let x = match x.get("extra").filter(|e| e.is_object()) {
        Some(extra) => {
            let mut extra = extra.clone();
            for key in ["host", "path", "mode"] {
                extra[key] = x.get(key).cloned().unwrap_or(Value::Null);
            }
            merged = extra;
            &merged
        }
        None => x,
    };
    let mut path = str_field(x, "path")
        .split('?')
        .next()
        .unwrap_or_default()
        .to_owned();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    let mode = match str_field(x, "mode") {
        "" => "auto",
        m @ ("auto" | "packet-up" | "stream-up" | "stream-one") => m,
        other => return Err(format!("unknown xhttp mode {other:?}")),
    };
    let padding = match parse_range(x.get("xPaddingBytes")) {
        Some((from, to)) if from == 0 && to == 0 => (100, 1000),
        Some((from, to)) if from == 0 || to == 0 => {
            return Err("xPaddingBytes cannot be disabled".into())
        }
        Some(range) => range,
        None => (100, 1000),
    };
    let text = |key: &str, default: &str| match str_field(x, key) {
        "" => default.to_owned(),
        value => value.to_owned(),
    };
    let placement = |key: &str, default: &str, allowed: &[&str]| {
        let value = text(key, default);
        allowed
            .contains(&value.as_str())
            .then(|| placement_of(&value))
            .ok_or_else(|| format!("xhttpSettings.{key}: unsupported placement {value:?}"))
    };
    let padding_obfs = if x
        .get("xPaddingObfsMode")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let tokenish = match text("xPaddingMethod", "repeat-x").as_str() {
            "repeat-x" => false,
            "tokenish" => true,
            other => {
                return Err(format!(
                    "xhttpSettings.xPaddingMethod: unsupported method {other:?}"
                ))
            }
        };
        Some(PaddingObfs {
            key: text("xPaddingKey", "x_padding"),
            header: header_name(text("xPaddingHeader", "X-Padding"))?,
            placement: placement(
                "xPaddingPlacement",
                "queryInHeader",
                &["cookie", "header", "query", "queryInHeader"],
            )?,
            tokenish,
        })
    } else {
        None
    };
    let meta = |placement_key: &str, key_key: &str, names: (&str, &str)| -> Result<Meta, String> {
        let placement = placement(
            placement_key,
            "path",
            &["path", "cookie", "header", "query"],
        )?;
        let key = match (placement, str_field(x, key_key)) {
            (Placement::Path, _) => String::new(),
            (Placement::Header, "") => names.0.to_owned(),
            (_, "") => names.1.to_owned(),
            (_, key) => key.to_owned(),
        };
        let key = if placement == Placement::Header {
            header_name(key)?
        } else {
            key
        };
        Ok(Meta { placement, key })
    };
    let session = meta(
        "sessionIDPlacement",
        "sessionIDKey",
        ("X-Session", "x_session"),
    )?;
    let seq = meta("seqPlacement", "seqKey", ("X-Seq", "x_seq"))?;
    // Xray adds the trailing slash only when a path segment carries metadata.
    if (session.placement == Placement::Path || seq.placement == Placement::Path)
        && !path.ends_with('/')
    {
        path.push('/');
    }
    let data_placement = placement(
        "uplinkDataPlacement",
        "auto",
        &["auto", "body", "cookie", "header"],
    )?;
    if matches!(data_placement, Placement::Cookie | Placement::Header) && mode != "packet-up" {
        return Err(
            "xhttpSettings.uplinkDataPlacement can be cookie or header only in packet-up mode"
                .into(),
        );
    }
    let data_key = match (data_placement, str_field(x, "uplinkDataKey")) {
        (Placement::Cookie, "") => "x_data".to_owned(),
        (_, "") => "X-Data".to_owned(),
        (_, key) => key.to_owned(),
    };
    let data_key = if data_placement == Placement::Cookie {
        data_key
    } else {
        header_name(data_key)?
    };
    let stream_up_secs = parse_range(x.get("scStreamUpServerSecs"))
        .filter(|r| r.1 > 0)
        .map_or((20, 80), |(a, b)| (a as u64, b as u64));
    if x.get("h2Params").is_some_and(|v| !v.is_null()) {
        log::warn("xhttpSettings.h2Params is ignored");
    }
    let max_each_post = parse_range(x.get("scMaxEachPostBytes"))
        .filter(|r| r.1 > 0)
        .map_or(1_000_000, |r| r.1);
    let max_buffered_posts = x
        .get("scMaxBufferedPosts")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(30) as usize;
    let mut response_headers = Vec::new();
    if let Some(headers) = x.get("responseHeaders").and_then(Value::as_object) {
        for (name, val) in headers {
            let Ok(header_name) = HeaderName::try_from(name.as_str()) else {
                return Err(format!("invalid header name in responseHeaders: {name:?}"));
            };
            let Some(val_str) = val.as_str() else {
                return Err(format!("header value for {name:?} must be a string"));
            };
            let Ok(header_value) = HeaderValue::try_from(val_str) else {
                return Err(format!(
                    "invalid header value in responseHeaders for {name:?}"
                ));
            };
            response_headers.push((header_name, header_value));
        }
    }
    Ok(XhttpSettings {
        path,
        host: str_field(x, "host").to_owned(),
        mode: mode.to_owned(),
        padding,
        padding_obfs,
        session,
        seq,
        uplink_data: Meta {
            placement: data_placement,
            key: data_key,
        },
        stream_up_secs,
        no_sse_header: x
            .get("noSSEHeader")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        max_each_post,
        max_buffered_posts,
        response_headers,
    })
}

fn parse_ws(settings: &Value) -> Result<crate::ws::WsSettings, String> {
    let mut path = str_field(settings, "path").to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    } else if !path.starts_with('/') {
        path = format!("/{path}");
    }
    let host = str_field(settings, "host");
    let host = if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    };
    Ok(crate::ws::WsSettings { path, host })
}

fn parse_httpupgrade(settings: &Value) -> Result<crate::httpupgrade::HttpUpgradeSettings, String> {
    let mut path = str_field(settings, "path").to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    } else if !path.starts_with('/') {
        path = format!("/{path}");
    }
    let host = str_field(settings, "host");
    let host = if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    };
    Ok(crate::httpupgrade::HttpUpgradeSettings { path, host })
}

fn parse_grpc(value: &Value) -> Result<crate::grpc::GrpcSettings, String> {
    if value.is_null() {
        return Ok(crate::grpc::GrpcSettings {
            service_name: String::new(),
            multi_mode: false,
            authority: None,
        });
    }
    let obj = value
        .as_object()
        .ok_or_else(|| "grpcSettings must be an object".to_string())?;
    let service_name = obj
        .get("serviceName")
        .or_else(|| obj.get("service_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let multi_mode = obj
        .get("multiMode")
        .or_else(|| obj.get("multi_mode"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let authority = obj
        .get("authority")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Ok(crate::grpc::GrpcSettings {
        service_name,
        multi_mode,
        authority,
    })
}

fn placement_of(value: &str) -> Placement {
    match value {
        "query" => Placement::Query,
        "header" => Placement::Header,
        "cookie" => Placement::Cookie,
        "queryInHeader" => Placement::QueryInHeader,
        "body" => Placement::Body,
        "auto" => Placement::Auto,
        _ => Placement::Path,
    }
}

fn header_name(name: String) -> Result<String, String> {
    http::HeaderName::from_bytes(name.as_bytes())
        .map(|_| name.clone())
        .map_err(|_| format!("xhttpSettings: invalid header name {name:?}"))
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
    std::env::var_os("XRAY_LOCATION_ASSET")
        .map(PathBuf::from)
        .into_iter()
        .collect()
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
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
        let InboundTransport::Xhttp(xhttp) = &inbound.transport else {
            panic!("expected Xhttp transport");
        };
        assert_eq!(xhttp.path, "/xh/");
        assert_eq!(xhttp.padding, (100, 1000));
        assert_eq!(inbound.users[0].email, "user1");
        assert_eq!(inbound.tls.as_ref().unwrap().cert_pem, b"CERT");
    }

    #[test]
    fn parses_vless_tcp_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vless-tcp", "port": 443, "protocol": "vless",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice"}]},
             "streamSettings": {"network": "tcp", "security": "none"}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.protocol, InboundProtocol::Vless);
        assert_eq!(inbound.transport, InboundTransport::Tcp);
        assert_eq!(inbound.port, 443);
        assert_eq!(inbound.users[0].email, "alice");
    }

    #[test]
    fn parses_trojan_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "trojan-in", "port": 443, "protocol": "trojan",
             "settings": {"clients": [{"password": "secret", "email": "bob@example.com"}]},
             "streamSettings": {"network": "tcp", "security": "none"}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.protocol, InboundProtocol::Trojan);
        assert_eq!(inbound.transport, InboundTransport::Tcp);
        assert_eq!(inbound.users[0].email, "bob@example.com");
        assert_eq!(
            inbound.users[0].hash,
            crate::trojan::trojan_password_hash("secret")
        );
    }

    #[test]
    fn parses_custom_response_headers() {
        let raw = serde_json::json!({
            "path": "/xh",
            "responseHeaders": {
                "Server": "nginx/1.24.0",
                "X-Frame-Options": "SAMEORIGIN"
            }
        });
        let settings = parse_xhttp(&raw).unwrap();
        assert_eq!(settings.response_headers.len(), 2);
        assert!(settings.response_headers.contains(&(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx/1.24.0")
        )));
    }

    #[test]
    fn parses_socks_and_http_inbounds() {
        let raw = r#"{
          "inbounds": [
            {"tag": "socks-in", "port": 1080, "protocol": "socks",
             "settings": {"auth": "password", "accounts": [{"user": "alice", "pass": "secret"}], "udp": true}},
            {"tag": "http-in", "port": 8080, "protocol": "http",
             "settings": {"accounts": [{"user": "bob", "pass": "secret2"}]}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Socks);
        assert_eq!(config.inbounds[0].port, 1080);
        assert!(config.inbounds[0].udp);
        assert_eq!(config.inbounds[1].protocol, InboundProtocol::Http);
        assert_eq!(config.inbounds[1].port, 8080);
    }

    #[test]
    fn parses_shadowsocks_inbound() {
        let raw = r#"{
          "inbounds": [
            {
              "tag": "ss-in",
              "port": 8388,
              "protocol": "shadowsocks",
              "settings": {
                "method": "aes-128-gcm",
                "password": "ss-secret-pass",
                "network": "tcp,udp"
              }
            },
            {
              "tag": "ss-multi",
              "port": 8389,
              "protocol": "shadowsocks",
              "settings": {
                "method": "chacha20-poly1305",
                "clients": [
                  {"password": "pass1", "email": "user1@ss"},
                  {"password": "pass2", "email": "user2@ss"}
                ],
                "udp": true
              }
            }
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Shadowsocks);
        assert_eq!(config.inbounds[0].port, 8388);
        assert!(config.inbounds[0].udp);
        assert_eq!(config.inbounds[0].shadowsocks_users.len(), 1);

        assert_eq!(config.inbounds[1].protocol, InboundProtocol::Shadowsocks);
        assert_eq!(config.inbounds[1].port, 8389);
        assert!(config.inbounds[1].udp);
        assert_eq!(config.inbounds[1].shadowsocks_users.len(), 2);
        assert_eq!(config.inbounds[1].shadowsocks_users[0].email, "user1@ss");
        assert_eq!(config.inbounds[1].shadowsocks_users[1].email, "user2@ss");
    }

    #[test]
    fn parses_fallbacks_inbound() {
        let raw = r#"{
          "inbounds": [
            {
              "tag": "vless-fallbacks",
              "port": 443,
              "protocol": "vless",
              "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
                "decryption": "none",
                "fallbacks": [
                  {"path": "/ray", "dest": "127.0.0.1:8001", "xver": 1},
                  {"dest": "80"}
                ]
              }
            }
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        let inb = &config.inbounds[0];
        assert_eq!(inb.fallbacks.len(), 2);
        assert_eq!(inb.fallbacks[0].path, "/ray");
        assert_eq!(inb.fallbacks[0].xver, 1);
        assert!(matches!(inb.fallbacks[0].dest, FallbackDest::Tcp(_, 8001)));
        assert_eq!(inb.fallbacks[1].path, "");
        assert_eq!(inb.fallbacks[1].xver, 0);
        assert!(matches!(inb.fallbacks[1].dest, FallbackDest::Tcp(_, 80)));
    }

    #[test]
    fn parses_websocket_inbounds() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vless-ws", "port": 80, "protocol": "vless",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice"}]},
             "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/chat", "host": "example.com"}}},
            {"tag": "trojan-ws", "port": 443, "protocol": "trojan",
             "settings": {"clients": [{"password": "secret", "email": "bob"}]},
             "streamSettings": {"network": "websocket", "security": "none", "wsSettings": {"path": "trojan-ws"}}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Vless);
        if let InboundTransport::Websocket(ws) = &config.inbounds[0].transport {
            assert_eq!(ws.path, "/chat");
            assert_eq!(ws.host.as_deref(), Some("example.com"));
        } else {
            panic!("expected websocket transport");
        }
        assert_eq!(config.inbounds[1].protocol, InboundProtocol::Trojan);
        if let InboundTransport::Websocket(ws) = &config.inbounds[1].transport {
            assert_eq!(ws.path, "/trojan-ws");
            assert_eq!(ws.host, None);
        } else {
            panic!("expected websocket transport");
        }
    }

    #[test]
    fn parses_httpupgrade_and_sniffing_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vless-hu", "port": 80, "protocol": "vless",
             "sniffing": {"enabled": true, "destOverride": ["tls", "quic"], "routeOnly": true},
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice"}]},
             "streamSettings": {"network": "httpupgrade", "security": "none", "httpupgradeSettings": {"path": "/hu", "host": "upgrade.example.com"}}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.protocol, InboundProtocol::Vless);
        let sniffing = crate::vless::Sniffing {
            http: false,
            tls: true,
            quic: true,
            route_only: true,
            metadata_only: false,
            domains_excluded: std::sync::Arc::new(Vec::new()),
        };
        assert_eq!(inbound.sniffing, sniffing);
        if let InboundTransport::HttpUpgrade(hu) = &inbound.transport {
            assert_eq!(hu.path, "/hu");
            assert_eq!(hu.host.as_deref(), Some("upgrade.example.com"));
        } else {
            panic!("expected httpupgrade transport");
        }
    }

    #[test]
    fn parses_grpc_inbounds() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vless-grpc", "port": 443, "protocol": "vless",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice"}]},
             "streamSettings": {"network": "grpc", "security": "none", "grpcSettings": {"serviceName": "MyGun", "multiMode": true, "authority": "example.com"}}},
            {"tag": "trojan-grpc", "port": 8443, "protocol": "trojan",
             "settings": {"clients": [{"password": "secret", "email": "bob"}]},
             "streamSettings": {"network": "gun", "security": "none"}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Vless);
        if let InboundTransport::Grpc(grpc) = &config.inbounds[0].transport {
            assert_eq!(grpc.service_name, "MyGun");
            assert!(grpc.multi_mode);
            assert_eq!(grpc.authority.as_deref(), Some("example.com"));
        } else {
            panic!("expected grpc transport");
        }
        assert_eq!(config.inbounds[1].protocol, InboundProtocol::Trojan);
        if let InboundTransport::Grpc(grpc) = &config.inbounds[1].transport {
            assert_eq!(grpc.service_name, "");
            assert!(!grpc.multi_mode);
            assert_eq!(grpc.authority, None);
        } else {
            panic!("expected grpc transport");
        }
    }

    #[test]
    fn parses_range_forms() {
        assert_eq!(parse_range(Some(&serde_json::json!(5))), Some((5, 5)));
        assert_eq!(
            parse_range(Some(&serde_json::json!("10-20"))),
            Some((10, 20))
        );
        assert_eq!(
            parse_range(Some(&serde_json::json!({"from": 1, "to": 2}))),
            Some((1, 2))
        );
    }

    #[test]
    fn parses_shadowsocks_2022_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "ss", "port": 8388, "protocol": "shadowsocks",
             "settings": {"method": "2022-blake3-aes-256-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                          "clients": [{"password": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "email": "a"}]}}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].shadowsocks_users.len(), 1);
        assert_eq!(inbounds[0].shadowsocks_users[0].email, "a");
    }

    #[test]
    fn parses_dokodemo_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "doko-tcp-udp", "port": 15353, "protocol": "dokodemo-door",
             "settings": {"address": "1.1.1.1", "port": 53, "network": "tcp,udp"}}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].protocol, InboundProtocol::Dokodemo);
        assert!(inbounds[0].udp);
        let doko = inbounds[0].dokodemo.as_ref().unwrap();
        assert_eq!(
            doko.address,
            Some(crate::vless::Host::Ip("1.1.1.1".parse().unwrap()))
        );
        assert_eq!(doko.port, Some(53));
    }

    #[test]
    fn parses_vmess_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vmess-in", "port": 10086, "protocol": "vmess",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice@xray.com", "alterId": 0}]}}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].protocol, InboundProtocol::Vmess);
        assert_eq!(inbounds[0].users.len(), 1);
        assert_eq!(inbounds[0].users[0].email, "alice@xray.com");
    }

    #[test]
    fn parses_tcp_http_obfs_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vless-obfs", "port": 8080, "protocol": "vless",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]},
             "streamSettings": {
               "network": "tcp",
               "tcpSettings": {
                 "header": {
                   "type": "http",
                   "response": {"version": "1.1", "status": "200", "reason": "OK"}
                 }
               }
             }}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        assert!(inbounds[0].http_obfs.is_some());
        let obfs = inbounds[0].http_obfs.as_ref().unwrap();
        assert!(std::str::from_utf8(&obfs.response)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn parses_accept_proxy_protocol() {
        let raw = r#"{
          "inbounds": [
            {"tag": "in-v1", "port": 10001, "protocol": "vless",
             "streamSettings": {"sockopt": {"acceptProxyProtocol": 1}}},
            {"tag": "in-v2", "port": 10002, "protocol": "vless",
             "streamSettings": {"sockopt": {"acceptProxyProtocol": 2}}},
            {"tag": "in-bool", "port": 10003, "protocol": "vless",
             "streamSettings": {"sockopt": {"acceptProxyProtocol": true}}},
            {"tag": "in-none", "port": 10004, "protocol": "vless"}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        assert_eq!(inbounds.len(), 4);
        assert_eq!(
            inbounds[0].accept_proxy_protocol,
            crate::proxy_proto::ProxyProtocolAccept::V1
        );
        assert_eq!(
            inbounds[1].accept_proxy_protocol,
            crate::proxy_proto::ProxyProtocolAccept::V2
        );
        assert_eq!(
            inbounds[2].accept_proxy_protocol,
            crate::proxy_proto::ProxyProtocolAccept::Any
        );
        assert_eq!(
            inbounds[3].accept_proxy_protocol,
            crate::proxy_proto::ProxyProtocolAccept::None
        );
    }

    #[test]
    fn parses_tls_reject_unknown_sni() {
        let raw = r#"{
          "inbounds": [
            {"tag": "tls-sni", "port": 10443, "protocol": "vless",
             "streamSettings": {"security": "tls", "tlsSettings": {
               "certificates": [{"certificate": ["CERT"], "key": ["KEY"]}],
               "rejectUnknownSni": true,
               "serverName": "example.com",
               "serverNames": ["api.example.com", "*.internal.net"]
             }}}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        let tls = inbounds[0].tls.as_ref().unwrap();
        assert!(tls.reject_unknown_sni);
        assert_eq!(
            tls.server_names,
            vec!["example.com", "api.example.com", "*.internal.net"]
        );
    }
}
