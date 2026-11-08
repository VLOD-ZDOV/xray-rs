//! Subset of the Xray JSON config that this server understands. Unknown or
//! unsupported entries are skipped with a warning so a full 3x-ui config loads.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use http::{HeaderName, HeaderValue};
use serde_json::Value;
use uuid::Uuid;

use crate::log;
use crate::policy;
use crate::routing::Router;
use crate::stats;

pub struct Config {
    pub log: log::Settings,
    /// gRPC API address from the inbound tagged like `api.tag` (or `api.listen`).
    pub api: Option<SocketAddr>,
    pub stats: stats::Policy,
    pub inbounds: Vec<Inbound>,
    pub router: Router,
    pub dns: Option<xray_config::DnsConfig>,
    pub policy: policy::PolicyManager,
    pub fakedns: Option<crate::fakedns::FakeDnsMulti>,
    pub observatory: Option<Arc<crate::observatory::Observatory>>,
    pub metrics_listen: Option<SocketAddr>,
    pub api_tag: Option<String>,
    pub env: HashMap<String, String>,
}

pub static ENV_TABLE: std::sync::LazyLock<std::sync::RwLock<HashMap<String, String>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));

pub fn get_env(key: &str) -> Option<String> {
    if let Ok(table) = ENV_TABLE.read() {
        if let Some(val) = table.get(key) {
            return Some(val.clone());
        }
    }
    std::env::var(key).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundTransport {
    Tcp,
    Websocket(crate::ws::WsSettings),
    HttpUpgrade(crate::httpupgrade::HttpUpgradeSettings),
    Grpc(crate::grpc::GrpcSettings),
    Xhttp(Box<XhttpSettings>),
    Hysteria,
    Kcp(Arc<crate::kcp::KcpSettings>),
    Xdrive(Arc<crate::xdrive::XdriveConfig>),
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
    Hysteria,
    Wireguard,
    Masque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TproxyMode {
    Off,
    Tproxy,
    Redirect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SockoptSettings {
    pub mark: u32,
    /// As Xray builds it: 256 for `true`, -1 for `false`, else the number.
    pub tcp_fast_open: Option<i32>,
    pub tproxy: TproxyMode,
    pub tcp_keep_alive_interval: Option<i32>,
    pub tcp_keep_alive_idle: Option<i32>,
    pub tcp_congestion: Option<String>,
    pub tcp_user_timeout_ms: Option<u32>,
    pub tcp_max_seg: Option<u32>,
    pub v6only: bool,
    pub mptcp: bool,
    pub interface: Option<String>,
    pub trusted_x_forwarded_for: Vec<String>,
    pub penetrate: bool,
    pub address_port_strategy: AddressPortStrategy,
    pub happy_eyeballs: Option<HappyEyeballsSettings>,
    pub tcp_window_clamp: Option<u32>,
    pub custom_sockopt: Vec<CustomSockopt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomSockopt {
    pub system: Option<String>,
    pub network: Option<String>,
    pub level: i32,
    pub opt: i32,
    pub value: CustomSockoptValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomSockoptValue {
    Int(i32),
    Str(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressPortStrategy {
    #[default]
    None,
    SrvPortOnly,
    SrvAddressOnly,
    SrvPortAndAddress,
    TxtPortOnly,
    TxtAddressOnly,
    TxtPortAndAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HappyEyeballsSettings {
    pub prioritize_ipv6: bool,
    pub interleave: u32,
    pub try_delay_ms: u32,
    pub max_concurrent_try: u32,
}

impl Default for HappyEyeballsSettings {
    fn default() -> Self {
        Self {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay_ms: 0,
            max_concurrent_try: 4,
        }
    }
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
    pub level: u32,
}

#[derive(Clone, Debug)]
pub struct Fallback {
    pub name: String,
    pub alpn: String,
    pub path: String,
    pub dest: FallbackDest,
    pub xver: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FallbackDest {
    Tcp(crate::vless::Host, u16),
    /// A socket path; `@name` is abstract and `@@name` abstract padded like Xray.
    Unix(String),
}

impl std::fmt::Display for FallbackDest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FallbackDest::Tcp(crate::vless::Host::Ip(ip), port) => {
                if ip.is_ipv6() {
                    write!(f, "[{ip}]:{port}")
                } else {
                    write!(f, "{ip}:{port}")
                }
            }
            FallbackDest::Tcp(crate::vless::Host::Domain(d), port) => write!(f, "{d}:{port}"),
            FallbackDest::Unix(path) => write!(f, "{path}"),
        }
    }
}

#[derive(Debug)]
pub struct Inbound {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub protocol: InboundProtocol,
    pub users: Vec<User>,
    pub shadowsocks_users: Vec<ShadowsocksUser>,
    pub shadowsocks_top_method: Option<String>,
    pub shadowsocks_top_password: Option<String>,
    pub fallbacks: Vec<Fallback>,
    pub socks_auth: xray_proxy::inbound::SocksInboundAuth,
    pub udp: bool,
    pub sniffing: crate::vless::Sniffing,
    pub dokodemo: Option<DokodemoSettings>,
    pub http_obfs: Option<crate::http_obfs::HttpObfsSettings>,
    pub tls: Option<TlsSettings>,
    pub reality: Option<RealityInboundSettings>,
    pub transport: InboundTransport,
    pub accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept,
    pub tcp_masks: Option<Arc<Vec<crate::tcp_mask::TcpMask>>>,
    pub hysteria_users: Vec<crate::vless::HysteriaUser>,
    pub hysteria_salamander: Option<String>,
    pub hysteria_gecko: Option<xray_transport::hysteria::gecko::GeckoPacketSize>,
    pub hysteria_udp_idle_timeout: Option<u64>,
    pub hysteria_masq: Option<HysteriaMasqConfig>,
    pub has_udphop: bool,
    pub vless_encryption: Option<Arc<xray_vless_encryption::Server>>,
    pub sockopt: Option<SockoptSettings>,
    pub quic_params: Option<xray_config::QuicParamsSettings>,
    pub wireguard: Option<Arc<xray_wireguard::ServerConfig>>,
    pub masque: Option<Arc<crate::masque_inbound::MasqueServerConfig>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteriaMasqType {
    NotFound,
    File,
    Proxy,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaMasqConfig {
    pub masq_type: HysteriaMasqType,
    pub masq_file: Option<String>,
    pub masq_url: Option<String>,
    pub masq_string: Option<String>,
    pub masq_string_headers: HashMap<String, String>,
    pub masq_string_status_code: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: [u8; 16],
    pub hash: [u8; 56],
    pub email: String,
    pub level: u32,
    /// VLESS: `xtls-rprx-vision` or empty.
    pub flow: String,
    pub reverse: Option<String>,
    pub testseed: [u32; 4],
}

pub fn parse_testseed(val: Option<&Value>, fallback: [u32; 4]) -> [u32; 4] {
    if let Some(Value::Array(arr)) = val {
        if arr.len() >= 4 {
            let mut res = [0u32; 4];
            let mut valid = true;
            for (i, item) in arr.iter().take(4).enumerate() {
                if let Some(n) = item.as_u64() {
                    res[i] = n as u32;
                } else {
                    valid = false;
                    break;
                }
            }
            if valid {
                return res;
            }
        }
    }
    fallback
}

pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// Like Xray, a non-UUID id maps to UUIDv5 in the nil namespace.
pub fn user_id(id: &str) -> [u8; 16] {
    *Uuid::parse_str(id)
        .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id.as_bytes()))
        .as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUsage {
    Encipherment,
    Issue,
    Verify,
}

#[derive(Debug, Clone)]
pub struct CertConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub usage: CertUsage,
    pub ocsp_stapling: u64,
    pub one_time_loading: bool,
    pub build_chain: bool,
}

#[derive(Debug, Clone)]
pub struct TlsSettings {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub certificates: Vec<CertConfig>,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
    pub server_names: Vec<String>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_suites: Vec<String>,
    pub ech_server_keys: Option<String>,
    pub ech_config_list: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityInboundSettings {
    pub dest: FallbackDest,
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    pub max_time_diff: u64,
    pub xver: u8,
    pub show: bool,
    pub alpn: Vec<String>,
    pub mldsa65_seed: Option<[u8; 32]>,
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

/// Xray's top-level sections. Go matches JSON names without case, so
/// `fakeDns` and `fakedns` are the same section.
const SECTIONS: [&str; 17] = [
    "log",
    "api",
    "dns",
    "routing",
    "policy",
    "inbounds",
    "outbounds",
    "transport",
    "stats",
    "reverse",
    "fakedns",
    "metrics",
    "observatory",
    "burstObservatory",
    "version",
    "geodata",
    "env",
];

fn normalize_sections(root: &mut Value) {
    let Some(map) = root.as_object_mut() else {
        return;
    };
    let keys: Vec<String> = map.keys().cloned().collect();
    for key in keys {
        if let Some(canonical) = SECTIONS
            .iter()
            .find(|s| s.eq_ignore_ascii_case(&key) && **s != key)
        {
            if !map.contains_key(*canonical) {
                if let Some(value) = map.remove(&key) {
                    map.insert((*canonical).to_owned(), value);
                }
            }
        }
    }
}

fn validate_geodata(geo: &Value) -> Result<(), String> {
    let cron = geo.get("cron").and_then(Value::as_str);
    if let Some(cron) = cron {
        if !cron.is_empty() {
            let fields: Vec<&str> = cron.split_whitespace().collect();
            let is_predefined = matches!(
                cron,
                "@yearly"
                    | "@annually"
                    | "@monthly"
                    | "@weekly"
                    | "@daily"
                    | "@midnight"
                    | "@hourly"
            );
            if !is_predefined && fields.len() != 5 {
                return Err("failed to build geodata configuration: invalid geodata cron".into());
            }
        }
    }
    if let Some(assets) = geo.get("assets").and_then(Value::as_array) {
        for asset in assets {
            let url = str_field(asset, "url");
            if !url.starts_with("https://") || url.len() <= 8 {
                return Err(format!("failed to build geodata configuration: invalid geodata asset url: {url}: scheme must be https"));
            }
            let host_part = &url[8..];
            let host = host_part.split(['/', '?', '#']).next().unwrap_or("");
            if host.is_empty() {
                return Err(format!("failed to build geodata configuration: invalid geodata asset url: {url}: scheme must be https"));
            }
        }
        if cron.is_some_and(|c| !c.is_empty()) {
            if assets.len() > 100 {
                return Err(
                    "failed to build geodata configuration: geodata supports at most 100 assets"
                        .into(),
                );
            }
            for asset in assets {
                let file = str_field(asset, "file");
                if !file.is_empty() && !file.to_ascii_lowercase().ends_with(".dat") {
                    return Err("failed to build geodata configuration: geodata asset file extension must be .dat".into());
                }
            }
        }
    }
    Ok(())
}

/// `version.min` / `version.max` against the Xray version this core stands in for.
fn check_version(root: &Value) -> Result<(), String> {
    fn compare(a: &str, b: &str) -> Result<std::cmp::Ordering, String> {
        let parts = |v: &str| -> Result<Vec<i64>, String> {
            v.split('.')
                .map(|p| {
                    p.parse()
                        .map_err(|_| format!("invalid version component {p} in {v}"))
                })
                .collect()
        };
        let (mut a, mut b) = (parts(a)?, parts(b)?);
        let len = a.len().max(b.len());
        a.resize(len, 0);
        b.resize(len, 0);
        Ok(a.cmp(&b))
    }
    let section = root.get("version").unwrap_or(&Value::Null);
    let core = crate::COMPAT_VERSION;
    let min = str_field(section, "min");
    if !min.is_empty() && compare(min, core)?.is_gt() {
        return Err(format!(
            "this config must be run on version {min} or higher"
        ));
    }
    let max = str_field(section, "max");
    if !max.is_empty() && compare(max, core)?.is_lt() {
        return Err(format!(
            "this config should be run on version {max} or lower"
        ));
    }
    Ok(())
}

pub fn parse(raw: &str) -> Result<Config, String> {
    let mut root: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    normalize_sections(&mut root);
    let mut env_map = HashMap::new();
    if let Some(env_obj) = root.get("env").and_then(Value::as_object) {
        for (k, v) in env_obj {
            let val = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            std::env::set_var(k, &val);
            env_map.insert(k.clone(), val);
        }
    }
    if let Ok(mut table) = ENV_TABLE.write() {
        table.extend(env_map.clone());
    }
    if root.get("reverse").is_some_and(|v| !v.is_null()) {
        return Err("The feature \"legacy reverse\" has been removed and migrated to \"VLESS Reverse Proxy\". Please update your config(s) according to release note and documentation.".into());
    }
    if let Some(t) = root.get("transport") {
        if !t.is_null() && t.as_object().is_some_and(|o| !o.is_empty()) {
            return Err("The feature Global transport config has been removed and migrated to streamSettings in inbounds and outbounds. Please update your config(s) according to release note and documentation.".into());
        }
    }
    if let Some(geo) = root.get("geodata") {
        if !geo.is_null() && geo.as_object().is_some() {
            validate_geodata(geo)?;
        }
    }
    check_version(&root)?;
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
    let dns_log = section
        .get("dnsLog")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let log = log::Settings {
        level: str_field(section, "loglevel").to_owned(),
        access: str_field(section, "access").to_owned(),
        error: str_field(section, "error").to_owned(),
        mask_address: str_field(section, "maskAddress").to_owned(),
        dns_log,
    };
    // The upstream parser is client-side and rejects server-only sections, so
    // it only sees `dns`.
    let dns = match root.get("dns") {
        Some(section) => {
            let only_dns = serde_json::json!({ "dns": section }).to_string();
            let parsed = xray_config::parse_xray_json_with_geodata_dirs(&only_dns, &asset_dirs())
                .map_err(|e| {
                let messages: Vec<String> =
                    e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
                format!("dns: {}", messages.join("; "))
            })?;
            Some(parsed.config.dns)
        }
        None => None,
    };
    let policy = policy::PolicyManager::from_config(&root);
    let fakedns = parse_fakedns(&root, dns.as_ref(), &inbounds)?;
    let observatory = crate::observatory::Observatory::from_config(&root)?;
    if let Some(obs) = &observatory {
        router.set_observatory(obs.clone());
    }
    Ok(Config {
        log,
        api,
        stats: stats::Policy::from_config(&root),
        inbounds,
        router,
        dns,
        policy,
        fakedns,
        observatory,
        metrics_listen: crate::metrics::parse(&root)?.and_then(|m| m.listen),
        api_tag: api_tag.map(str::to_owned),
        env: env_map,
    })
}

fn parse_inbound(item: &Value, tag: String) -> Result<Option<Inbound>, String> {
    crate::finalmask::warn_inbound_finalmask(
        item.get("streamSettings").unwrap_or(&Value::Null),
        str_field(item, "protocol"),
        &tag,
    );
    let protocol = match str_field(item, "protocol") {
        "vless" => InboundProtocol::Vless,
        "trojan" => InboundProtocol::Trojan,
        "vmess" => InboundProtocol::Vmess,
        "socks" | "mixed" => InboundProtocol::Socks,
        "http" => InboundProtocol::Http,
        "shadowsocks" => InboundProtocol::Shadowsocks,
        "dokodemo-door" | "dokodemo" | "tunnel" => InboundProtocol::Dokodemo,
        "hysteria" | "hysteria2" => InboundProtocol::Hysteria,
        "wireguard" => {
            let wg_cfg = crate::wg_inbound::parse(&tag, item)?;
            let port = parse_port(item.get("port")).unwrap_or(wg_cfg.listen_addr.port());
            let listen = match str_field(item, "listen") {
                "" => String::new(),
                addr if addr.starts_with('/') || addr.starts_with('@') => {
                    return Err("unix socket listen is not supported".into());
                }
                addr => addr.to_owned(),
            };
            let sniffing = parse_sniffing(item.get("sniffing").unwrap_or(&Value::Null), &tag);
            let stream = item.get("streamSettings").unwrap_or(&Value::Null);
            let sockopt_settings = parse_sockopt(
                stream
                    .get("sockopt")
                    .or_else(|| item.get("sockopt"))
                    .unwrap_or(&Value::Null),
                &format!("inbound {tag:?}"),
            )?;
            return Ok(Some(Inbound {
                tag,
                listen,
                port,
                protocol: InboundProtocol::Wireguard,
                users: Vec::new(),
                shadowsocks_users: Vec::new(),
                shadowsocks_top_method: None,
                shadowsocks_top_password: None,
                fallbacks: Vec::new(),
                socks_auth: xray_proxy::inbound::SocksInboundAuth::NoAuth,
                udp: true,
                sniffing,
                dokodemo: None,
                http_obfs: None,
                tls: None,
                reality: None,
                transport: InboundTransport::Tcp,
                accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept::None,
                tcp_masks: None,
                hysteria_users: Vec::new(),
                hysteria_salamander: None,
                hysteria_gecko: None,
                hysteria_udp_idle_timeout: None,
                hysteria_masq: None,
                has_udphop: false,
                vless_encryption: None,
                sockopt: sockopt_settings,
                quic_params: None,
                wireguard: Some(Arc::new(wg_cfg)),
                masque: None,
            }));
        }
        "masque" => {
            let masque_cfg = crate::masque_inbound::parse(&tag, item)?;
            let port = parse_port(item.get("port")).unwrap_or(443);
            let listen = match str_field(item, "listen") {
                "" => String::new(),
                addr if addr.starts_with('/') || addr.starts_with('@') => {
                    return Err("unix socket listen is not supported".into());
                }
                addr => addr.to_owned(),
            };
            let stream = item.get("streamSettings").unwrap_or(&Value::Null);
            let network = str_field(stream, "network");
            if network != "masque" {
                return Err("the masque transport can only be used by the masque inbound".into());
            }
            let security = str_field(stream, "security");
            if security != "tls" {
                return Err("MASQUE requires \"security\": \"tls\"".into());
            }
            let tls_settings = parse_tls(stream.get("tlsSettings").unwrap_or(&Value::Null))?;
            let sniffing = parse_sniffing(item.get("sniffing").unwrap_or(&Value::Null), &tag);
            let sockopt_settings = parse_sockopt(
                stream
                    .get("sockopt")
                    .or_else(|| item.get("sockopt"))
                    .unwrap_or(&Value::Null),
                &format!("inbound {tag:?}"),
            )?;
            let quic_params = parse_quic_params_from_stream(stream, &tag)?;
            return Ok(Some(Inbound {
                tag,
                listen,
                port,
                protocol: InboundProtocol::Masque,
                users: Vec::new(),
                shadowsocks_users: Vec::new(),
                shadowsocks_top_method: None,
                shadowsocks_top_password: None,
                fallbacks: Vec::new(),
                socks_auth: xray_proxy::inbound::SocksInboundAuth::NoAuth,
                udp: true,
                sniffing,
                dokodemo: None,
                http_obfs: None,
                tls: Some(tls_settings),
                reality: None,
                transport: InboundTransport::Tcp,
                accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept::None,
                tcp_masks: None,
                hysteria_users: Vec::new(),
                hysteria_salamander: None,
                hysteria_gecko: None,
                hysteria_udp_idle_timeout: None,
                hysteria_masq: None,
                has_udphop: false,
                vless_encryption: None,
                sockopt: sockopt_settings,
                quic_params,
                wireguard: None,
                masque: Some(Arc::new(masque_cfg)),
            }));
        }
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

    if network == "masque" {
        return Err("the masque transport can only be used by the masque inbound".into());
    }
    if network == "xdrive" {
        if protocol != InboundProtocol::Vless {
            return Err("the xdrive transport can only be used by VLESS".into());
        }
        let settings = item.get("settings").unwrap_or(&Value::Null);
        let decryption = str_field(settings, "decryption");
        if decryption == "none" {
            return Err(
                "the xdrive transport needs VLESS \"decryption\", run \"xray vlessenc\" to get one"
                    .into(),
            );
        }
        if let Some(clients) = settings.get("clients").and_then(Value::as_array) {
            for client in clients {
                if !str_field(client, "flow").is_empty() {
                    return Err("the xdrive transport doesn't support VLESS \"flow\"".into());
                }
            }
        }
        if let Some(port_val) = item.get("port") {
            if let Some(s) = port_val.as_str() {
                if s.contains('-') || s.contains(',') {
                    return Err("the xdrive transport can only listen on one port".into());
                }
            }
        }
    }
    if protocol == InboundProtocol::Hysteria {
        if !matches!(network, "hysteria" | "hysteria2") {
            return Err("not hysteria transport".into());
        }
        let settings = item.get("settings").unwrap_or(&Value::Null);
        if let Some(v) = settings.get("version") {
            if v.as_i64() != Some(2) {
                return Err("version != 2".into());
            }
        }
        let h_settings = stream.get("hysteriaSettings").unwrap_or(&Value::Null);
        if let Some(v) = h_settings.get("version") {
            if v.as_i64() != Some(2) {
                return Err("version != 2".into());
            }
        }
        let timeout_val = h_settings
            .get("udpIdleTimeout")
            .or_else(|| settings.get("udpIdleTimeout"))
            .and_then(Value::as_u64);
        if let Some(t) = timeout_val {
            if t != 0 && !(2..=600).contains(&t) {
                return Err("UdpIdleTimeout must be between 2 and 600".into());
            }
        }
        let _ = parse_hysteria_masq(h_settings, settings)?;
    }

    let is_hysteria =
        protocol == InboundProtocol::Hysteria || matches!(network, "hysteria" | "hysteria2");
    let is_tcp = matches!(network, "" | "tcp" | "raw");
    let is_ws = matches!(network, "ws" | "websocket");
    let is_httpupgrade = network == "httpupgrade";
    let is_grpc = matches!(network, "grpc" | "gun");
    let is_xhttp = matches!(network, "xhttp" | "splithttp");
    let is_kcp = matches!(network, "kcp" | "mkcp");
    let is_xdrive = network == "xdrive";
    let supported_security = matches!(security, "" | "none" | "tls" | "reality");

    let kcp_settings = if is_kcp {
        Some(Arc::new(parse_kcp(stream)?))
    } else {
        None
    };

    let xdrive_settings = if is_xdrive {
        let xs = stream.get("xdriveSettings").unwrap_or(&Value::Null);
        Some(Arc::new(crate::xdrive::parse_xdrive_settings(xs)?))
    } else {
        None
    };

    if is_hysteria {
        if security != "tls" {
            log::warn(format!("skipping inbound {tag:?}: Hysteria requires TLS"));
            return Ok(None);
        }
    } else if (!is_tcp
        && !is_ws
        && !is_httpupgrade
        && !is_grpc
        && !is_xhttp
        && !is_kcp
        && !is_xdrive)
        || !supported_security
    {
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

    let port = if is_xdrive {
        parse_port(item.get("port")).unwrap_or(0)
    } else {
        parse_port(item.get("port")).ok_or("invalid or missing port")?
    };
    let listen = match str_field(item, "listen") {
        "" => String::new(),
        addr if !is_xdrive && (addr.starts_with('/') || addr.starts_with('@')) => {
            return Err("unix socket listen is not supported".into());
        }
        addr => addr.to_owned(),
    };

    let settings = item.get("settings").unwrap_or(&Value::Null);
    let mut vless_encryption = None;
    if protocol == InboundProtocol::Vless {
        let decryption = str_field(settings, "decryption");
        if decryption.is_empty() {
            if settings.get("decryption").is_some() {
                return Err(
                    "VLESS settings: please add/set \"decryption\":\"none\" to every settings"
                        .into(),
                );
            }
        } else if decryption != "none" {
            if settings.get("fallbacks").is_some() {
                return Err(
                    "VLESS settings: \"fallbacks\" can not be used together with \"decryption\""
                        .into(),
                );
            }
            use std::str::FromStr;
            let server_cfg = xray_vless_encryption::ServerConfig::from_str(decryption)
                .map_err(|_| format!("VLESS settings: unsupported \"decryption\": {decryption}"))?;
            vless_encryption = Some(Arc::new(xray_vless_encryption::Server::new(server_cfg)));
        }
    }
    let mut users = Vec::new();
    let default_flow = str_field(settings, "flow");
    if protocol == InboundProtocol::Vless && !matches!(default_flow, "" | VISION_FLOW) {
        return Err(format!(
            r#"VLESS "settings.flow" doesn't support "{default_flow}" in this version"#
        ));
    }
    let default_testseed = parse_testseed(
        settings.get("testseed"),
        xray_proxy::vless::DEFAULT_VISION_SEED,
    );
    for client in array(settings, "clients") {
        let testseed = parse_testseed(client.get("testseed"), default_testseed);
        let flow = match (protocol, str_field(client, "flow")) {
            (InboundProtocol::Vless, "") => default_flow,
            (InboundProtocol::Vless, VISION_FLOW) => VISION_FLOW,
            (InboundProtocol::Vless, other) => {
                return Err(format!(
                    r#"VLESS users: "flow" doesn't support "{other}" in this version"#
                ))
            }
            _ => "",
        };
        let reverse = if protocol == InboundProtocol::Vless {
            if let Some(rev) = client.get("reverse") {
                if !rev.is_null() {
                    let tag = str_field(rev, "tag");
                    if tag.is_empty() {
                        return Err(r#"VLESS users: "tag" can't be empty for "reverse""#.into());
                    }
                    if rev.get("sniffing").is_some_and(|s| !s.is_null()) {
                        return Err(
                            r#"VLESS users: inbound's "reverse" can't have "sniffing""#.into()
                        );
                    }
                    Some(tag.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let id_str = str_field(client, "id");
        let pass_str = str_field(client, "password");
        let key = if !pass_str.is_empty() {
            pass_str
        } else {
            id_str
        };
        let level = client.get("level").and_then(Value::as_u64).unwrap_or(0) as u32;
        users.push(User {
            id: user_id(key),
            hash: crate::trojan::trojan_password_hash(key),
            email: str_field(client, "email").to_owned(),
            level,
            flow: flow.to_owned(),
            reverse,
            testseed,
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
                let level = settings.get("level").and_then(Value::as_u64).unwrap_or(0) as u32;
                shadowsocks_users.push(ShadowsocksUser {
                    method: ShadowsocksMethod::Ss2022(Arc::new(m)),
                    email: str_field(settings, "email").to_owned(),
                    level,
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
                    let level = entry.get("level").and_then(Value::as_u64).unwrap_or(0) as u32;
                    shadowsocks_users.push(ShadowsocksUser {
                        method: ShadowsocksMethod::Ss2022(Arc::new(m)),
                        email: str_field(entry, "email").to_owned(),
                        level,
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
                let level = entry.get("level").and_then(Value::as_u64).unwrap_or(0) as u32;
                shadowsocks_users.push(ShadowsocksUser {
                    method: ShadowsocksMethod::Aead2017(Arc::new(m)),
                    email: str_field(entry, "email").to_owned(),
                    level,
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
    let reality = if security == "reality" {
        let Some(settings) = stream.get("realitySettings") else {
            log::warn(format!("skipping inbound {tag:?}: missing realitySettings"));
            return Ok(None);
        };
        match parse_reality(settings, &tag)? {
            Some(r) => Some(r),
            None => return Ok(None),
        }
    } else {
        None
    };
    let transport = if is_hysteria {
        InboundTransport::Hysteria
    } else if let Some(kcp) = kcp_settings {
        InboundTransport::Kcp(kcp)
    } else if let Some(xdrive) = xdrive_settings {
        InboundTransport::Xdrive(xdrive)
    } else if is_tcp {
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
    let tcp_masks = crate::tcp_mask::parse(stream).map_err(|e| format!("inbound {tag:?}: {e}"))?;
    let sockopt_settings = parse_sockopt(sockopt, &format!("inbound {tag:?}"))?;

    let (shadowsocks_top_method, shadowsocks_top_password) =
        if protocol == InboundProtocol::Shadowsocks {
            (
                Some(str_field(settings, "method").to_owned()).filter(|s| !s.is_empty()),
                Some(str_field(settings, "password").to_owned()).filter(|s| !s.is_empty()),
            )
        } else {
            (None, None)
        };

    let mut hysteria_users = Vec::new();
    let mut hysteria_salamander = None;
    let mut hysteria_gecko = None;
    let mut hysteria_udp_idle_timeout = None;
    let mut hysteria_masq = None;
    let mut has_udphop = false;

    if is_hysteria {
        let users_arr = array(settings, "users");
        let clients_arr = array(settings, "clients");
        let user_list = if !users_arr.is_empty() {
            users_arr
        } else {
            clients_arr
        };
        for u in user_list {
            let auth = str_field(u, "auth");
            if !auth.is_empty() {
                hysteria_users.push(crate::vless::HysteriaUser {
                    auth: auth.to_owned(),
                    email: str_field(u, "email").to_owned(),
                    level: u.get("level").and_then(Value::as_u64).unwrap_or(0) as u32,
                });
            }
        }
        let h_settings = stream.get("hysteriaSettings").unwrap_or(&Value::Null);
        let top_auth = str_field(settings, "auth");
        let stream_auth = str_field(h_settings, "auth");
        let single_auth = if !top_auth.is_empty() {
            top_auth
        } else {
            stream_auth
        };
        if !single_auth.is_empty() && hysteria_users.is_empty() {
            hysteria_users.push(crate::vless::HysteriaUser {
                auth: single_auth.to_owned(),
                email: String::new(),
                level: 0,
            });
        }
        let timeout_val = h_settings
            .get("udpIdleTimeout")
            .or_else(|| settings.get("udpIdleTimeout"))
            .and_then(Value::as_u64);
        if let Some(t) = timeout_val {
            if t != 0 && !(2..=600).contains(&t) {
                return Err("UdpIdleTimeout must be between 2 and 600".into());
            }
            hysteria_udp_idle_timeout = Some(t);
        }
        hysteria_masq = parse_hysteria_masq(h_settings, settings)?;

        if let Some(masks) = stream
            .get("finalmask")
            .and_then(|f| f.get("udp"))
            .and_then(Value::as_array)
        {
            for mask in masks {
                let mask_type = str_field(mask, "type");
                let m_settings = mask.get("settings").unwrap_or(&Value::Null);
                if mask_type.eq_ignore_ascii_case("udphop") {
                    has_udphop = true;
                } else if mask_type.eq_ignore_ascii_case("salamander") {
                    let pwd = str_field(m_settings, "password");
                    if !pwd.is_empty() {
                        hysteria_salamander = Some(pwd.to_owned());
                        if let Some(ps) = m_settings.get("packetSize") {
                            if let Some(n) = ps.as_u64() {
                                if n > 0 && n <= 2048 {
                                    hysteria_gecko =
                                        xray_transport::hysteria::gecko::GeckoPacketSize::new(
                                            n as u16, n as u16,
                                        );
                                }
                            } else if let Some(s) = ps.as_str() {
                                if let Some((left, right)) = s.split_once('-') {
                                    if let (Ok(l), Ok(r)) =
                                        (left.parse::<u16>(), right.parse::<u16>())
                                    {
                                        let min = l.min(r);
                                        let max = l.max(r);
                                        hysteria_gecko =
                                            xray_transport::hysteria::gecko::GeckoPacketSize::new(
                                                min, max,
                                            );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let obfs = stream.get("obfs").or_else(|| settings.get("obfs"));
        if let Some(obfs) = obfs {
            let obfs_type = str_field(obfs, "type");
            if obfs_type.eq_ignore_ascii_case("salamander") {
                let s_obj = obfs.get("salamander").unwrap_or(obfs);
                let pwd = str_field(s_obj, "password");
                if !pwd.is_empty() {
                    hysteria_salamander = Some(pwd.to_owned());
                }
            } else if obfs_type.eq_ignore_ascii_case("gecko") {
                let g_obj = obfs.get("gecko").unwrap_or(obfs);
                let pwd = str_field(g_obj, "password");
                if !pwd.is_empty() {
                    hysteria_salamander = Some(pwd.to_owned());
                    let min = g_obj
                        .get("minPacketSize")
                        .and_then(Value::as_u64)
                        .unwrap_or(512) as u16;
                    let max = g_obj
                        .get("maxPacketSize")
                        .and_then(Value::as_u64)
                        .unwrap_or(1200) as u16;
                    hysteria_gecko =
                        xray_transport::hysteria::gecko::GeckoPacketSize::new(min, max);
                }
            }
        }
    }

    let quic_params = parse_quic_params_from_stream(stream, &tag)?;

    Ok(Some(Inbound {
        tag,
        listen,
        port,
        protocol,
        users,
        shadowsocks_users,
        shadowsocks_top_method,
        shadowsocks_top_password,
        fallbacks,
        socks_auth,
        udp,
        sniffing,
        dokodemo,
        http_obfs,
        tls,
        reality,
        transport,
        accept_proxy_protocol,
        tcp_masks,
        hysteria_users,
        hysteria_salamander,
        hysteria_gecko,
        hysteria_udp_idle_timeout,
        hysteria_masq,
        has_udphop,
        vless_encryption,
        sockopt: sockopt_settings,
        quic_params,
        wireguard: None,
        masque: None,
    }))
}

fn parse_quic_params_from_stream(
    stream: &Value,
    tag: &str,
) -> Result<Option<xray_config::QuicParamsSettings>, String> {
    if stream.pointer("/finalmask/quicParams").is_some() || stream.get("quicParams").is_some() {
        crate::finalmask::validate_inbound_quic_params(stream, tag)?;
        let mut qp_val = stream
            .pointer("/finalmask/quicParams")
            .or_else(|| stream.get("quicParams"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(obj) = qp_val.as_object_mut() {
            obj.insert("disableChromeParrot".to_string(), serde_json::json!(true));
        }
        let synth_stream = serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": { "path": "/" },
            "security": "tls",
            "tlsSettings": { "serverName": "a", "alpn": ["h3"] },
            "finalmask": {
                "quicParams": qp_val
            }
        });
        let synth = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "freedom",
                "streamSettings": synth_stream
            }]
        });
        let parsed = xray_config::parse_xray_json(&synth.to_string()).map_err(|e| {
            let messages: Vec<String> = e.diagnostics.iter().map(|d| d.message.clone()).collect();
            format!("inbound {tag:?}: {}", messages.join("; "))
        })?;
        Ok(parsed
            .config
            .outbounds
            .into_iter()
            .next()
            .and_then(|o| o.stream.quic_params))
    } else {
        Ok(None)
    }
}

fn parse_hysteria_masq(
    h_settings: &Value,
    settings: &Value,
) -> Result<Option<HysteriaMasqConfig>, String> {
    let masq = h_settings
        .get("masquerade")
        .or_else(|| settings.get("masquerade"));
    let Some(masq) = masq.filter(|m| !m.is_null()) else {
        return Ok(None);
    };
    let masq_type_str = str_field(masq, "type");
    let masq_type = match masq_type_str.to_ascii_lowercase().as_str() {
        "" | "404" => HysteriaMasqType::NotFound,
        "file" => HysteriaMasqType::File,
        "proxy" => {
            let url_str = str_field(masq, "url");
            if !url_str.is_empty() {
                let lower = url_str.to_ascii_lowercase();
                let valid = lower.starts_with("http://")
                    || lower.starts_with("https://")
                    || lower.starts_with("unix:")
                    || lower.starts_with('/');
                if !valid {
                    return Err("unknown scheme".into());
                }
            }
            HysteriaMasqType::Proxy
        }
        "string" => HysteriaMasqType::String,
        _ => return Err("unknown masq type".into()),
    };

    let masq_file = masq.get("dir").and_then(Value::as_str).map(String::from);
    let masq_url = masq.get("url").and_then(Value::as_str).map(String::from);
    let masq_string = masq
        .get("content")
        .and_then(Value::as_str)
        .map(String::from);
    let masq_string_status_code =
        masq.get("statusCode").and_then(Value::as_u64).unwrap_or(0) as u16;
    let mut masq_string_headers = HashMap::new();
    if let Some(headers) = masq.get("headers").and_then(Value::as_object) {
        for (k, v) in headers {
            if let Some(val_str) = v.as_str() {
                masq_string_headers.insert(k.clone(), val_str.to_string());
            }
        }
    }

    Ok(Some(HysteriaMasqConfig {
        masq_type,
        masq_file,
        masq_url,
        masq_string,
        masq_string_headers,
        masq_string_status_code,
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

pub fn parse_sockopt(sockopt: &Value, _owner: &str) -> Result<Option<SockoptSettings>, String> {
    let Some(map) = sockopt.as_object() else {
        return Ok(None);
    };
    let parse_i32_val = |v: Option<&Value>| {
        v.and_then(|val| match val {
            Value::Number(n) => n.as_i64().map(|x| x as i32),
            Value::String(s) => {
                if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    i32::from_str_radix(hex, 16).ok()
                } else {
                    s.parse::<i32>().ok()
                }
            }
            _ => None,
        })
    };
    let mut custom_sockopt = Vec::new();
    if let Some(Value::Array(items)) = map.get("customSockopt") {
        for item in items {
            if let Some(obj) = item.as_object() {
                let system = obj
                    .get("system")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let network = obj
                    .get("network")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let level = parse_i32_val(obj.get("level")).unwrap_or(libc::IPPROTO_TCP);
                let Some(opt) = parse_i32_val(obj.get("opt")) else {
                    continue;
                };
                let typ = obj.get("type").and_then(Value::as_str).unwrap_or("int");
                let value = match typ {
                    "str" => {
                        let s = obj
                            .get("value")
                            .and_then(|v| match v {
                                Value::String(s) => Some(s.clone()),
                                Value::Number(n) => Some(n.to_string()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        CustomSockoptValue::Str(s)
                    }
                    _ => {
                        let v = parse_i32_val(obj.get("value")).unwrap_or(0);
                        CustomSockoptValue::Int(v)
                    }
                };
                custom_sockopt.push(CustomSockopt {
                    system,
                    network,
                    level,
                    opt,
                    value,
                });
            }
        }
    }
    let penetrate = map
        .get("penetrate")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let address_port_strategy = match map.get("addressPortStrategy").and_then(Value::as_str) {
        None | Some("") | Some("none") => AddressPortStrategy::None,
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "srvportonly" => AddressPortStrategy::SrvPortOnly,
            "srvaddressonly" => AddressPortStrategy::SrvAddressOnly,
            "srvportandaddress" => AddressPortStrategy::SrvPortAndAddress,
            "txtportonly" => AddressPortStrategy::TxtPortOnly,
            "txtaddressonly" => AddressPortStrategy::TxtAddressOnly,
            "txtportandaddress" => AddressPortStrategy::TxtPortAndAddress,
            _ => return Err(format!("unknown addressPortStrategy: {s}")),
        },
    };
    let happy_eyeballs = if let Some(he) = map.get("happyEyeballs").and_then(Value::as_object) {
        let prioritize_ipv6 = he
            .get("prioritizeIPv6")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let interleave = he.get("interleave").and_then(Value::as_u64).unwrap_or(1) as u32;
        let try_delay_ms = he.get("tryDelayMs").and_then(Value::as_u64).unwrap_or(0) as u32;
        let max_concurrent_try = he
            .get("maxConcurrentTry")
            .and_then(Value::as_u64)
            .unwrap_or(4) as u32;
        Some(HappyEyeballsSettings {
            prioritize_ipv6,
            interleave,
            try_delay_ms,
            max_concurrent_try,
        })
    } else {
        None
    };
    let trusted_x_forwarded_for = match map.get("trustedXForwardedFor") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    };
    let int = |key: &str| map.get(key).and_then(Value::as_i64);
    let tcp_fast_open = match map.get("tcpFastOpen") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(true)) => Some(256),
        Some(Value::Bool(false)) => Some(-1),
        Some(Value::Number(n)) => Some(n.as_f64().unwrap_or(0.0).min(i32::MAX as f64) as i32),
        Some(_) => return Err("tcpFastOpen: only boolean and integer value is acceptable".into()),
    };
    let tproxy = match str_field(sockopt, "tproxy").to_ascii_lowercase().as_str() {
        "tproxy" => TproxyMode::Tproxy,
        "redirect" => TproxyMode::Redirect,
        _ => TproxyMode::Off,
    };
    let positive = |key: &str| int(key).filter(|v| *v > 0).map(|v| v as u32);
    let settings = SockoptSettings {
        mark: int("mark").unwrap_or(0) as u32,
        tcp_fast_open,
        tproxy,
        tcp_keep_alive_interval: int("tcpKeepAliveInterval").map(|v| v as i32),
        tcp_keep_alive_idle: int("tcpKeepAliveIdle").map(|v| v as i32),
        tcp_congestion: Some(str_field(sockopt, "tcpCongestion"))
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        tcp_user_timeout_ms: positive("tcpUserTimeout"),
        tcp_max_seg: positive("tcpMaxSeg"),
        v6only: map.get("v6only").and_then(Value::as_bool).unwrap_or(false),
        mptcp: map
            .get("tcpMptcp")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        interface: Some(str_field(sockopt, "interface"))
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        trusted_x_forwarded_for,
        penetrate,
        address_port_strategy,
        happy_eyeballs,
        tcp_window_clamp: positive("tcpWindowClamp"),
        custom_sockopt,
    };
    let unset = SockoptSettings {
        mark: 0,
        tcp_fast_open: None,
        tproxy: TproxyMode::Off,
        tcp_keep_alive_interval: None,
        tcp_keep_alive_idle: None,
        tcp_congestion: None,
        tcp_user_timeout_ms: None,
        tcp_max_seg: None,
        v6only: false,
        mptcp: false,
        interface: None,
        trusted_x_forwarded_for: Vec::new(),
        penetrate: false,
        address_port_strategy: AddressPortStrategy::None,
        happy_eyeballs: None,
        tcp_window_clamp: None,
        custom_sockopt: Vec::new(),
    };
    Ok((settings != unset).then_some(settings))
}

fn parse_tls(tls: &Value) -> Result<TlsSettings, String> {
    if tls
        .get("allowInsecure")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("The feature \"allowInsecure\" has been removed and migrated to \"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn). Please update your config(s) according to release note and documentation.".into());
    }
    let cert_array = array(tls, "certificates");
    if cert_array.is_empty() {
        return Err("tlsSettings.certificates is empty".into());
    }
    let mut certificates = Vec::new();
    for cert in cert_array {
        let cert_pem = inline_or_file(cert, "certificate", "certificateFile")?;
        let key_pem = inline_or_file(cert, "key", "keyFile")?;
        let cert_file = str_field(cert, "certificateFile");
        let cert_file = (!cert_file.is_empty()).then(|| cert_file.to_string());
        let key_file = str_field(cert, "keyFile");
        let key_file = (!key_file.is_empty()).then(|| key_file.to_string());
        let usage = match str_field(cert, "usage").to_ascii_lowercase().as_str() {
            "verify" => CertUsage::Verify,
            "issue" => CertUsage::Issue,
            _ => CertUsage::Encipherment,
        };
        let ocsp_stapling = cert
            .get("ocspStapling")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let one_time_loading = cert
            .get("oneTimeLoading")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let build_chain = cert
            .get("buildChain")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        certificates.push(CertConfig {
            cert_pem,
            key_pem,
            cert_file,
            key_file,
            usage,
            ocsp_stapling,
            one_time_loading,
            build_chain,
        });
    }
    let first_cert = &certificates[0];
    let cert_pem = first_cert.cert_pem.clone();
    let key_pem = first_cert.key_pem.clone();
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
    let min_version = tls
        .get("minVersion")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let max_version = tls
        .get("maxVersion")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut cipher_suites = Vec::new();
    if let Some(cs) = tls.get("cipherSuites").and_then(Value::as_str) {
        for s in cs.split(':').map(str::trim).filter(|s| !s.is_empty()) {
            cipher_suites.push(s.to_owned());
        }
    } else if let Some(arr) = tls.get("cipherSuites").and_then(Value::as_array) {
        for item in arr.iter().filter_map(Value::as_str) {
            cipher_suites.push(item.to_owned());
        }
    }
    let ech_server_keys = if let Some(ech_keys) = tls.get("echServerKeys").and_then(Value::as_str) {
        if !ech_keys.is_empty() {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(ech_keys)
                .map_err(|_| format!("invalid ECH Config{ech_keys}"))?;
            Some(ech_keys.to_owned())
        } else {
            None
        }
    } else {
        None
    };
    let ech_config_list = tls
        .get("echConfigList")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(TlsSettings {
        cert_pem,
        key_pem,
        certificates,
        alpn,
        reject_unknown_sni,
        server_names,
        min_version,
        max_version,
        cipher_suites,
        ech_server_keys,
        ech_config_list,
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

fn parse_fakedns_pool(item: &Value) -> Result<crate::fakedns::FakeDnsPoolConfig, String> {
    let ip_pool = str_field(item, "ipPool");
    if ip_pool.is_empty() {
        return Err("invalid fakeDNS setting".to_owned());
    }
    let pool_size = item
        .get("poolSize")
        .and_then(Value::as_u64)
        .unwrap_or(65535) as usize;
    if pool_size == 0 {
        return Err("invalid fakeDNS setting".to_owned());
    }
    Ok(crate::fakedns::FakeDnsPoolConfig {
        ip_pool: ip_pool.to_owned(),
        pool_size,
    })
}

fn parse_fakedns(
    root: &Value,
    dns: Option<&xray_config::DnsConfig>,
    inbounds: &[Inbound],
) -> Result<Option<crate::fakedns::FakeDnsMulti>, String> {
    let mut pools = Vec::new();
    if let Some(fakedns_val) = root.get("fakedns") {
        match fakedns_val {
            Value::Object(_) => {
                pools.push(parse_fakedns_pool(fakedns_val)?);
            }
            Value::Array(arr) => {
                for item in arr {
                    pools.push(parse_fakedns_pool(item)?);
                }
            }
            _ => return Err("invalid fakedns config".to_owned()),
        }
    } else {
        let fake_dns_in_use = dns.is_some_and(|d| {
            d.servers.iter().any(|s| match s.endpoint() {
                xray_config::DnsServerEndpoint::Domain { domain, .. } => {
                    domain.eq_ignore_ascii_case("fakedns")
                }
                _ => false,
            })
        });
        if fake_dns_in_use {
            let strategy = dns
                .map(|d| d.query_strategy)
                .unwrap_or(xray_config::DnsQueryStrategy::UseIp);
            match strategy {
                xray_config::DnsQueryStrategy::UseIp => {
                    pools.push(crate::fakedns::FakeDnsPoolConfig {
                        ip_pool: "198.18.0.0/15".to_owned(),
                        pool_size: 32768,
                    });
                    pools.push(crate::fakedns::FakeDnsPoolConfig {
                        ip_pool: "fc00::/18".to_owned(),
                        pool_size: 32768,
                    });
                }
                xray_config::DnsQueryStrategy::UseIpv4 => {
                    pools.push(crate::fakedns::FakeDnsPoolConfig {
                        ip_pool: "198.18.0.0/15".to_owned(),
                        pool_size: 65535,
                    });
                }
                xray_config::DnsQueryStrategy::UseIpv6 => {
                    pools.push(crate::fakedns::FakeDnsPoolConfig {
                        ip_pool: "fc00::/18".to_owned(),
                        pool_size: 65535,
                    });
                }
            }
        }
    }

    if pools.is_empty() {
        return Ok(None);
    }

    let has_fakedns_sniffer = inbounds.iter().any(|inbound| {
        inbound.sniffing.enabled() && (inbound.sniffing.fakedns || inbound.sniffing.fakedns_other)
    });
    if !has_fakedns_sniffer {
        log::warn("Defined FakeDNS but haven't enabled FakeDNS destOverride at any inbound.");
    }

    let multi = crate::fakedns::FakeDnsMulti::from_configs(&pools)?;
    Ok(Some(multi))
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
            "fakedns" => sniffing.fakedns = true,
            "fakedns+others" => sniffing.fakedns_other = true,
            other => ignored.push(other),
        }
    }
    let mut excluded = Vec::new();
    for ex in array(item, "domainsExcluded")
        .iter()
        .filter_map(Value::as_str)
    {
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
    let path = str_field(item, "path");
    if !path.is_empty() && !path.starts_with('/') {
        return Err(r#""path" must be empty or start with "/""#.into());
    }
    let dest = parse_dest(item.get("dest"))?;
    let xver = match item.get("xver").and_then(Value::as_u64).unwrap_or(0) {
        x @ 0..=2 => x as u8,
        x => return Err(format!("xver {x} is not 0, 1 or 2")),
    };
    Ok(Fallback {
        name: str_field(item, "name").to_owned(),
        alpn: str_field(item, "alpn").to_owned(),
        path: path.to_owned(),
        dest,
        xver,
    })
}

pub(crate) fn parse_dest(dest: Option<&Value>) -> Result<FallbackDest, String> {
    let localhost = |port| FallbackDest::Tcp(crate::vless::Host::Domain("localhost".into()), port);
    match dest {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .map(localhost)
            .ok_or_else(|| "invalid dest port".to_string()),
        Some(Value::String(s)) if s.starts_with('/') || s.starts_with('@') => {
            if cfg!(unix) {
                Ok(FallbackDest::Unix(s.clone()))
            } else {
                Err("unix sockets are not supported on this platform".into())
            }
        }
        Some(Value::String(s)) => match s.parse::<u16>() {
            Ok(port) => Ok(localhost(port)),
            Err(_) => {
                let (host, port) = s.rsplit_once(':').ok_or("dest needs host:port")?;
                let port = port.parse::<u16>().map_err(|_| "invalid dest port")?;
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let host = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => crate::vless::Host::Ip(ip),
                    Err(_) => crate::vless::Host::Domain(host.to_owned()),
                };
                Ok(FallbackDest::Tcp(host, port))
            }
        },
        _ => Err("missing dest".into()),
    }
}

pub fn decode_base64_32(s: &str) -> Result<[u8; 32], String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let s = s.trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .map_err(|e| format!("invalid base64: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "key must be 32 bytes".to_string())
}

fn parse_short_id(s: &str) -> Result<[u8; 8], String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok([0u8; 8]);
    }
    if s.len() > 16 {
        return Err(format!(
            "shortId {s:?} cannot exceed 16 hex characters (8 bytes)"
        ));
    }
    if !s.len().is_multiple_of(2) {
        return Err(format!("shortId {s:?} has odd hex string length"));
    }
    let mut out = [0u8; 8];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hex_chunk = match std::str::from_utf8(chunk) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string()),
        };
        out[i] = u8::from_str_radix(hex_chunk, 16)
            .map_err(|e| format!("invalid hex in shortId {s:?}: {e}"))?;
    }
    Ok(out)
}

fn parse_version_opt(v: &Value) -> Option<Result<[u8; 3], String>> {
    match v {
        Value::String(s) if !s.is_empty() => {
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() != 3 {
                return Some(Err(format!("invalid version {s:?}, expected x.y.z")));
            }
            let a = match parts[0].parse::<u8>() {
                Ok(n) => n,
                Err(e) => return Some(Err(e.to_string())),
            };
            let b = match parts[1].parse::<u8>() {
                Ok(n) => n,
                Err(e) => return Some(Err(e.to_string())),
            };
            let c = match parts[2].parse::<u8>() {
                Ok(n) => n,
                Err(e) => return Some(Err(e.to_string())),
            };
            Some(Ok([a, b, c]))
        }
        Value::Array(arr) if arr.len() == 3 => {
            let a = match arr[0].as_u64().and_then(|n| u8::try_from(n).ok()) {
                Some(n) => n,
                None => return Some(Err("invalid version array".into())),
            };
            let b = match arr[1].as_u64().and_then(|n| u8::try_from(n).ok()) {
                Some(n) => n,
                None => return Some(Err("invalid version array".into())),
            };
            let c = match arr[2].as_u64().and_then(|n| u8::try_from(n).ok()) {
                Some(n) => n,
                None => return Some(Err("invalid version array".into())),
            };
            Some(Ok([a, b, c]))
        }
        _ => None,
    }
}

fn parse_reality(reality: &Value, _tag: &str) -> Result<Option<RealityInboundSettings>, String> {
    let dest = parse_dest(reality.get("dest"))?;

    let mut server_names = Vec::new();
    for name in array(reality, "serverNames") {
        if let Some(s) = name.as_str() {
            if !s.is_empty() {
                server_names.push(s.to_ascii_lowercase());
            }
        }
    }
    if server_names.is_empty() {
        if let Some(s) = reality.get("serverName").and_then(Value::as_str) {
            if !s.is_empty() {
                server_names.push(s.to_ascii_lowercase());
            }
        }
    }
    if server_names.is_empty() {
        return Err("realitySettings: serverNames is empty".into());
    }

    let priv_str = str_field(reality, "privateKey");
    if priv_str.is_empty() {
        return Err("realitySettings: missing privateKey".into());
    }
    let private_key = decode_base64_32(priv_str)?;

    let mldsa65_seed_str = reality
        .get("mldsa65Seed")
        .or_else(|| reality.get("mldsa65_seed"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let mldsa65_seed = if !mldsa65_seed_str.is_empty() {
        if mldsa65_seed_str == priv_str {
            return Err(format!(
                "\"mldsa65Seed\" and \"privateKey\" can not be the same value: {mldsa65_seed_str}"
            ));
        }
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            mldsa65_seed_str,
        )
        .map_err(|_| format!("invalid \"mldsa65Seed\": {mldsa65_seed_str}"))?;
        if decoded.len() != 32 {
            return Err(format!("invalid \"mldsa65Seed\": {mldsa65_seed_str}"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Some(arr)
    } else {
        None
    };

    let mut short_ids = Vec::new();
    let short_id_arr = array(reality, "shortIds");
    if !short_id_arr.is_empty() {
        for sid in short_id_arr {
            let s = sid.as_str().unwrap_or_default();
            short_ids.push(parse_short_id(s)?);
        }
    } else if let Some(s) = reality.get("shortId").and_then(Value::as_str) {
        short_ids.push(parse_short_id(s)?);
    }

    let min_client_ver = reality
        .get("minClientVer")
        .and_then(parse_version_opt)
        .transpose()?;
    let max_client_ver = reality
        .get("maxClientVer")
        .and_then(parse_version_opt)
        .transpose()?;

    let max_time_diff = reality
        .get("maxTimeDiff")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let xver = match reality.get("xver").and_then(Value::as_u64).unwrap_or(0) {
        x @ 0..=2 => x as u8,
        x => return Err(format!("realitySettings: xver {x} is not 0, 1 or 2")),
    };
    let show = reality
        .get("show")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut alpn = Vec::new();
    for a in array(reality, "alpn") {
        if let Some(s) = a.as_str() {
            alpn.push(s.to_string());
        }
    }

    Ok(Some(RealityInboundSettings {
        dest,
        server_names,
        private_key,
        short_ids,
        min_client_ver,
        max_client_ver,
        max_time_diff,
        xver,
        show,
        alpn,
        mldsa65_seed,
    }))
}

pub fn parse_kcp(stream: &Value) -> Result<crate::kcp::KcpSettings, String> {
    let k = stream.get("kcpSettings").unwrap_or(&Value::Null);
    let mut settings = crate::kcp::KcpSettings::default();

    if let Some(mtu) = k.get("mtu").and_then(Value::as_u64) {
        settings.mtu = mtu as u32;
    }
    if let Some(tti) = k.get("tti").and_then(Value::as_u64) {
        settings.tti = tti as u32;
    }
    if let Some(up) = k.get("uplinkCapacity").and_then(Value::as_u64) {
        settings.uplink_capacity = up as u32;
    }
    if let Some(down) = k.get("downlinkCapacity").and_then(Value::as_u64) {
        settings.downlink_capacity = down as u32;
    }
    if let Some(c) = k.get("congestion").and_then(Value::as_bool) {
        settings.congestion = c;
        if c && k.get("cwndMultiplier").is_none() {
            settings.cwnd_multiplier = 20;
        }
    }
    if let Some(cwnd) = k.get("cwndMultiplier").and_then(Value::as_u64) {
        settings.cwnd_multiplier = cwnd as u32;
    }
    if let Some(r) = k.get("readBufferSize").and_then(Value::as_u64) {
        settings.read_buffer_size = r as u32;
    }
    if let Some(w) = k.get("writeBufferSize").and_then(Value::as_u64) {
        settings.write_buffer_size = w as u32;
    }
    if let Some(m) = k.get("maxSendingWindow").and_then(Value::as_u64) {
        settings.max_sending_window = m as u32;
    }

    if let Some(h) = k.get("header") {
        let h_type = h.get("type").and_then(Value::as_str).unwrap_or("");
        if let Some(ht) = crate::kcp::KcpHeaderType::parse(h_type) {
            settings.header_type = ht;
        }
        if let Some(domain) = h.get("domain").and_then(Value::as_str) {
            settings.header_domain = domain.to_string();
        }
    }
    if let Some(seed) = k.get("seed").and_then(Value::as_str) {
        if !seed.is_empty() {
            settings.seed = Some(seed.to_string());
        }
    }

    // Also check finalmask.udp for mkcp-legacy if not set in kcpSettings
    if let Some(udp_masks) = stream
        .get("finalmask")
        .and_then(|f| f.get("udp"))
        .and_then(Value::as_array)
    {
        for mask in udp_masks {
            if mask.get("type").and_then(Value::as_str) == Some("mkcp-legacy") {
                let s = mask.get("settings").unwrap_or(&Value::Null);
                let h = s.get("header").and_then(Value::as_str).unwrap_or("");
                let val = s.get("value").and_then(Value::as_str).unwrap_or("");
                if !h.is_empty() {
                    if let Some(ht) = crate::kcp::KcpHeaderType::parse(h) {
                        settings.header_type = ht;
                    }
                    if settings.header_type == crate::kcp::KcpHeaderType::Dns && !val.is_empty() {
                        settings.header_domain = val.to_string();
                    }
                } else if !val.is_empty() {
                    settings.seed = Some(val.to_string());
                }
            }
        }
    }

    settings.validate()?;
    Ok(settings)
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
    get_env("XRAY_LOCATION_ASSET")
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

pub(crate) fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
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
        assert!(inbound.vless_encryption.is_none());
    }

    #[test]
    fn parses_vless_decryption_inbound() {
        let raw = r#"{
          "inbounds": [
            {"tag": "vless-enc", "port": 443, "protocol": "vless",
             "settings": {
               "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice"}],
               "decryption": "mlkem768x25519plus.native.600s.UKfUEMDdjlEnycTMBP0a08acky8vRRKSrM1MRnaYk3s"
             },
             "streamSettings": {"network": "tcp", "security": "none"}}
          ]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        let inbound = &config.inbounds[0];
        assert!(inbound.vless_encryption.is_some());
    }

    #[test]
    fn rejects_vless_decryption_errors_matching_xray() {
        // Empty decryption string
        let raw_empty = r#"{
          "inbounds": [
            {"tag": "vless-in", "port": 443, "protocol": "vless",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}], "decryption": ""}}
          ]
        }"#;
        let err = match parse(raw_empty) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err
            .contains("VLESS settings: please add/set \"decryption\":\"none\" to every settings"));

        // Unsupported decryption
        let raw_unsupported = r#"{
          "inbounds": [
            {"tag": "vless-in", "port": 443, "protocol": "vless",
             "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}], "decryption": "invalid.format"}}
          ]
        }"#;
        let err = match parse(raw_unsupported) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err.contains("VLESS settings: unsupported \"decryption\": invalid.format"));

        // Decryption with fallbacks
        let raw_fallbacks = r#"{
          "inbounds": [
            {"tag": "vless-in", "port": 443, "protocol": "vless",
             "settings": {
               "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
               "decryption": "mlkem768x25519plus.native.600s.UKfUEMDdjlEnycTMBP0a08acky8vRRKSrM1MRnaYk3s",
               "fallbacks": [{"dest": 80}]
             }}
          ]
        }"#;
        let err = match parse(raw_fallbacks) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err.contains(
            "VLESS settings: \"fallbacks\" can not be used together with \"decryption\""
        ));
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
            fakedns: false,
            fakedns_other: false,
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

    #[test]
    fn parses_tls_versions_and_ciphers() {
        let raw = r#"{
          "inbounds": [
            {"tag": "tls-vers", "port": 10444, "protocol": "vless",
             "streamSettings": {"security": "tls", "tlsSettings": {
               "certificates": [{"certificate": ["CERT"], "key": ["KEY"]}],
               "minVersion": "1.3",
               "maxVersion": "1.3",
               "cipherSuites": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
             }}}
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        let tls = inbounds[0].tls.as_ref().unwrap();
        assert_eq!(tls.min_version.as_deref(), Some("1.3"));
        assert_eq!(tls.max_version.as_deref(), Some("1.3"));
        assert_eq!(
            tls.cipher_suites,
            vec!["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
        );
    }

    #[test]
    fn parses_all_outbound_protocols_in_config() {
        let raw = r#"{
          "outbounds": [
            {
              "tag": "vmess-out",
              "protocol": "vmess",
              "settings": {
                "vnext": [{
                  "address": "127.0.0.1",
                  "port": 10086,
                  "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "auto"}]
                }]
              }
            },
            {
              "tag": "trojan-out",
              "protocol": "trojan",
              "settings": {
                "servers": [{"address": "127.0.0.1", "port": 10087, "password": "password"}]
              }
            },
            {
              "tag": "ss-2017-out",
              "protocol": "shadowsocks",
              "settings": {
                "servers": [{"address": "127.0.0.1", "port": 10088, "method": "aes-128-gcm", "password": "password"}]
              }
            },
            {
              "tag": "ss-2022-out",
              "protocol": "shadowsocks",
              "settings": {
                "servers": [{"address": "127.0.0.1", "port": 10089, "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}]
              }
            },
            {
              "tag": "http-out",
              "protocol": "http",
              "settings": {
                "servers": [{"address": "127.0.0.1", "port": 8080, "users": [{"user": "alice", "pass": "secret"}]}],
                "headers": {"User-Agent": "Test/1.0"}
              }
            },
            {
              "tag": "dns-out",
              "protocol": "dns",
              "settings": {
                "rewriteAddress": "1.1.1.1",
                "rewritePort": 53
              }
            },
            {
              "tag": "loop-out",
              "protocol": "loopback",
              "settings": {
                "inboundTag": "api"
              }
            },
            {
              "tag": "direct",
              "protocol": "freedom",
              "settings": {
                "redirect": "127.0.0.1:8080",
                "fragment": {
                  "packets": "tlshello",
                  "length": "100-200",
                  "interval": "10-20"
                }
              }
            }
          ],
          "routing": {
            "balancers": [
              {
                "tag": "b1",
                "selector": ["ss-"],
                "strategy": "roundRobin"
              }
            ],
            "rules": [
              {"type": "field", "port": 80, "balancerTag": "b1"},
              {"type": "field", "port": 53, "outboundTag": "dns-out"},
              {"type": "field", "inboundTag": ["loop"], "outboundTag": "http-out"}
            ]
          }
        }"#;
        let cfg = parse(raw).unwrap();
        assert_eq!(cfg.inbounds.len(), 0);
    }

    #[test]
    fn parses_reality_inbound_settings() {
        let raw = r#"{
          "inbounds": [
            {
              "tag": "reality-in",
              "port": 443,
              "protocol": "vless",
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                  "dest": "www.yahoo.com:443",
                  "serverNames": ["www.yahoo.com", "yahoo.com"],
                  "privateKey": "iAIPl1iED4ujD2JWzwdm9mdyZx2EjZgqCQWPuf9HN10",
                  "shortIds": ["", "0123456789abcdef", "1234"],
                  "minClientVer": "1.0.0",
                  "maxClientVer": "26.10.21",
                  "maxTimeDiff": 60000,
                  "xver": 1,
                  "show": true,
                  "alpn": ["h2", "http/1.1"]
                }
              }
            }
          ]
        }"#;
        let inbounds = parse(raw).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        let reality = inbounds[0].reality.as_ref().unwrap();
        assert_eq!(
            reality.dest,
            FallbackDest::Tcp(crate::vless::Host::Domain("www.yahoo.com".into()), 443)
        );
        assert_eq!(reality.server_names, vec!["www.yahoo.com", "yahoo.com"]);
        assert_eq!(reality.short_ids.len(), 3);
        assert_eq!(reality.short_ids[0], [0u8; 8]);
        assert_eq!(
            reality.short_ids[1],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(
            reality.short_ids[2],
            [0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(reality.min_client_ver, Some([1, 0, 0]));
        assert_eq!(reality.max_client_ver, Some([26, 10, 21]));
        assert_eq!(reality.max_time_diff, 60000);
        assert_eq!(reality.xver, 1);
        assert!(reality.show);
        assert_eq!(reality.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn parses_reality_inbound_with_mldsa65_seed() {
        let raw_with_seed = r#"{
          "inbounds": [
            {
              "tag": "reality-mldsa",
              "port": 443,
              "protocol": "vless",
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                  "dest": "www.yahoo.com:443",
                  "serverNames": ["www.yahoo.com"],
                  "privateKey": "iAIPl1iED4ujD2JWzwdm9mdyZx2EjZgqCQWPuf9HN10",
                  "mldsa65Seed": "ai9ixjkLpABQyp5J15DrKgz1ik7vFAYprc46d8y512g"
                }
              }
            }
          ]
        }"#;
        let inbounds = parse(raw_with_seed).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        assert!(inbounds[0].reality.as_ref().unwrap().mldsa65_seed.is_some());

        let raw_same_seed = r#"{
          "inbounds": [
            {
              "tag": "reality-same-seed",
              "port": 443,
              "protocol": "vless",
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                  "dest": "www.yahoo.com:443",
                  "serverNames": ["www.yahoo.com"],
                  "privateKey": "iAIPl1iED4ujD2JWzwdm9mdyZx2EjZgqCQWPuf9HN10",
                  "mldsa65Seed": "iAIPl1iED4ujD2JWzwdm9mdyZx2EjZgqCQWPuf9HN10"
                }
              }
            }
          ]
        }"#;
        let err = match parse(raw_same_seed) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err.contains("\"mldsa65Seed\" and \"privateKey\" can not be the same value"));

        let raw_invalid_seed = r#"{
          "inbounds": [
            {
              "tag": "reality-invalid-seed",
              "port": 443,
              "protocol": "vless",
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                  "dest": "www.yahoo.com:443",
                  "serverNames": ["www.yahoo.com"],
                  "privateKey": "iAIPl1iED4ujD2JWzwdm9mdyZx2EjZgqCQWPuf9HN10",
                  "mldsa65Seed": "not-valid-base64!"
                }
              }
            }
          ]
        }"#;
        let err = match parse(raw_invalid_seed) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err.contains("invalid \"mldsa65Seed\""));

        let raw_empty_seed = r#"{
          "inbounds": [
            {
              "tag": "reality-empty-seed",
              "port": 443,
              "protocol": "vless",
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                  "dest": "www.yahoo.com:443",
                  "serverNames": ["www.yahoo.com"],
                  "privateKey": "iAIPl1iED4ujD2JWzwdm9mdyZx2EjZgqCQWPuf9HN10",
                  "mldsa65Seed": ""
                }
              }
            }
          ]
        }"#;
        let inbounds = parse(raw_empty_seed).unwrap().inbounds;
        assert_eq!(inbounds.len(), 1);
        assert!(inbounds[0].reality.as_ref().unwrap().mldsa65_seed.is_none());
    }

    #[test]
    fn parses_short_id_validation() {
        assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
        assert_eq!(
            parse_short_id("abcd").unwrap(),
            [0xab, 0xcd, 0, 0, 0, 0, 0, 0]
        );
        assert!(parse_short_id("abc").is_err());
        assert!(parse_short_id("0123456789abcdef01").is_err());
        assert!(parse_short_id("zz").is_err());
    }

    #[test]
    fn parses_dns_config() {
        // Panel configs carry server-only sections next to `dns`.
        let raw = r#"{
          "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
          "stats": {},
          "policy": {"levels": {"0": {"statsUserOnline": true, "connIdle": 120}}},
          "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789,
                        "protocol": "tunnel", "settings": {"address": "127.0.0.1"}}],
          "dns": {
            "servers": ["8.8.8.8", "1.1.1.1"],
            "hosts": {
              "example.com": "127.0.0.1"
            },
            "queryStrategy": "UseIPv4"
          }
        }"#;
        let config = parse(raw).unwrap();
        let dns = config.dns.expect("dns config must be present");
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.query_strategy, xray_config::DnsQueryStrategy::UseIpv4);
        assert!(!dns.hosts.is_empty());
        assert_eq!(
            config.policy.for_level(0).conn_idle,
            std::time::Duration::from_secs(120)
        );
    }

    #[test]
    fn parses_sockopt_like_xray() {
        let parse = |v: serde_json::Value| parse_sockopt(&v, "test");
        assert_eq!(parse(serde_json::json!({})).unwrap(), None);
        assert_eq!(
            parse(serde_json::json!({"acceptProxyProtocol": true})).unwrap(),
            None
        );
        let on = parse(serde_json::json!({"tcpFastOpen": true, "tproxy": "Redirect", "mark": 7}))
            .unwrap()
            .unwrap();
        assert_eq!(on.tcp_fast_open, Some(256));
        assert_eq!(on.tproxy, TproxyMode::Redirect);
        assert_eq!(on.mark, 7);
        let off = parse(serde_json::json!({"tcpFastOpen": false}))
            .unwrap()
            .unwrap();
        assert_eq!(off.tcp_fast_open, Some(-1));
        let queue = parse(serde_json::json!({"tcpFastOpen": 64, "tcpUserTimeout": 10000}))
            .unwrap()
            .unwrap();
        assert_eq!(queue.tcp_fast_open, Some(64));
        assert_eq!(queue.tcp_user_timeout_ms, Some(10000));
        assert!(parse(serde_json::json!({"tcpFastOpen": "yes"})).is_err());

        let full = parse(serde_json::json!({
            "penetrate": true,
            "addressPortStrategy": "srvPortAndAddress",
            "happyEyeballs": {
                "prioritizeIPv6": true,
                "interleave": 2,
                "tryDelayMs": 300,
                "maxConcurrentTry": 6
            }
        }))
        .unwrap()
        .unwrap();
        assert!(full.penetrate);
        assert_eq!(
            full.address_port_strategy,
            AddressPortStrategy::SrvPortAndAddress
        );
        let he = full.happy_eyeballs.unwrap();
        assert!(he.prioritize_ipv6);
        assert_eq!(he.interleave, 2);
        assert_eq!(he.try_delay_ms, 300);
        assert_eq!(he.max_concurrent_try, 6);
        assert!(parse(serde_json::json!({"addressPortStrategy": "invalid"})).is_err());
    }

    #[test]
    fn reads_sections_and_aliases_like_xray() {
        let raw = r#"{
          "Log": {"loglevel": "warning"},
          "version": {"min": "26.10", "max": "26.10.31"},
          "inbounds": [
            {"tag": "m", "port": 1080, "listen": "127.0.0.1", "protocol": "mixed"},
            {"tag": "t", "port": 1081, "listen": "127.0.0.1", "protocol": "tunnel",
             "settings": {"address": "127.0.0.1", "port": 80}}
          ],
          "outbounds": [{"tag": "d", "protocol": "direct"}, {"tag": "b", "protocol": "block"}]
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(config.log.level, "warning");
        assert_eq!(config.inbounds[0].protocol, InboundProtocol::Socks);
        assert_eq!(config.inbounds[1].protocol, InboundProtocol::Dokodemo);
        let too_new = r#"{"version": {"min": "26.11"}, "inbounds": []}"#;
        assert_eq!(
            parse(too_new).err().unwrap(),
            "this config must be run on version 26.11 or higher"
        );
        let too_old = r#"{"version": {"max": "26.10.30"}, "inbounds": []}"#;
        assert_eq!(
            parse(too_old).err().unwrap(),
            "this config should be run on version 26.10.30 or lower"
        );
    }

    #[test]
    fn parses_env_section() {
        let raw = r#"{
          "env": {
            "XRAY_TEST_VAR_1": "hello",
            "XRAY_TEST_VAR_2": "world"
          },
          "inbounds": []
        }"#;
        let config = parse(raw).unwrap();
        assert_eq!(
            config.env.get("XRAY_TEST_VAR_1"),
            Some(&"hello".to_string())
        );
        assert_eq!(
            config.env.get("XRAY_TEST_VAR_2"),
            Some(&"world".to_string())
        );
        assert_eq!(get_env("XRAY_TEST_VAR_1"), Some("hello".to_string()));
    }
}
