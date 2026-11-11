//! Xray routing for the server: rules pick an outbound tag, and only freedom
//! (direct) and blackhole outbounds are implemented. Traffic routed to any
//! other outbound is blocked so it never silently leaves via the server IP.
//!
//! Domain/IP/port/network/inboundTag matching, including geoip and geosite,
//! reuses xray-config's parser. Fields that parser does not know (user,
//! source, sourcePort, protocol) are matched here.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use regex::Regex;
use serde_json::{json, Value};
use xray_config::{Network, RoutingDomainStrategy, RoutingRule};
use xray_transport::TcpFragmentConfig;

use crate::dns_outbound::DnsOutbound;
use crate::http_outbound::HttpOutbound;
use crate::log;
use crate::shadowsocks_outbound::ShadowsocksOutbound;
use crate::socks::SocksOutbound;
use crate::trojan_outbound::TrojanOutbound;
use crate::vless::{is_private, Host};
use crate::vless_outbound::VlessOutbound;
use crate::vmess_outbound::VmessOutbound;
use crate::wg::WgOutbound;

const STUB_TAG: &str = "rule";
const SERVER_FIELDS: [&str; 10] = [
    "user",
    "source",
    "sourcePort",
    "protocol",
    "localPort",
    "attrs",
    "vlessRoute",
    "localIP",
    "process",
    "webhook",
];
const IGNORED_FIELDS: [&str; 2] = ["ruleTag", "domainMatcher"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreedomStrategy {
    #[default]
    AsIs,
    UseIP,
    UseIPv4,
    UseIPv6,
    UseIPv4v6,
    UseIPv6v4,
    ForceIP,
    ForceIPv4,
    ForceIPv6,
    ForceIPv4v6,
    ForceIPv6v4,
}

impl FreedomStrategy {
    /// Xray's names, read without case.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "" | "asis" => Self::AsIs,
            "useip" => Self::UseIP,
            "useipv4" => Self::UseIPv4,
            "useipv6" => Self::UseIPv6,
            "useipv4v6" => Self::UseIPv4v6,
            "useipv6v4" => Self::UseIPv6v4,
            "forceip" => Self::ForceIP,
            "forceipv4" => Self::ForceIPv4,
            "forceipv6" => Self::ForceIPv6,
            "forceipv4v6" => Self::ForceIPv4v6,
            "forceipv6v4" => Self::ForceIPv6v4,
            _ => return None,
        })
    }

    /// Xray's strategy table: (none 0 / use 1 / force 2, preferred family,
    /// fallback family), a family being 4, 6 or 0 for both.
    pub fn table(self) -> (u8, u8, u8) {
        match self {
            Self::AsIs => (0, 0, 0),
            Self::UseIP => (1, 0, 0),
            Self::UseIPv4 => (1, 4, 0),
            Self::UseIPv6 => (1, 6, 0),
            Self::UseIPv4v6 => (1, 4, 6),
            Self::UseIPv6v4 => (1, 6, 4),
            Self::ForceIP => (2, 0, 0),
            Self::ForceIPv4 => (2, 4, 0),
            Self::ForceIPv6 => (2, 6, 0),
            Self::ForceIPv4v6 => (2, 4, 6),
            Self::ForceIPv6v4 => (2, 6, 4),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedirectSetting {
    pub host: Option<Host>,
    pub port: u16,
}

impl RedirectSetting {
    pub fn apply(&self, host: &Host, port: u16) -> (Host, u16) {
        let h = self.host.as_ref().unwrap_or(host).clone();
        let p = if self.port != 0 { self.port } else { port };
        (h, p)
    }
}

pub fn parse_redirect(s: &str) -> Result<Option<RedirectSetting>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let (host_str, port_str) = if let Some(bracket_end) = s.find(']') {
        if !s.starts_with('[') {
            return Err(format!("invalid redirect {s:?}"));
        }
        let host = &s[1..bracket_end];
        let rest = &s[bracket_end + 1..];
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("invalid redirect {s:?}"))?;
        (host, port_str)
    } else if let Some(colon) = s.rfind(':') {
        let host = &s[..colon];
        let port_str = &s[colon + 1..];
        (host, port_str)
    } else {
        return Err(format!("redirect must be host:port, got {s:?}"));
    };

    let port: u16 = if port_str.is_empty() {
        0
    } else {
        port_str
            .parse()
            .map_err(|_| format!("invalid redirect port {port_str:?}"))?
    };

    let host_trimmed = host_str.trim();
    let host = if host_trimmed.is_empty() || host_trimmed == "0.0.0.0" || host_trimmed == "::" {
        None
    } else if let Ok(ip) = host_trimmed.parse::<IpAddr>() {
        Some(Host::Ip(ip))
    } else {
        Some(Host::Domain(host_trimmed.to_owned()))
    };

    if host.is_none() && port == 0 {
        Ok(None)
    } else {
        Ok(Some(RedirectSetting { host, port }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreedomFragmentPackets {
    TlsHello,
    All,
    Range(u64, u64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FreedomFragmentSetting {
    pub packets: FreedomFragmentPackets,
    pub length: (u64, u64),
    pub interval: (u64, u64),
    pub max_split: (u64, u64),
    pub tcp_fragment: Option<Arc<TcpFragmentConfig>>,
}

pub fn parse_fragment(v: &Value) -> Result<FreedomFragmentSetting, String> {
    let packets_str = v
        .get("packets")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let packets = match packets_str.to_ascii_lowercase().as_str() {
        "tlshello" | "1" => FreedomFragmentPackets::TlsHello,
        "" | "all" => FreedomFragmentPackets::All,
        range_s => {
            let (from, to) =
                parse_u64_range_str(range_s).map_err(|e| format!("Invalid PacketsFrom: {e}"))?;
            if from == 0 {
                return Err("PacketsFrom can't be 0".to_string());
            }
            FreedomFragmentPackets::Range(from, to)
        }
    };

    let length_val = v
        .get("length")
        .or_else(|| v.get("lengths"))
        .ok_or("Length can't be empty")?;
    let (len_min, len_max) =
        parse_u64_range(length_val).map_err(|_| "Length can't be empty".to_string())?;
    if len_min == 0 {
        return Err("LengthMin can't be 0".to_string());
    }

    let interval_val = v
        .get("interval")
        .or_else(|| v.get("intervals"))
        .or_else(|| v.get("delay"))
        .or_else(|| v.get("delays"))
        .ok_or("Interval can't be empty")?;
    let (int_min, int_max) =
        parse_u64_range(interval_val).map_err(|_| "Interval can't be empty".to_string())?;

    let max_split = if let Some(ms) = v.get("maxSplit") {
        parse_u64_range(ms).unwrap_or((0, 0))
    } else {
        (0, 0)
    };

    let tcp_fragment = if matches!(packets, FreedomFragmentPackets::TlsHello) {
        let lengths: Vec<std::ops::RangeInclusive<u32>> = if let Some(arr) = v
            .get("lengths")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
        {
            arr.iter()
                .filter_map(|item| parse_u64_range(item).ok())
                .map(|(min, max)| (min as u32)..=(max as u32))
                .collect()
        } else {
            vec![(len_min as u32)..=(len_max as u32)]
        };
        let delays: Vec<std::ops::RangeInclusive<u32>> = if let Some(arr) = v
            .get("delays")
            .or_else(|| v.get("intervals"))
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
        {
            arr.iter()
                .filter_map(|item| parse_u64_range(item).ok())
                .map(|(min, max)| (min as u32)..=(max as u32))
                .collect()
        } else {
            vec![(int_min as u32)..=(int_max as u32)]
        };
        let split = if max_split.1 > 0 {
            (max_split.0 as u32)..=(max_split.1 as u32)
        } else {
            0..=0
        };
        TcpFragmentConfig::new(lengths, delays, split)
            .ok()
            .map(Arc::new)
    } else {
        None
    };

    Ok(FreedomFragmentSetting {
        packets,
        length: (len_min, len_max),
        interval: (int_min, int_max),
        max_split,
        tcp_fragment,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreedomNoiseFamily {
    Ip,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreedomNoisePacket {
    Bytes(Vec<u8>),
    Random(u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreedomNoiseSetting {
    pub apply_to: FreedomNoiseFamily,
    pub packet: FreedomNoisePacket,
    pub delay_ms: (u64, u64),
}

pub fn parse_freedom_noises(settings: &Value) -> Result<Vec<FreedomNoiseSetting>, String> {
    if settings.get("noise").is_some() {
        return Err("The feature noise = { ... } has been removed and migrated to noises = [ { ... } ]. Please update your config(s) according to release note and documentation.".to_string());
    }
    let Some(noises_val) = settings.get("noises").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for n in noises_val {
        let noise_type = n.get("type").and_then(Value::as_str).unwrap_or("rand");
        let packet_val = n.get("packet").and_then(Value::as_str).unwrap_or("").trim();
        let packet = match noise_type {
            "rand" => {
                let (min, max) = parse_u64_range_str(packet_val)
                    .map_err(|e| format!("invalid value for rand Length: {e}"))?;
                if min == 0 {
                    return Err("rand lengthMin or lengthMax cannot be 0".to_string());
                }
                FreedomNoisePacket::Random(min, max)
            }
            "str" => FreedomNoisePacket::Bytes(packet_val.as_bytes().to_vec()),
            "hex" => {
                let clean = packet_val.strip_prefix("0x").unwrap_or(packet_val);
                let bytes = decode_hex(clean).map_err(|_| "Invalid hex string".to_string())?;
                FreedomNoisePacket::Bytes(bytes)
            }
            "base64" => {
                use base64::Engine;
                let clean = packet_val
                    .replace('+', "-")
                    .replace('/', "_")
                    .replace('=', "");
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&clean)
                    .or_else(|_| base64::engine::general_purpose::STANDARD.decode(packet_val))
                    .map_err(|_| "Invalid base64 string".to_string())?;
                FreedomNoisePacket::Bytes(bytes)
            }
            _ => return Err("Invalid packet, only rand/str/hex/base64 are supported".to_string()),
        };

        let delay_ms = if let Some(d) = n.get("delay") {
            parse_u64_range(d).unwrap_or((0, 0))
        } else {
            (0, 0)
        };

        let apply_to = match n
            .get("applyTo")
            .and_then(Value::as_str)
            .unwrap_or("ip")
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "ip" | "all" => FreedomNoiseFamily::Ip,
            "ipv4" => FreedomNoiseFamily::Ipv4,
            "ipv6" => FreedomNoiseFamily::Ipv6,
            _ => return Err("Invalid applyTo, only ip/ipv4/ipv6 are supported".to_string()),
        };

        result.push(FreedomNoiseSetting {
            apply_to,
            packet,
            delay_ms,
        });
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendThrough {
    Ip(IpAddr),
    Cidr(IpAddr, u8),
    SrcIp,
    Origin,
}

impl SendThrough {
    pub fn resolve_ip(&self) -> Option<IpAddr> {
        use rand::Rng;
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Cidr(base, prefix) => {
                let mask_bits = *prefix;
                match base {
                    IpAddr::V4(v4) => {
                        let total_bits = 32u8;
                        if mask_bits >= total_bits {
                            return Some(IpAddr::V4(*v4));
                        }
                        let host_bits = total_bits - mask_bits;
                        let max_offset = 1u64 << host_bits;
                        let offset = rand::thread_rng().gen_range(0..max_offset) as u32;
                        let ip_num = u32::from(*v4);
                        let mask = !((1u32 << host_bits) - 1);
                        let network = ip_num & mask;
                        Some(IpAddr::V4(std::net::Ipv4Addr::from(network | offset)))
                    }
                    IpAddr::V6(v6) => {
                        let total_bits = 128u8;
                        if mask_bits >= total_bits {
                            return Some(IpAddr::V6(*v6));
                        }
                        let host_bits = total_bits - mask_bits;
                        let ip_num = u128::from(*v6);
                        let offset: u128 = if host_bits <= 64 {
                            rand::thread_rng().gen_range(0..(1u64 << host_bits)) as u128
                        } else {
                            rand::random::<u128>() & ((1u128 << host_bits) - 1)
                        };
                        let mask = !((1u128 << host_bits) - 1);
                        let network = ip_num & mask;
                        Some(IpAddr::V6(std::net::Ipv6Addr::from(network | offset)))
                    }
                }
            }
            Self::SrcIp | Self::Origin => None,
        }
    }
}

pub fn parse_send_through(v: Option<&Value>) -> Result<Option<SendThrough>, String> {
    let Some(v) = v else { return Ok(None) };
    let s = v
        .as_str()
        .ok_or_else(|| "sendThrough must be a string".to_string())?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if s.eq_ignore_ascii_case("srcip") {
        return Ok(Some(SendThrough::SrcIp));
    }
    if s.eq_ignore_ascii_case("origin") {
        return Ok(Some(SendThrough::Origin));
    }
    if let Some((ip_s, cidr_s)) = s.split_once('/') {
        let ip = ip_s
            .parse::<IpAddr>()
            .map_err(|_| format!("unable to send through: {s}"))?;
        let prefix = cidr_s
            .parse::<u8>()
            .map_err(|_| format!("unable to send through: {s}"))?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(format!("unable to send through: {s}"));
        }
        return Ok(Some(SendThrough::Cidr(ip, prefix)));
    }
    let ip = s
        .parse::<IpAddr>()
        .map_err(|_| format!("unable to send through: {s}"))?;
    Ok(Some(SendThrough::Ip(ip)))
}

pub fn parse_dialer_proxy(outbound: &Value, _tag: &str) -> Result<Option<String>, String> {
    let dialer = outbound
        .pointer("/streamSettings/sockopt/dialerProxy")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let proxy = outbound.get("proxySettings").filter(|v| !v.is_null());

    if let Some(dialer_tag) = dialer {
        if proxy.is_some() {
            return Err("proxySettings and sockopt.dialerProxy cannot be combined".to_string());
        }
        return Ok(Some(dialer_tag.to_string()));
    }

    if let Some(proxy_val) = proxy {
        if !proxy_val.is_object() {
            return Err("outbound proxySettings must be an object".to_string());
        }
        let ptag = proxy_val
            .get("tag")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "outbound proxySettings tag must be a non-empty string".to_string())?;
        let transport_layer = proxy_val
            .get("transportLayer")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !transport_layer {
            return Err(
                "only transport-layer outbound chaining is supported; transportLayer must be true"
                    .to_string(),
            );
        }
        return Ok(Some(ptag.to_string()));
    }

    Ok(None)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn parse_u64_range_str(s: &str) -> Result<(u64, u64), String> {
    let s = s.trim();
    if let Some((start_s, end_s)) = s.split_once('-') {
        let start: u64 = start_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid range start in {s:?}"))?;
        let end: u64 = end_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid range end in {s:?}"))?;
        Ok((start, end))
    } else {
        let val: u64 = s.parse().map_err(|_| format!("invalid number in {s:?}"))?;
        Ok((val, val))
    }
}

fn parse_u64_range(v: &Value) -> Result<(u64, u64), String> {
    match v {
        Value::Number(n) => {
            let val = n.as_u64().ok_or("number out of range")?;
            Ok((val, val))
        }
        Value::String(s) => parse_u64_range_str(s),
        Value::Object(obj) => {
            let from = obj.get("from").and_then(Value::as_u64).unwrap_or(0);
            let to = obj.get("to").and_then(Value::as_u64).unwrap_or(from);
            Ok((from, to))
        }
        Value::Array(arr) if !arr.is_empty() => parse_u64_range(&arr[0]),
        _ => Err("expected number, string or range object".into()),
    }
}

/// Xray-core's blackhole `http` response: Go's `http.Response.Write` of a
/// 403 with sorted headers.
pub const BLACKHOLE_HTTP_RESPONSE: &[u8] = b"HTTP/1.1 403 Forbidden\r\nCache-Control: max-age=3600, public\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FreedomSettings {
    pub strategy: FreedomStrategy,
    pub redirect: Option<RedirectSetting>,
    pub fragment: Option<FreedomFragmentSetting>,
    pub noises: Vec<FreedomNoiseSetting>,
    pub send_through: Option<SendThrough>,
    pub dialer_proxy: Option<String>,
    pub sockopt: Option<Arc<crate::config::SockoptSettings>>,
}

impl From<FreedomStrategy> for FreedomSettings {
    fn from(strategy: FreedomStrategy) -> Self {
        Self {
            strategy,
            redirect: None,
            fragment: None,
            noises: Vec::new(),
            send_through: None,
            dialer_proxy: None,
            sockopt: None,
        }
    }
}

use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct StrategyWeight {
    pub regexp: bool,
    pub match_str: String,
    pub value: f64,
    compiled: Option<CompiledRegex>,
}

#[derive(Debug, Clone)]
struct CompiledRegex(Regex);

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeastLoadConfig {
    pub costs: Vec<StrategyWeight>,
    pub baselines: Vec<Duration>,
    pub expected: i32,
    pub max_rtt: Duration,
    pub tolerance: f64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum BalancerStrategy {
    #[default]
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad(LeastLoadConfig),
}

pub struct Balancer {
    pub tag: String,
    pub selectors: Vec<String>,
    pub strategy: BalancerStrategy,
    pub fallback_tag: Option<String>,
    pub override_target: std::sync::RwLock<Option<String>>,
    counter: AtomicUsize,
}

#[allow(dead_code)]
pub struct LeastLoadNode {
    pub tag: String,
    pub count_all: i64,
    pub count_fail: i64,
    pub rtt_average: Duration,
    pub rtt_deviation: Duration,
    pub rtt_deviation_cost: Duration,
}

fn leastload_sort(nodes: &mut [LeastLoadNode]) {
    nodes.sort_by(|left, right| {
        left.rtt_deviation_cost
            .cmp(&right.rtt_deviation_cost)
            .then_with(|| left.rtt_average.cmp(&right.rtt_average))
            .then_with(|| left.count_fail.cmp(&right.count_fail))
            .then_with(|| right.count_all.cmp(&left.count_all))
            .then_with(|| left.tag.cmp(&right.tag))
    });
}

static NUMBER_FINDER: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"\d+(\.\d+)?").unwrap());

fn apply_cost(tag: &str, value: Duration, costs: &[StrategyWeight]) -> Duration {
    let mut weight = 1.0f64;
    for w in costs {
        let matched = if w.regexp {
            w.compiled.as_ref().is_some_and(|re| re.0.is_match(tag))
        } else {
            tag.contains(&w.match_str)
        };
        if matched {
            if w.value > 0.0 {
                weight = w.value;
                break;
            }
            if let Some(num_re) = NUMBER_FINDER.find(&w.match_str) {
                if let Ok(num) = num_re.as_str().parse::<f64>() {
                    weight = num;
                    break;
                }
            }
        }
    }
    let scaled = value.as_secs_f64() * weight.powf(0.5);
    Duration::try_from_secs_f64(scaled).unwrap_or(Duration::MAX)
}

pub fn select_least_load_nodes(
    candidates: &[&str],
    observatory: &crate::observatory::Observatory,
    config: &LeastLoadConfig,
) -> Vec<LeastLoadNode> {
    let mut qualified = Vec::new();
    for tag in candidates {
        if let Some(status) = observatory.get_status_for(tag) {
            if !status.alive {
                continue;
            }
            if !config.max_rtt.is_zero() && status.delay >= config.max_rtt.as_millis() as i64 {
                continue;
            }
            if let Some(hp) = &status.health_ping {
                if hp.all > 0 && config.tolerance > 0.0 {
                    let fail_rate = hp.fail as f64 / hp.all as f64;
                    if fail_rate > config.tolerance {
                        continue;
                    }
                }
            }

            let (count_all, count_fail, rtt_average, rtt_deviation) =
                if let Some(hp) = &status.health_ping {
                    (
                        hp.all,
                        hp.fail,
                        Duration::from_nanos(hp.average.max(0) as u64),
                        Duration::from_nanos(hp.deviation.max(0) as u64),
                    )
                } else {
                    (
                        1,
                        1,
                        Duration::from_millis(status.delay.max(0) as u64),
                        Duration::from_millis(status.delay.max(0) as u64),
                    )
                };

            let rtt_deviation_cost = apply_cost(tag, rtt_deviation, &config.costs);

            qualified.push(LeastLoadNode {
                tag: (*tag).to_owned(),
                count_all,
                count_fail,
                rtt_average,
                rtt_deviation,
                rtt_deviation_cost,
            });
        }
    }

    if qualified.is_empty() {
        return Vec::new();
    }

    leastload_sort(&mut qualified);

    let expected = if config.expected <= 0 {
        1
    } else {
        config.expected as usize
    };
    let available = qualified.len();
    if expected > available {
        return qualified;
    }
    if config.baselines.is_empty() {
        qualified.truncate(expected);
        return qualified;
    }

    let mut count = 0;
    for b in &config.baselines {
        for (i, node) in qualified.iter().enumerate().take(available).skip(count) {
            if node.rtt_deviation_cost >= *b {
                break;
            }
            count = i + 1;
        }
        if count >= expected {
            break;
        }
    }
    if config.expected > 0 && count < expected {
        count = expected;
    }
    qualified.truncate(count.min(available));
    qualified
}

impl Balancer {
    pub fn parse(index: usize, val: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("routing.balancers[{index}]: {m}");
        let tag = str_field(val, "tag").trim();
        if tag.is_empty() {
            return Err(err("missing or empty tag"));
        }
        let mut selectors = Vec::new();
        if let Some(sel) = val.get("selector") {
            if let Some(s) = sel.as_str() {
                if !s.is_empty() {
                    selectors.push(s.to_owned());
                }
            } else if let Some(arr) = sel.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str().filter(|s| !s.is_empty()) {
                        selectors.push(s.to_owned());
                    }
                }
            }
        }
        if selectors.is_empty() {
            return Err(err("selector must contain at least one non-empty string"));
        }
        let strategy = if let Some(strat) = val.get("strategy") {
            let strat_str = if let Some(s) = strat.as_str() {
                s
            } else {
                strat
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("random")
            };
            match strat_str.to_ascii_lowercase().as_str() {
                "random" | "" => BalancerStrategy::Random,
                "roundrobin" => BalancerStrategy::RoundRobin,
                "leastping" => BalancerStrategy::LeastPing,
                "leastload" => {
                    let settings_val = strat.get("settings").unwrap_or(&Value::Null);
                    let mut costs = Vec::new();
                    if let Some(arr) = settings_val.get("costs").and_then(Value::as_array) {
                        for c in arr {
                            let regexp = c.get("regexp").and_then(Value::as_bool).unwrap_or(false);
                            let match_str = c
                                .get("match")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let value = c.get("value").and_then(Value::as_f64).unwrap_or(0.0);
                            let compiled = if regexp {
                                Regex::new(&match_str).ok().map(CompiledRegex)
                            } else {
                                None
                            };
                            costs.push(StrategyWeight {
                                regexp,
                                match_str,
                                value,
                                compiled,
                            });
                        }
                    }
                    let mut baselines = Vec::new();
                    if let Some(arr) = settings_val.get("baselines").and_then(Value::as_array) {
                        for b in arr {
                            if let Some(s) = b.as_str() {
                                if let Some(d) = xray_config::parse_xray_duration(s) {
                                    baselines.push(d);
                                }
                            } else if let Some(n) = b.as_i64() {
                                if n > 0 {
                                    baselines.push(Duration::from_nanos(n as u64));
                                }
                            }
                        }
                    }
                    let expected = settings_val
                        .get("expected")
                        .and_then(Value::as_i64)
                        .unwrap_or(0) as i32;
                    let max_rtt = settings_val
                        .get("maxRTT")
                        .and_then(Value::as_str)
                        .and_then(xray_config::parse_xray_duration)
                        .unwrap_or_default();
                    let tolerance = settings_val
                        .get("tolerance")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);

                    BalancerStrategy::LeastLoad(LeastLoadConfig {
                        costs,
                        baselines,
                        expected,
                        max_rtt,
                        tolerance,
                    })
                }
                other => return Err(err(&format!("unsupported strategy {other:?}"))),
            }
        } else {
            BalancerStrategy::Random
        };

        let fallback_tag = val
            .get("fallbackTag")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        Ok(Self {
            tag: tag.to_owned(),
            selectors,
            strategy,
            fallback_tag,
            override_target: std::sync::RwLock::new(None),
            counter: AtomicUsize::new(0),
        })
    }

    pub fn select<'a>(
        &self,
        outbounds: &'a HashMap<String, Action>,
        observatory: Option<&crate::observatory::Observatory>,
    ) -> Option<(&'a str, &'a Action)> {
        if let Some(target) = self.override_target.read().unwrap().as_ref() {
            if let Some((tag, action)) = outbounds.get_key_value(target) {
                return Some((tag.as_str(), action));
            }
        }

        let mut candidates: Vec<(&str, &Action)> = outbounds
            .iter()
            .filter(|(tag, _)| self.selectors.iter().any(|prefix| tag.starts_with(prefix)))
            .map(|(t, a)| (t.as_str(), a))
            .collect();
        candidates.sort_by_key(|(t, _)| *t);

        if candidates.is_empty() {
            if let Some(fallback) = &self.fallback_tag {
                if let Some((tag, action)) = outbounds.get_key_value(fallback) {
                    return Some((tag.as_str(), action));
                }
            }
            return None;
        }

        match &self.strategy {
            BalancerStrategy::Random => {
                let mut valid = candidates;
                if let Some(obs) = observatory {
                    valid.retain(|(t, _)| obs.get_status_for(t).is_none_or(|s| s.alive));
                }
                if valid.is_empty() {
                    if let Some(fallback) = &self.fallback_tag {
                        if let Some((tag, action)) = outbounds.get_key_value(fallback) {
                            return Some((tag.as_str(), action));
                        }
                    }
                    return None;
                }
                let index = rand::random::<usize>() % valid.len();
                Some(valid[index])
            }
            BalancerStrategy::RoundRobin => {
                let mut valid = candidates;
                if let Some(obs) = observatory {
                    valid.retain(|(t, _)| obs.get_status_for(t).is_none_or(|s| s.alive));
                }
                if valid.is_empty() {
                    if let Some(fallback) = &self.fallback_tag {
                        if let Some((tag, action)) = outbounds.get_key_value(fallback) {
                            return Some((tag.as_str(), action));
                        }
                    }
                    return None;
                }
                let index = self.counter.fetch_add(1, Ordering::Relaxed) % valid.len();
                Some(valid[index])
            }
            BalancerStrategy::LeastPing => {
                let mut least_ping = i64::MAX;
                let mut selected = None;
                if let Some(obs) = observatory {
                    for (tag, action) in &candidates {
                        if let Some(status) = obs.get_status_for(tag) {
                            if status.alive && status.delay < least_ping {
                                least_ping = status.delay;
                                selected = Some((*tag, *action));
                            }
                        }
                    }
                }
                if let Some(best) = selected {
                    return Some(best);
                }
                if let Some(fallback) = &self.fallback_tag {
                    if let Some((tag, action)) = outbounds.get_key_value(fallback) {
                        return Some((tag.as_str(), action));
                    }
                }
                None
            }
            BalancerStrategy::LeastLoad(settings) => {
                let candidate_tags: Vec<&str> = candidates.iter().map(|(t, _)| *t).collect();
                if let Some(obs) = observatory {
                    let nodes = select_least_load_nodes(&candidate_tags, obs, settings);
                    if !nodes.is_empty() {
                        let idx = rand::random::<usize>() % nodes.len();
                        let chosen_tag = &nodes[idx].tag;
                        if let Some(found) = candidates.into_iter().find(|(t, _)| *t == chosen_tag)
                        {
                            return Some(found);
                        }
                    }
                }
                if let Some(fallback) = &self.fallback_tag {
                    if let Some((tag, action)) = outbounds.get_key_value(fallback) {
                        return Some((tag.as_str(), action));
                    }
                }
                None
            }
        }
    }

    pub fn get_principle_target(
        &self,
        outbounds: &HashMap<String, Action>,
        observatory: Option<&crate::observatory::Observatory>,
    ) -> Vec<String> {
        let mut candidates: Vec<&str> = outbounds
            .keys()
            .filter(|tag| self.selectors.iter().any(|prefix| tag.starts_with(prefix)))
            .map(|s| s.as_str())
            .collect();
        candidates.sort();

        match &self.strategy {
            BalancerStrategy::Random | BalancerStrategy::RoundRobin => {
                candidates.into_iter().map(str::to_owned).collect()
            }
            BalancerStrategy::LeastPing => {
                let mut least_ping = i64::MAX;
                let mut selected = None;
                if let Some(obs) = observatory {
                    for tag in candidates {
                        if let Some(status) = obs.get_status_for(tag) {
                            if status.alive && status.delay < least_ping {
                                least_ping = status.delay;
                                selected = Some(tag.to_owned());
                            }
                        }
                    }
                }
                selected.into_iter().collect()
            }
            BalancerStrategy::LeastLoad(settings) => {
                if let Some(obs) = observatory {
                    let nodes = select_least_load_nodes(&candidates, obs, settings);
                    nodes.into_iter().map(|n| n.tag).collect()
                } else {
                    Vec::new()
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockAction {
    #[default]
    Drop,
    Http403,
    /// freedom's `finalRules` block: the connection is held, its input
    /// discarded, for a random delay in seconds, then closed.
    Hold(FinalBlock),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalBlock {
    pub delay: (u64, u64),
    pub log: FinalLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalLog {
    None,
    Debug,
    Info,
    Warning,
    Error,
}

/// Xray's default private-address and block rules: 30 to 90 s, at warning.
pub const DEFAULT_FINAL_BLOCK: FinalBlock = FinalBlock {
    delay: (30, 90),
    log: FinalLog::Warning,
};

/// A `finalRules` entry's `delay` (or the deprecated `blockDelay`) and
/// `logLevel`, which Xray allows on block rules only.
fn parse_final_block(raw: &Value, block: bool, at: &str) -> Result<FinalBlock, String> {
    let mut delay = raw.get("delay").filter(|v| !v.is_null());
    if let Some(old) = raw.get("blockDelay").filter(|v| !v.is_null()) {
        log::warn(format!(
            "{at}: finalRules.blockDelay is deprecated, use finalRules.delay"
        ));
        delay = Some(old);
    }
    let level = str_field(raw, "logLevel");
    if !block {
        if delay.is_some() || !level.is_empty() {
            return Err("delay and logLevel are only supported for block finalRules".into());
        }
        return Ok(DEFAULT_FINAL_BLOCK);
    }
    let delay = match delay {
        None => (30, 90),
        Some(Value::Number(n)) => {
            let n = n.as_u64().ok_or(format!("{at}: invalid delay {n}"))?;
            (n, n)
        }
        Some(Value::String(text)) => {
            let parse = |t: &str| {
                t.trim()
                    .parse::<u64>()
                    .map_err(|_| format!("{at}: invalid delay {text:?}"))
            };
            match text.split_once('-') {
                Some((from, to)) => (parse(from)?, parse(to)?),
                None => {
                    let n = parse(text)?;
                    (n, n)
                }
            }
        }
        Some(other) => return Err(format!("{at}: invalid delay {other}")),
    };
    let log = match level.to_ascii_lowercase().as_str() {
        "" | "info" => FinalLog::Info,
        "none" => FinalLog::None,
        "debug" => FinalLog::Debug,
        "warning" => FinalLog::Warning,
        "error" => FinalLog::Error,
        _ => return Err(format!("unknown finalRules.logLevel: {level}")),
    };
    Ok(FinalBlock { delay, log })
}

#[derive(Debug, Clone)]
pub enum Action {
    Direct(FreedomSettings),
    Block(BlockAction),
    Wireguard(Arc<WgOutbound>),
    Socks(Arc<SocksOutbound>),
    Vless(Arc<VlessOutbound>),
    Vmess(Arc<VmessOutbound>),
    Trojan(Arc<TrojanOutbound>),
    Shadowsocks(Arc<ShadowsocksOutbound>),
    Http(Arc<HttpOutbound>),
    Dns(Arc<DnsOutbound>),
    Hysteria(Arc<crate::hysteria_outbound::HysteriaOutbound>),
    Masque(Arc<crate::masque_outbound::MasqueOutbound>),
    Loopback(String),
    /// The `metrics` section's tag: connections reach its HTTP server.
    Metrics,
    Reverse(Arc<crate::mux::ReversePortal>),
}

impl PartialEq for Action {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct(a), Self::Direct(b)) => a == b,
            (Self::Block(a), Self::Block(b)) => a == b,
            (Self::Wireguard(a), Self::Wireguard(b)) => Arc::ptr_eq(a, b),
            (Self::Socks(a), Self::Socks(b)) => Arc::ptr_eq(a, b),
            (Self::Vless(a), Self::Vless(b)) => Arc::ptr_eq(a, b),
            (Self::Vmess(a), Self::Vmess(b)) => Arc::ptr_eq(a, b),
            (Self::Trojan(a), Self::Trojan(b)) => Arc::ptr_eq(a, b),
            (Self::Shadowsocks(a), Self::Shadowsocks(b)) => Arc::ptr_eq(a, b),
            (Self::Http(a), Self::Http(b)) => Arc::ptr_eq(a, b),
            (Self::Dns(a), Self::Dns(b)) => Arc::ptr_eq(a, b),
            (Self::Hysteria(a), Self::Hysteria(b)) => Arc::ptr_eq(a, b),
            (Self::Masque(a), Self::Masque(b)) => Arc::ptr_eq(a, b),
            (Self::Reverse(a), Self::Reverse(b)) => Arc::ptr_eq(a, b),
            (Self::Loopback(a), Self::Loopback(b)) => a == b,
            (a, b) => std::mem::discriminant(a) == std::mem::discriminant(b),
        }
    }
}

impl Eq for Action {}

impl Action {
    pub fn set_chained_connector(&self, connector: Arc<dyn xray_transport::ResolvedTcpConnector>) {
        match self {
            Action::Socks(socks) => socks.set_chained_connector(connector),
            Action::Vless(vless) => vless.set_chained_connector(connector),
            Action::Vmess(vmess) => vmess.connector.set_chained_connector(connector),
            Action::Trojan(trojan) => trojan.connector.set_chained_connector(connector),
            Action::Shadowsocks(ss) => ss.connector.set_chained_connector(connector),
            Action::Http(http) => http.connector.set_chained_connector(connector),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub tag: String,
    pub action: Action,
    /// Freedom may dial private addresses with no matching `finalRules`
    /// entry: Xray blocks them only for public proxy inbounds.
    pub open_private: bool,
}

pub struct Query<'a> {
    pub inbound: &'a str,
    pub inbound_port: u16,
    pub user: &'a str,
    pub source: SocketAddr,
    pub network: Network,
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: Option<&'static str>,
    pub attributes: Option<&'a HashMap<String, String>>,
    pub local_ip: Option<IpAddr>,
    pub vless_route: Option<u32>,
    pub process_info: Option<&'a std::sync::OnceLock<Option<crate::process::ProcessInfo>>>,
}

impl<'a> Query<'a> {
    pub fn get_process_info(&self) -> Option<crate::process::ProcessInfo> {
        match self.process_info {
            Some(cell) => cell
                .get_or_init(|| crate::process::find_local_process(self.network, self.source))
                .clone(),
            None => crate::process::find_local_process(self.network, self.source),
        }
    }
}

pub struct WebhookNotifier {
    pub url: String,
    pub socket_path: Option<String>,
    pub headers: HashMap<String, String>,
    pub deduplication: u32,
    seen: std::sync::Mutex<HashMap<String, std::time::Instant>>,
}

impl WebhookNotifier {
    pub fn new(url_str: String, headers: HashMap<String, String>, deduplication: u32) -> Self {
        let (url, socket_path) = split_http_unix_url(&url_str);
        Self {
            url,
            socket_path,
            headers,
            deduplication,
            seen: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn fire(&self, query: &Query<'_>, outbound_tag: &str) {
        let email = query.user;
        if self.is_duplicate(email) {
            return;
        }

        let network_str = match query.network {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        };
        let dest = if let Some(d) = query.domain {
            format!("{d}:{}", query.port)
        } else if let Some(ip) = query.ip {
            format!("{ip}:{}", query.port)
        } else {
            format!("{}:{}", query.port, query.port)
        };
        let orig_target = format!("{network_str}:{dest}");
        let inbound_local = query
            .local_ip
            .map(|ip| format!("{ip}:{}", query.inbound_port));

        let event = json!({
            "email": if email.is_empty() { Value::Null } else { json!(email) },
            "level": 0,
            "protocol": query.protocol.unwrap_or(""),
            "network": network_str,
            "source": query.source.to_string(),
            "destination": dest,
            "originalTarget": orig_target,
            "routeTarget": Value::Null,
            "inboundTag": query.inbound,
            "inboundName": "socks",
            "inboundLocal": inbound_local,
            "outboundTag": outbound_tag,
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        });

        let body = serde_json::to_vec(&event).unwrap_or_default();
        let url = self.url.clone();
        let socket_path = self.socket_path.clone();
        let headers = self.headers.clone();

        tokio::spawn(async move {
            let _ = post_webhook(&url, socket_path.as_deref(), &headers, &body).await;
        });
    }

    fn is_duplicate(&self, email: &str) -> bool {
        if self.deduplication == 0 || email.is_empty() {
            return false;
        }
        let ttl = std::time::Duration::from_secs(self.deduplication as u64);
        let now = std::time::Instant::now();
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, time| now.duration_since(*time) < ttl);
        if let Some(last) = seen.get(email) {
            if now.duration_since(*last) < ttl {
                return true;
            }
        }
        seen.insert(email.to_string(), now);
        false
    }
}

fn split_http_unix_url(raw: &str) -> (String, Option<String>) {
    if raw.is_empty() || (!raw.starts_with('/') && !raw.starts_with('@')) {
        return (raw.to_string(), None);
    }
    if let Some(idx) = raw.find(":/") {
        (
            format!("http://localhost{}", &raw[idx + 1..]),
            Some(raw[..idx].to_string()),
        )
    } else {
        ("http://localhost/".to_string(), Some(raw.to_string()))
    }
}

async fn post_webhook(
    url_str: &str,
    socket_path: Option<&str>,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let clean_url = url_str.strip_prefix("http://").unwrap_or(url_str);
        let (host_port, path) = match clean_url.find('/') {
            Some(idx) => (&clean_url[..idx], &clean_url[idx..]),
            None => (clean_url, "/"),
        };
        let (host, port) = match host_port.find(':') {
            Some(idx) => (
                &host_port[..idx],
                host_port[idx + 1..].parse::<u16>().unwrap_or(80),
            ),
            None => (host_port, 80),
        };

        let mut req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");

        if let Some(sock) = socket_path {
            let mut stream = tokio::net::UnixStream::connect(sock).await?;
            stream.write_all(req.as_bytes()).await?;
            stream.write_all(body).await?;
            stream.flush().await?;
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
        } else {
            let mut stream = tokio::net::TcpStream::connect((host, port)).await?;
            stream.write_all(req.as_bytes()).await?;
            stream.write_all(body).await?;
            stream.flush().await?;
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "webhook timeout"))?
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleTarget {
    Outbound(String),
    Balancer(String),
}

pub struct Router {
    pub rules: std::sync::RwLock<Vec<Rule>>,
    pub strategy: RoutingDomainStrategy,
    pub outbounds: std::sync::RwLock<HashMap<String, Action>>,
    pub balancers: HashMap<String, Arc<Balancer>>,
    pub default_tag: std::sync::RwLock<String>,
    pub sniff: bool,
    pub final_rules: std::sync::RwLock<HashMap<String, Vec<(Action, RoutingRule)>>>,
    pub asset_dirs: Vec<PathBuf>,
    pub observatory: Arc<std::sync::RwLock<Option<Arc<crate::observatory::Observatory>>>>,
    pub dialer_proxies: Vec<(String, String)>,
    pub reverse_portals: std::sync::RwLock<HashMap<String, Arc<crate::mux::ReversePortal>>>,
    pub inbound_protocols: std::sync::RwLock<HashMap<String, String>>,
}

pub struct Rule {
    pub target: RuleTarget,
    pub tag: String,
    pub rule_tag: String,
    pub matcher: RoutingRule,
    pub source: Option<RoutingRule>,
    pub users: Vec<UserMatcher>,
    pub protocols: Vec<String>,
    pub local_ports: Vec<(u16, u16)>,
    pub attrs: HashMap<String, String>,
    pub vless_routes: Vec<(u32, u32)>,
    pub local_ip: Option<RoutingRule>,
    pub process: Option<crate::process::ProcessMatcher>,
    pub webhook: Option<Arc<WebhookNotifier>>,
}

pub enum UserMatcher {
    Exact(String),
    Regex(Regex),
}

impl Router {
    pub fn build(root: &Value, asset_dirs: &[PathBuf]) -> Result<Self, String> {
        let mut outbounds = HashMap::new();
        let reverse_portals = std::sync::RwLock::new(HashMap::new());
        for inbound in array(root, "inbounds") {
            let settings = inbound.get("settings").unwrap_or(&Value::Null);
            for client in array(settings, "clients") {
                if let Some(rev) = client.get("reverse") {
                    let tag = str_field(rev, "tag");
                    if !tag.is_empty() {
                        let portal = Arc::new(crate::mux::ReversePortal::new(tag.to_string()));
                        reverse_portals
                            .write()
                            .unwrap()
                            .insert(tag.to_string(), portal.clone());
                        outbounds.insert(tag.to_string(), Action::Reverse(portal));
                    }
                }
            }
        }
        let mut default_tag = None;
        let mut synth_rules = Vec::new();
        let mut pending_final = Vec::new();
        let mut dialer_proxies = Vec::new();
        for outbound in array(root, "outbounds") {
            let tag = str_field(outbound, "tag").to_owned();
            let protocol = str_field(outbound, "protocol");
            let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
            let network = str_field(stream, "network");

            if network == "masque" && protocol != "masque" {
                return Err("the masque transport can only be used by the masque outbound".into());
            }

            if network == "xdrive" {
                if protocol != "vless" {
                    return Err("the xdrive transport can only be used by VLESS".into());
                }
                let settings = outbound.get("settings").unwrap_or(&Value::Null);
                if let Some(vnext) = settings
                    .get("vnext")
                    .and_then(Value::as_array)
                    .and_then(|v| v.first())
                {
                    if let Some(users) = vnext
                        .get("users")
                        .and_then(Value::as_array)
                        .and_then(|u| u.first())
                    {
                        if !str_field(users, "flow").is_empty() {
                            return Err(
                                "the xdrive transport doesn't support VLESS \"flow\"".into()
                            );
                        }
                        if str_field(users, "encryption") == "none" {
                            return Err("the xdrive transport needs VLESS \"encryption\", run \"xray vlessenc\" to get one".into());
                        }
                        if let Some(testpre) = users.get("testpre").and_then(Value::as_i64) {
                            if testpre != 0 {
                                return Err(
                                    "the xdrive transport doesn't support VLESS \"testpre\"".into(),
                                );
                            }
                        }
                        let has_reverse = users.get("reverse").is_some_and(|r| !r.is_null());
                        if !has_reverse {
                            let mux = outbound.get("mux").unwrap_or(&Value::Null);
                            let mux_enabled =
                                mux.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                            let concurrency =
                                mux.get("concurrency").and_then(Value::as_i64).unwrap_or(0);
                            let xudp_concurrency = mux
                                .get("xudpConcurrency")
                                .and_then(Value::as_i64)
                                .unwrap_or(0);
                            let xudp_skip = str_field(mux, "xudpProxyUDP443") == "skip";
                            if !mux_enabled || concurrency < 0 || xudp_concurrency < 0 || xudp_skip
                            {
                                return Err("the xdrive transport needs \"mux\" enabled, with no negative \"concurrency\" or \"xudpConcurrency\" and no \"xudpProxyUDP443\":\"skip\"".into());
                            }
                        }
                    }
                }
            }

            if matches!(network, "kcp" | "mkcp") {
                let _ = crate::config::parse_kcp(stream)?;
            }

            let action = match protocol {
                "freedom" | "direct" => {
                    let settings = outbound.get("settings").unwrap_or(&Value::Null);
                    // Xray reads targetStrategy first, then the older domainStrategy.
                    let name = match str_field(settings, "targetStrategy") {
                        "" => str_field(settings, "domainStrategy"),
                        name => name,
                    };
                    let domain_strategy = FreedomStrategy::parse(name).ok_or_else(|| {
                        format!("outbound {tag:?}: unsupported domain strategy: {name}")
                    })?;
                    let redirect = if let Some(r) = settings.get("redirect").and_then(Value::as_str)
                    {
                        parse_redirect(r)?
                    } else {
                        None
                    };
                    let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
                    let fragment = if let Some(f) = settings.get("fragment") {
                        Some(parse_fragment(f)?)
                    } else {
                        crate::finalmask::parse_freedom_fragment_from_finalmask(stream)?
                    };
                    let mut noises = parse_freedom_noises(settings)?;
                    if noises.is_empty() {
                        noises = crate::finalmask::parse_finalmask_udp_noises(stream)?;
                    }
                    let send_through = parse_send_through(outbound.get("sendThrough"))?;
                    let dialer_proxy = parse_dialer_proxy(outbound, &tag)?;
                    let sockopt = crate::config::parse_sockopt(
                        outbound
                            .pointer("/streamSettings/sockopt")
                            .unwrap_or(&Value::Null),
                        &format!("outbound {tag:?}"),
                    )?
                    .map(Arc::new);
                    if let Some(ref so) = sockopt {
                        if so.address_port_strategy != crate::config::AddressPortStrategy::None {
                            return Err(
                                "freedom outbound does not support \"sockopt.addressPortStrategy\""
                                    .into(),
                            );
                        }
                    }
                    let freedom_settings = FreedomSettings {
                        strategy: domain_strategy,
                        redirect,
                        fragment,
                        noises,
                        send_through,
                        dialer_proxy,
                        sockopt,
                    };
                    for (index, raw) in array(settings, "finalRules").iter().enumerate() {
                        let at = format!("outbound {tag:?} finalRules[{index}]");
                        let action = match str_field(raw, "action") {
                            "allow" => {
                                parse_final_block(raw, false, &at)?;
                                Action::Direct(freedom_settings.clone())
                            }
                            "block" => {
                                Action::Block(BlockAction::Hold(parse_final_block(raw, true, &at)?))
                            }
                            other => {
                                return Err(format!(
                                "outbound {tag:?} finalRules[{index}]: unknown action {other:?}"
                            ))
                            }
                        };
                        let mut rule =
                            json!({"type": "field", "outboundTag": STUB_TAG, "network": "tcp,udp"});
                        for key in ["network", "port", "ip"] {
                            if let Some(value) = raw.get(key).filter(|v| !v.is_null()) {
                                rule[key] = value.clone();
                            }
                        }
                        pending_final.push((tag.clone(), action, synth_rules.len()));
                        synth_rules.push(rule);
                    }
                    Action::Direct(freedom_settings)
                }
                "blackhole" | "block" => {
                    let settings = outbound.get("settings").unwrap_or(&Value::Null);
                    let resp = settings.get("response").unwrap_or(&Value::Null);
                    let block_action = match str_field(resp, "type") {
                        "" | "none" => BlockAction::Drop,
                        "http" => BlockAction::Http403,
                        other => {
                            log::warn(format!(
                                "outbound {tag:?}: unsupported blackhole response type {other:?}"
                            ));
                            BlockAction::Drop
                        }
                    };
                    Action::Block(block_action)
                }
                "wireguard" => {
                    let wg = Arc::new(WgOutbound::parse(&tag, outbound)?);
                    wg.clone().warm_up();
                    Action::Wireguard(wg)
                }
                "socks" => Action::Socks(Arc::new(SocksOutbound::parse(&tag, outbound)?)),
                "vless" => {
                    require_transport_security(outbound, true)?;
                    Action::Vless(Arc::new(VlessOutbound::parse(&tag, outbound)?))
                }
                "vmess" => Action::Vmess(Arc::new(VmessOutbound::parse(&tag, outbound)?)),
                "trojan" => {
                    let settings = outbound.get("settings").unwrap_or(&Value::Null);
                    if array(settings, "servers")
                        .iter()
                        .chain([settings])
                        .any(|server| !str_field(server, "flow").is_empty())
                    {
                        return Err("The feature Flow for Trojan has been removed. Please update your config(s) according to release note and documentation.".into());
                    }
                    require_transport_security(outbound, false)?;
                    Action::Trojan(Arc::new(TrojanOutbound::parse(&tag, outbound)?))
                }
                "shadowsocks" => {
                    Action::Shadowsocks(Arc::new(ShadowsocksOutbound::parse(&tag, outbound)?))
                }
                "http" => Action::Http(Arc::new(HttpOutbound::parse(&tag, outbound)?)),
                "dns" => Action::Dns(Arc::new(DnsOutbound::parse(&tag, outbound)?)),
                "masque" => Action::Masque(Arc::new(
                    crate::masque_outbound::MasqueOutbound::parse(&tag, outbound)?,
                )),
                "hysteria" | "hysteria2" => {
                    let settings = outbound.get("settings").unwrap_or(&Value::Null);
                    if let Some(v) = settings.get("version") {
                        if v.as_i64() != Some(2) {
                            return Err("version != 2".into());
                        }
                    }
                    if !matches!(network, "hysteria" | "hysteria2") {
                        return Err("not hysteria transport".into());
                    }
                    Action::Hysteria(Arc::new(crate::hysteria_outbound::HysteriaOutbound::parse(
                        &tag, outbound,
                    )?))
                }
                "loopback" => {
                    let settings = outbound.get("settings").unwrap_or(&Value::Null);
                    let inbound_tag = str_field(settings, "inboundTag").to_owned();
                    Action::Loopback(inbound_tag)
                }
                other => {
                    log::warn(format!("outbound {tag:?} ({other}) is not supported yet; traffic routed to it will be blocked"));
                    Action::Block(BlockAction::Drop)
                }
            };
            default_tag.get_or_insert_with(|| tag.clone());
            crate::finalmask::validate_and_log_finalmask(outbound, &tag)?;
            if let Some(proxy_tag) = parse_dialer_proxy(outbound, &tag)? {
                dialer_proxies.push((tag.clone(), proxy_tag));
            }
            if !tag.is_empty() && outbounds.contains_key(&tag) {
                return Err(format!("existing tag found: {tag}"));
            }
            outbounds.insert(tag, action);
        }
        if let Some(metrics) = crate::metrics::parse(root)? {
            outbounds.insert(metrics.tag, Action::Metrics);
        }

        let routing = root.get("routing").cloned().unwrap_or(Value::Null);
        let mut balancers = HashMap::new();
        for (index, raw) in array(&routing, "balancers").iter().enumerate() {
            let balancer = Balancer::parse(index, raw)?;
            if balancers.contains_key(&balancer.tag) {
                return Err("duplicate balancer tag".into());
            }
            balancers.insert(balancer.tag.clone(), Arc::new(balancer));
        }

        let mut rules = Vec::new();
        let mut sniff = false;
        for (index, raw) in array(&routing, "rules").iter().enumerate() {
            let rule = parse_single_rule(raw, asset_dirs)
                .map_err(|e| format!("routing.rules[{index}]: {e}"))?;
            match &rule.target {
                RuleTarget::Outbound(tag) => {
                    if !outbounds.contains_key(tag) {
                        log::debug(format!(
                            "routing: outbound {tag:?} is not defined; matching traffic will be blocked"
                        ));
                        outbounds.insert(tag.clone(), Action::Block(BlockAction::Drop));
                    }
                }
                RuleTarget::Balancer(balancer_tag) => {
                    if !balancers.contains_key(balancer_tag) {
                        return Err(format!(
                            "routing balancer {balancer_tag:?} is not configured"
                        ));
                    }
                }
            }
            sniff |= !rule.protocols.is_empty();
            rules.push(rule);
        }

        let mut final_rules: HashMap<String, Vec<(Action, RoutingRule)>> = HashMap::new();
        if !pending_final.is_empty() {
            let synth = json!({
                "outbounds": [{"tag": STUB_TAG, "protocol": "freedom"}],
                "routing": {"rules": synth_rules}
            });
            let parsed =
                xray_config::parse_xray_json_with_geodata_dirs(&synth.to_string(), asset_dirs)
                    .map_err(|e| {
                        let messages: Vec<String> =
                            e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
                        format!("routing finalRules: {}", messages.join("; "))
                    })?;
            for (tag, action, index) in pending_final {
                final_rules
                    .entry(tag)
                    .or_default()
                    .push((action, parsed.config.routing.rules[index].clone()));
            }
        }

        let strategy = match str_field(&routing, "domainStrategy")
            .to_ascii_lowercase()
            .as_str()
        {
            "ipifnonmatch" => RoutingDomainStrategy::IpIfNonMatch,
            "ipondemand" => RoutingDomainStrategy::IpOnDemand,
            _ => RoutingDomainStrategy::AsIs,
        };

        for (tag, proxy_tag) in &dialer_proxies {
            if !outbounds.contains_key(proxy_tag) {
                return Err("there is no outbound handler for dialerProxy".to_string());
            }
            let mut visited = std::collections::HashSet::new();
            visited.insert(tag.clone());
            let mut curr = proxy_tag;
            while let Some((_, next)) = dialer_proxies.iter().find(|(t, _)| t == curr) {
                if !visited.insert(next.clone()) {
                    return Err(format!(
                        "cycle detected in dialerProxy / proxySettings: {next}"
                    ));
                }
                curr = next;
            }
        }

        Ok(Self {
            rules: std::sync::RwLock::new(rules),
            strategy,
            outbounds: std::sync::RwLock::new(outbounds),
            balancers,
            default_tag: std::sync::RwLock::new(default_tag.unwrap_or_default()),
            sniff,
            final_rules: std::sync::RwLock::new(final_rules),
            asset_dirs: asset_dirs.to_vec(),
            observatory: Arc::new(std::sync::RwLock::new(None)),
            dialer_proxies,
            reverse_portals,
            inbound_protocols: std::sync::RwLock::new(
                array(root, "inbounds")
                    .iter()
                    .filter_map(|inbound| {
                        let tag = str_field(inbound, "tag");
                        (!tag.is_empty())
                            .then(|| (tag.to_owned(), str_field(inbound, "protocol").to_owned()))
                    })
                    .collect(),
            ),
        })
    }

    pub fn get_or_create_reverse_portal(&self, tag: &str) -> Arc<crate::mux::ReversePortal> {
        let mut portals = self.reverse_portals.write().unwrap();
        if let Some(p) = portals.get(tag) {
            return p.clone();
        }
        let portal = Arc::new(crate::mux::ReversePortal::new(tag.to_string()));
        portals.insert(tag.to_string(), portal.clone());
        let mut outbounds = self.outbounds.write().unwrap();
        outbounds.insert(tag.to_string(), Action::Reverse(portal.clone()));
        portal
    }

    pub fn start_reverse_bridges(&self, router: Arc<Router>) {
        let outbounds = self.outbounds.read().unwrap();
        for action in outbounds.values() {
            if let Action::Vless(vless) = action {
                vless.clone().start_reverse_bridge(router.clone());
            }
        }
    }

    pub fn init_chained_outbounds(&self, router: &Arc<Router>) {
        let outbounds = self
            .outbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (tag, proxy_tag) in &self.dialer_proxies {
            let connector = Arc::new(crate::outbound_transport::ChainedTcpConnector {
                router: router.clone(),
                proxy_tag: proxy_tag.clone(),
            });
            if let Some(action) = outbounds.get(tag) {
                action.set_chained_connector(connector);
            }
        }
    }

    pub fn set_observatory(&self, obs: Arc<crate::observatory::Observatory>) {
        *self
            .observatory
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(obs);
    }

    pub fn decision_for_tag(&self, tag: &str) -> Decision {
        let outbounds = self
            .outbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.decision(&outbounds, tag)
    }

    pub fn add_rule(&self, rule: Rule, should_append: bool) {
        let mut rules = self
            .rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if should_append {
            rules.push(rule);
        } else {
            rules.insert(0, rule);
        }
    }

    pub fn remove_rule(&self, rule_tag: &str) -> usize {
        let mut rules = self
            .rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if rule_tag.is_empty() {
            return 0;
        }
        let before = rules.len();
        rules.retain(|r| r.rule_tag != rule_tag);
        before - rules.len()
    }

    pub fn list_rules(&self) -> Vec<(String, String)> {
        let rules = self
            .rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        rules
            .iter()
            .map(|r| (r.tag.clone(), r.rule_tag.clone()))
            .collect()
    }

    pub fn parse_rule(&self, raw: &Value) -> Result<Rule, String> {
        parse_single_rule(raw, &self.asset_dirs)
    }

    /// Tags of the configured outbounds, without internal ones like metrics.
    pub fn outbound_tags(&self) -> Vec<String> {
        self.outbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, action)| !matches!(action, Action::Metrics))
            .map(|(tag, _)| tag.clone())
            .collect()
    }

    /// Returns false, leaving the existing entry, when the tag is taken.
    pub fn add_outbound(&self, tag: String, action: Action) -> bool {
        let mut outbounds = self
            .outbounds
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if outbounds.contains_key(&tag) {
            return false;
        }
        crate::stats::get().register("outbound", &tag);
        outbounds.insert(tag, action);
        true
    }

    pub fn remove_outbound(&self, tag: &str) -> bool {
        let mut outbounds = self
            .outbounds
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        outbounds.remove(tag).is_some()
    }

    pub fn set_inbound_protocol(&self, tag: &str, protocol: Option<&str>) {
        let mut protocols = self
            .inbound_protocols
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match protocol {
            Some(protocol) if !tag.is_empty() => {
                protocols.insert(tag.to_owned(), protocol.to_owned());
            }
            _ => {
                protocols.remove(tag);
            }
        }
    }

    /// Xray's freedom `getDefaultFinalRule` blocks private addresses for its
    /// public proxy inbounds and leaves local ones (socks, http, tunnel)
    /// free. Only those local ones are opened here, so an untagged inbound or
    /// a protocol Xray does not list stays blocked.
    fn inbound_opens_private(&self, tag: &str) -> bool {
        let protocols = self
            .inbound_protocols
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        protocols.get(tag).is_some_and(|protocol| {
            matches!(
                protocol.to_ascii_lowercase().as_str(),
                "socks" | "http" | "mixed" | "dokodemo-door" | "dokodemo" | "tunnel"
            )
        })
    }

    /// Freedom's last check on the resolved address: the first matching
    /// `finalRules` entry wins, otherwise private addresses are blocked
    /// unless the inbound may reach them.
    pub fn final_action(
        &self,
        outbound: &str,
        network: Network,
        addr: SocketAddr,
        open_private: bool,
    ) -> Action {
        let ip = addr.ip();
        let final_rules = self
            .final_rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let outbounds = self
            .outbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        final_rules
            .get(outbound)
            .into_iter()
            .flatten()
            .find(|(_, rule)| {
                rule.matches_network(Some(network))
                    && rule.matches_port(Some(addr.port()))
                    && rule.matches_ip(Some(&ip))
            })
            .map_or(
                if !open_private && is_private(ip) {
                    Action::Block(BlockAction::Hold(DEFAULT_FINAL_BLOCK))
                } else {
                    outbounds
                        .get(outbound)
                        .cloned()
                        .unwrap_or_else(|| Action::Direct(FreedomStrategy::AsIs.into()))
                },
                |(action, _)| action.clone(),
            )
    }

    /// Whether any rule needs the first payload to detect the protocol.
    pub fn needs_sniff(&self) -> bool {
        self.sniff
    }

    pub async fn route(&self, query: &Query<'_>) -> Decision {
        let resolve_first = self.strategy == RoutingDomainStrategy::IpOnDemand;
        let mut resolved = None;
        if resolve_first {
            resolved = self.resolve(query).await;
        }

        let mut current_inbound = query.inbound.to_owned();
        for _ in 0..8 {
            let q = Query {
                inbound: &current_inbound,
                inbound_port: query.inbound_port,
                user: query.user,
                source: query.source,
                network: query.network,
                domain: query.domain,
                ip: query.ip,
                port: query.port,
                protocol: query.protocol,
                attributes: query.attributes,
                local_ip: query.local_ip,
                vless_route: query.vless_route,
                process_info: query.process_info,
            };
            let decision = self.route_once(&q, resolved).await;
            match decision.action {
                Action::Loopback(inbound_tag) => {
                    current_inbound = inbound_tag;
                }
                _ => {
                    // Loopback keeps the original inbound's protocol, as Xray's does.
                    return Decision {
                        open_private: self.inbound_opens_private(query.inbound),
                        ..decision
                    };
                }
            }
        }

        Decision {
            open_private: false,
            tag: "loopback".into(),
            action: Action::Block(BlockAction::Drop),
        }
    }

    async fn resolve(&self, query: &Query<'_>) -> Option<IpAddr> {
        let domain = query.domain?;
        tokio::net::lookup_host((domain, query.port))
            .await
            .ok()?
            .next()
            .map(|a| a.ip())
    }

    async fn route_once(&self, query: &Query<'_>, resolved: Option<IpAddr>) -> Decision {
        let matched = {
            let rules = self
                .rules
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.first_match(&rules, query, query.ip.or(resolved))
        };
        if let Some((target, webhook)) = matched {
            let decision = self.resolve_target(&target).await;
            if let Some(wh) = webhook {
                wh.fire(query, &decision.tag);
            }
            return decision;
        }
        if self.strategy == RoutingDomainStrategy::IpIfNonMatch && query.domain.is_some() {
            let ip = match resolved {
                Some(ip) => Some(ip),
                None => self.resolve(query).await,
            };
            if let Some(ip) = ip {
                let matched = {
                    let rules = self
                        .rules
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    self.first_match(&rules, query, Some(ip))
                };
                if let Some((target, webhook)) = matched {
                    let decision = self.resolve_target(&target).await;
                    if let Some(wh) = webhook {
                        wh.fire(query, &decision.tag);
                    }
                    return decision;
                }
            }
        }
        let default_tag = self
            .default_tag
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let outbounds = self
            .outbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.decision(&outbounds, &default_tag)
    }

    fn first_match<'a>(
        &'a self,
        rules: &'a [Rule],
        query: &Query<'_>,
        ip: Option<IpAddr>,
    ) -> Option<(RuleTarget, Option<Arc<WebhookNotifier>>)> {
        rules
            .iter()
            .find(|rule| rule.matches(query, ip))
            .map(|rule| (rule.target.clone(), rule.webhook.clone()))
    }

    async fn resolve_target(&self, target: &RuleTarget) -> Decision {
        let outbounds = self
            .outbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match target {
            RuleTarget::Outbound(tag) => self.decision(&outbounds, tag),
            RuleTarget::Balancer(balancer_tag) => {
                if let Some(balancer) = self.balancers.get(balancer_tag) {
                    let obs = self
                        .observatory
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some((tag, action)) = balancer.select(&outbounds, obs.as_deref()) {
                        return Decision {
                            open_private: false,
                            tag: tag.to_owned(),
                            action: action.clone(),
                        };
                    }
                }
                Decision {
                    open_private: false,
                    tag: format!("balancer:{balancer_tag}"),
                    action: Action::Block(BlockAction::Drop),
                }
            }
        }
    }

    fn decision(&self, outbounds: &HashMap<String, Action>, tag: &str) -> Decision {
        let action = if outbounds.is_empty() {
            Action::Direct(FreedomStrategy::AsIs.into())
        } else {
            outbounds
                .get(tag)
                .cloned()
                .unwrap_or(Action::Block(BlockAction::Drop))
        };
        Decision {
            open_private: false,
            tag: tag.to_owned(),
            action,
        }
    }
}

/// Xray's validateOutboundTransportSecurity: VLESS without encryption and
/// Trojan need TLS or REALITY unless the server is a private address.
fn require_transport_security(outbound: &Value, vless: bool) -> Result<(), String> {
    let security = outbound
        .get("streamSettings")
        .map(|s| str_field(s, "security"))
        .unwrap_or_default();
    if !matches!(security, "" | "none") {
        return Ok(());
    }
    let settings = outbound.get("settings").unwrap_or(&Value::Null);
    let server = array(settings, if vless { "vnext" } else { "servers" })
        .first()
        .unwrap_or(settings);
    if vless {
        let encryption = array(server, "users")
            .first()
            .map(|u| str_field(u, "encryption"))
            .unwrap_or_else(|| str_field(settings, "encryption"));
        if !matches!(encryption, "" | "none") {
            return Ok(());
        }
    }
    if is_private_server_address(str_field(server, "address")) {
        return Ok(());
    }
    Err(if vless {
        "vless without TLS or other encryption is prohibited unless the server address is a private IP or domain"
    } else {
        "trojan without TLS is prohibited unless the server address is a private IP or domain"
    }
    .into())
}

/// Xray's requiresTransportSecurity, negated: Go's IsPrivate, IsLoopback and
/// IsLinkLocalUnicast for IPs, its private domain list for names.
fn is_private_server_address(address: &str) -> bool {
    if address.is_empty() {
        return false;
    }
    if let Ok(ip) = address.trim_matches(['[', ']']).parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
            }
        };
    }
    let domain = address.trim_end_matches('.').to_ascii_lowercase();
    const PRIVATE: [&str; 9] = [
        "lan",
        "localdomain",
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "home.arpa",
        "internal",
    ];
    let dotless = !domain.contains('.')
        && (1..=63).contains(&domain.len())
        && domain.starts_with(|c: char| c.is_ascii_lowercase())
        && !domain.ends_with('-')
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    dotless
        || PRIVATE.iter().any(|p| {
            domain == *p
                || domain
                    .strip_suffix(p)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
}

pub fn parse_single_rule(raw: &Value, asset_dirs: &[PathBuf]) -> Result<Rule, String> {
    let Some(object) = raw.as_object() else {
        return Err("routing rule must be an object".into());
    };
    let mut rule = object.clone();
    let rule_tag = rule
        .remove("ruleTag")
        .and_then(|v| match v {
            Value::String(s) => Some(s),
            _ => None,
        })
        .unwrap_or_default();
    let target = match (rule.remove("outboundTag"), rule.remove("balancerTag")) {
        (Some(Value::String(tag)), _) => RuleTarget::Outbound(tag),
        (_, Some(Value::String(tag))) => RuleTarget::Balancer(tag),
        _ => return Err("routing rule needs outboundTag or balancerTag".into()),
    };
    let tag = match &target {
        RuleTarget::Outbound(t) => t.clone(),
        RuleTarget::Balancer(t) => format!("balancer:{t}"),
    };
    // Xray's conditions; a rule left only with fields it ignores fails there.
    const CONDITIONS: [&str; 17] = [
        "domain",
        "domains",
        "ip",
        "port",
        "network",
        "sourceIP",
        "source",
        "sourcePort",
        "user",
        "vlessRoute",
        "inboundTag",
        "protocol",
        "attrs",
        "localIP",
        "localPort",
        "process",
        "localOS",
    ];
    if !rule.keys().any(|k| CONDITIONS.contains(&k.as_str())) {
        return Err("this rule has no effective fields".into());
    }
    let users = take_strings(&mut rule, "user")
        .into_iter()
        .map(|u| match u.strip_prefix("regexp:") {
            Some(pattern) => Regex::new(pattern)
                .map(UserMatcher::Regex)
                .map_err(|e| format!("rule.user: {e}")),
            None => Ok(UserMatcher::Exact(u)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let protocols = take_strings(&mut rule, "protocol");
    let local_ports = take_port_ranges(&mut rule, "localPort")?;
    let attrs = take_attrs(&mut rule, "attrs");
    let vless_routes = take_vless_routes(&mut rule, "vlessRoute")?;
    let local_ip = rule.remove("localIP");
    let source = rule.remove("source").or_else(|| rule.remove("sourceIP"));
    let source_port = rule.remove("sourcePort");
    let process_list = match rule.remove("process") {
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    };
    let process = if !process_list.is_empty() {
        Some(crate::process::ProcessMatcher::new(&process_list))
    } else {
        None
    };
    let webhook = if let Some(wh) = rule.remove("webhook").and_then(|v| match v {
        Value::Object(map) => Some(map),
        _ => None,
    }) {
        let url = wh.get("url").and_then(Value::as_str).unwrap_or("");
        if !url.is_empty() {
            let deduplication = wh.get("deduplication").and_then(Value::as_u64).unwrap_or(0) as u32;
            let mut headers = HashMap::new();
            if let Some(h) = wh.get("headers").and_then(Value::as_object) {
                for (k, v) in h {
                    if let Some(vs) = v.as_str() {
                        headers.insert(k.clone(), vs.to_string());
                    }
                }
            }
            Some(Arc::new(WebhookNotifier::new(
                url.to_string(),
                headers,
                deduplication,
            )))
        } else {
            None
        }
    } else {
        None
    };
    for key in IGNORED_FIELDS {
        rule.remove(key);
    }
    let known = [
        "type",
        "inboundTag",
        "network",
        "port",
        "domain",
        "domains",
        "ip",
        "localOS",
    ];
    // Go's JSON decoding drops fields Xray does not know, so they are ignored.
    let unknown: Vec<String> = rule
        .keys()
        .filter(|k| !known.contains(&k.as_str()) && !SERVER_FIELDS.contains(&k.as_str()))
        .cloned()
        .collect();
    for key in unknown {
        log::warn(format!("routing rule field {key:?} is unknown, ignored"));
        rule.remove(&key);
    }
    // The parser rejects a rule without conditions; this one matches everything.
    if !rule.keys().any(|k| k != "type") {
        rule.insert("network".into(), json!("tcp,udp"));
    }
    rule.insert("outboundTag".into(), json!(STUB_TAG));
    let mut synth_rules = vec![Value::Object(rule)];
    let helper_source = (source.is_some() || source_port.is_some()).then(|| {
        let mut helper = json!({"type": "field", "outboundTag": STUB_TAG});
        if let Some(source) = source {
            helper["ip"] = source;
        }
        if let Some(port) = source_port {
            helper["port"] = port;
        }
        synth_rules.push(helper);
        synth_rules.len() - 1
    });
    let helper_local_ip = local_ip.map(|lip| {
        let mut helper = json!({"type": "field", "outboundTag": STUB_TAG});
        helper["ip"] = lip;
        synth_rules.push(helper);
        synth_rules.len() - 1
    });
    let synth = json!({
        "outbounds": [{"tag": STUB_TAG, "protocol": "freedom"}],
        "routing": {"rules": synth_rules}
    });
    let parsed = xray_config::parse_xray_json_with_geodata_dirs(&synth.to_string(), asset_dirs)
        .map_err(|e| {
            let messages: Vec<String> = e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
            format!("routing: {}", messages.join("; "))
        })?;
    let parsed_rules = parsed.config.routing.rules;
    Ok(Rule {
        target,
        tag,
        rule_tag,
        matcher: parsed_rules[0].clone(),
        source: helper_source.map(|i| parsed_rules[i].clone()),
        users,
        protocols,
        local_ports,
        attrs,
        vless_routes,
        local_ip: helper_local_ip.map(|i| parsed_rules[i].clone()),
        process,
        webhook,
    })
}

fn take_attrs(rule: &mut serde_json::Map<String, Value>, key: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    if let Some(val) = rule.remove(key) {
        match val {
            Value::Object(obj) => {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        attrs.insert(k, s.to_owned());
                    } else {
                        attrs.insert(k, v.to_string());
                    }
                }
            }
            Value::String(s) => {
                for part in s.split(',') {
                    if let Some((k, v)) = part.split_once(':') {
                        attrs.insert(k.trim().to_owned(), v.trim().to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    attrs
}

fn take_vless_routes(
    rule: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<(u32, u32)>, String> {
    let mut ranges = Vec::new();
    if let Some(val) = rule.remove(key) {
        match val {
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    ranges.push((u as u32, u as u32));
                }
            }
            Value::String(s) => {
                for part in s.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if let Some((from, to)) = part.split_once('-') {
                        let from: u32 = from
                            .trim()
                            .parse()
                            .map_err(|e| format!("{key} range {part:?}: {e}"))?;
                        let to: u32 = to
                            .trim()
                            .parse()
                            .map_err(|e| format!("{key} range {part:?}: {e}"))?;
                        ranges.push((from, to));
                    } else {
                        let single: u32 = part
                            .parse()
                            .map_err(|e| format!("{key} value {part:?}: {e}"))?;
                        ranges.push((single, single));
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    match item {
                        Value::Number(n) => {
                            if let Some(u) = n.as_u64() {
                                ranges.push((u as u32, u as u32));
                            }
                        }
                        Value::String(s) => {
                            let single: u32 =
                                s.parse().map_err(|e| format!("{key} value {s:?}: {e}"))?;
                            ranges.push((single, single));
                        }
                        _ => return Err(format!("{key} array item must be number or string")),
                    }
                }
            }
            _ => return Err(format!("{key} must be a number, string or array")),
        }
    }
    Ok(ranges)
}

impl Rule {
    fn matches(&self, q: &Query<'_>, ip: Option<IpAddr>) -> bool {
        self.matcher.matches_target(
            Some(q.inbound),
            q.domain,
            ip.as_ref(),
            Some(q.network),
            Some(q.port),
        ) && self.source.as_ref().is_none_or(|s| {
            s.matches_ip(Some(&q.source.ip())) && s.matches_port(Some(q.source.port()))
        }) && (self.users.is_empty() || self.users.iter().any(|u| u.matches(q.user)))
            && (self.protocols.is_empty()
                || q.protocol
                    .is_some_and(|p| self.protocols.iter().any(|x| x == p)))
            && (self.local_ports.is_empty()
                || self
                    .local_ports
                    .iter()
                    .any(|(from, to)| q.inbound_port >= *from && q.inbound_port <= *to))
            && (self.attrs.is_empty()
                || self
                    .attrs
                    .iter()
                    .all(|(k, v)| q.attributes.and_then(|a| a.get(k)) == Some(v)))
            && (self.vless_routes.is_empty()
                || q.vless_route.is_some_and(|r| {
                    self.vless_routes
                        .iter()
                        .any(|(from, to)| r >= *from && r <= *to)
                }))
            && self
                .local_ip
                .as_ref()
                .is_none_or(|lip_rule| q.local_ip.is_some_and(|ip| lip_rule.matches_ip(Some(&ip))))
            && self.process.as_ref().is_none_or(|matcher| {
                let info = q.get_process_info();
                info.as_ref()
                    .is_some_and(|p| matcher.matches(p.pid, &p.name, &p.abs_path))
            })
    }
}

impl UserMatcher {
    fn matches(&self, user: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == user,
            Self::Regex(regex) => regex.is_match(user),
        }
    }
}

/// Guesses the application protocol from the first payload, like Xray's
/// sniffers for routing `protocol` rules.
pub fn sniff(data: &[u8], network: Network) -> Option<&'static str> {
    match network {
        Network::Tcp => {
            if data.len() >= 20 && data[0] == 19 && &data[1..20] == b"BitTorrent protocol" {
                Some("bittorrent")
            } else if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01 {
                Some("tls")
            } else if [
                "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ",
                "TRACE ",
            ]
            .iter()
            .any(|m| data.starts_with(m.as_bytes()))
            {
                Some("http")
            } else {
                None
            }
        }
        Network::Udp => {
            let is_utp =
                data.len() >= 20 && data[0] & 0x0f == 1 && data[0] >> 4 <= 4 && data[1] <= 2;
            let is_dht = data.starts_with(b"d1:") && data.windows(5).any(|w| w == b"1:y1:");
            if is_utp || is_dht {
                Some("bittorrent")
            } else if data.len() > 5 && data[0] & 0xc0 == 0xc0 && data[1..5] == [0, 0, 0, 1] {
                Some("quic")
            } else {
                None
            }
        }
    }
}

/// Extracts the SNI (Server Name Indication) domain from a TLS ClientHello packet.
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 44 || data[0] != 0x16 || data.get(5) != Some(&0x01) {
        return None;
    }
    let session_id_len = *data.get(43)? as usize;
    let mut pos = 44 + session_id_len;
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > data.len() {
        return None;
    }
    let compression_methods_len = *data.get(pos)? as usize;
    pos += 1 + compression_methods_len;
    if pos + 2 > data.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext_total_len).min(data.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0 {
            if pos + 2 > end {
                return None;
            }
            let list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let mut list_pos = pos + 2;
            let list_end = (list_pos + list_len).min(end);
            while list_pos + 3 <= list_end {
                let name_type = data[list_pos];
                let name_len =
                    u16::from_be_bytes([data[list_pos + 1], data[list_pos + 2]]) as usize;
                list_pos += 3;
                if name_type == 0 && list_pos + name_len <= list_end {
                    let name_bytes = &data[list_pos..list_pos + name_len];
                    return std::str::from_utf8(name_bytes)
                        .ok()
                        .map(|s| s.to_ascii_lowercase());
                }
                list_pos += name_len;
            }
        }
        pos += ext_len;
    }
    None
}

/// Extracts the Host header domain from an HTTP request.
pub fn sniff_http_host(data: &[u8]) -> Option<String> {
    for raw in data.split(|&b| b == b'\n') {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.is_empty() {
            break;
        }
        let line = String::from_utf8_lossy(raw);
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let host = v.trim().split(':').next()?.trim();
                if !host.is_empty() {
                    return Some(host.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

fn take_port_ranges(
    rule: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<(u16, u16)>, String> {
    let mut ranges = Vec::new();
    match rule.remove(key) {
        Some(Value::Number(n)) => {
            let p = n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| format!("{key}: invalid port number {n}"))?;
            ranges.push((p, p));
        }
        Some(Value::String(s)) => {
            for part in s.split(',') {
                let part = part.trim();
                if !part.is_empty() {
                    ranges.push(parse_port_range(part).map_err(|e| format!("{key}: {e}"))?);
                }
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::Number(n) => {
                        let p = n
                            .as_u64()
                            .and_then(|v| u16::try_from(v).ok())
                            .ok_or_else(|| format!("{key}: invalid port number {n}"))?;
                        ranges.push((p, p));
                    }
                    Value::String(s) => {
                        for part in s.split(',') {
                            let part = part.trim();
                            if !part.is_empty() {
                                ranges.push(
                                    parse_port_range(part).map_err(|e| format!("{key}: {e}"))?,
                                );
                            }
                        }
                    }
                    other => return Err(format!("{key}: unexpected item {other:?}")),
                }
            }
        }
        Some(other) => return Err(format!("{key}: unexpected value {other:?}")),
        None => {}
    }
    Ok(ranges)
}

fn parse_port_range(part: &str) -> Result<(u16, u16), String> {
    let part = part.trim();
    if let Some((start, end)) = part.split_once('-') {
        let s = start
            .trim()
            .parse::<u16>()
            .map_err(|e| format!("invalid port {start}: {e}"))?;
        let e = end
            .trim()
            .parse::<u16>()
            .map_err(|e| format!("invalid port {end}: {e}"))?;
        if s > e {
            return Err(format!("port range start {s} exceeds end {e}"));
        }
        Ok((s, e))
    } else {
        let p = part
            .parse::<u16>()
            .map_err(|e| format!("invalid port {part}: {e}"))?;
        Ok((p, p))
    }
}

/// Xray accepts these fields as an array or a comma-separated string.
fn take_strings(rule: &mut serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    match rule.remove(key) {
        Some(Value::String(s)) => s
            .split(',')
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
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

    fn query<'a>(domain: Option<&'a str>, ip: Option<&str>, port: u16) -> Query<'a> {
        Query {
            inbound: "in",
            inbound_port: 443,
            user: "alice",
            source: "203.0.113.5:40000".parse().unwrap(),
            network: Network::Tcp,
            domain,
            ip: ip.map(|i| i.parse().unwrap()),
            port,
            protocol: None,
            attributes: None,
            local_ip: None,
            vless_route: None,
            process_info: None,
        }
    }

    fn router(config: Value) -> Router {
        Router::build(&config, &[]).unwrap()
    }

    #[tokio::test]
    async fn panel_default_rules() {
        let r = router(json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}],
            "routing": {"domainStrategy": "AsIs", "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "outboundTag": "blocked", "ip": ["10.0.0.0/8"]},
                {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}
            ]}
        }));
        assert!(r.needs_sniff());
        assert_eq!(
            r.route(&query(None, Some("10.1.1.1"), 80)).await.action,
            Action::Block(BlockAction::Drop)
        );
        assert_eq!(
            r.route(&query(Some("example.com"), None, 443)).await,
            Decision {
                open_private: false,
                tag: "direct".into(),
                action: Action::Direct(FreedomStrategy::AsIs.into())
            }
        );
        let mut bt = query(None, Some("1.1.1.1"), 6881);
        bt.protocol = Some("bittorrent");
        assert_eq!(r.route(&bt).await.tag, "blocked");
    }

    #[tokio::test]
    async fn server_side_fields_and_unsupported_outbounds() {
        let r = router(json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "warp", "protocol": "unsupported-proto"}],
            "routing": {"rules": [
                {"type": "field", "outboundTag": "warp", "domain": ["domain:openai.com"]},
                {"type": "field", "outboundTag": "warp", "user": ["regexp:^bob"]},
                {"type": "field", "outboundTag": "warp", "source": ["198.51.100.0/24"], "sourcePort": "1-1000"}
            ]}
        }));
        let blocked = r.route(&query(Some("chat.openai.com"), None, 443)).await;
        assert_eq!(
            blocked,
            Decision {
                open_private: false,
                tag: "warp".into(),
                action: Action::Block(BlockAction::Drop)
            }
        );
        assert_eq!(
            r.route(&query(Some("example.com"), None, 443)).await.action,
            Action::Direct(FreedomStrategy::AsIs.into())
        );
        let mut bob = query(Some("example.com"), None, 443);
        bob.user = "bobby";
        assert_eq!(r.route(&bob).await.tag, "warp");
        let mut src = query(Some("example.com"), None, 443);
        src.source = "198.51.100.7:999".parse().unwrap();
        assert_eq!(r.route(&src).await.tag, "warp");
        src.source = "198.51.100.7:5000".parse().unwrap();
        assert_eq!(r.route(&src).await.tag, "direct");
    }

    #[test]
    fn plaintext_outbounds_need_a_private_server() {
        for (address, private) in [
            ("10.0.0.1", true),
            ("127.0.0.1", true),
            ("fe80::1", true),
            ("203.0.113.42", false),
            ("example.com", false),
            ("router.lan", true),
            ("nas", true),
            ("", false),
        ] {
            assert_eq!(is_private_server_address(address), private, "{address}");
        }
        let plain =
            json!({"protocol": "trojan", "settings": {"servers": [{"address": "203.0.113.42"}]}});
        assert!(require_transport_security(&plain, false).is_err());
        let tls = json!({"settings": {"servers": [{"address": "203.0.113.42"}]},
                         "streamSettings": {"security": "tls"}});
        assert!(require_transport_security(&tls, false).is_ok());
    }

    #[test]
    fn private_addresses_open_only_to_local_inbounds() {
        let r = router(json!({
            "inbounds": [
                {"tag": "s", "protocol": "socks"},
                {"tag": "d", "protocol": "dokodemo-door"},
                {"tag": "v", "protocol": "vless"},
                {"tag": "ss", "protocol": "shadowsocks"}
            ],
            "outbounds": [{"tag": "plain", "protocol": "freedom"}]
        }));
        assert!(r.inbound_opens_private("s"));
        assert!(r.inbound_opens_private("d"));
        assert!(!r.inbound_opens_private("v"));
        assert!(!r.inbound_opens_private("ss"));
        assert!(!r.inbound_opens_private(""));
        r.set_inbound_protocol("api-added", Some("http"));
        assert!(r.inbound_opens_private("api-added"));
        r.set_inbound_protocol("api-added", None);
        assert!(!r.inbound_opens_private("api-added"));
        let at = "192.168.1.1:80".parse::<SocketAddr>().unwrap();
        assert!(matches!(
            r.final_action("plain", Network::Tcp, at, false),
            Action::Block(_)
        ));
        assert!(matches!(
            r.final_action("plain", Network::Tcp, at, true),
            Action::Direct(_)
        ));
    }

    #[test]
    fn freedom_final_rules() {
        let r = router(json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "ip": ["127.0.0.1/32"], "port": "8080"},
                {"action": "block", "ip": ["1.1.1.1"]}
            ]}}, {"tag": "plain", "protocol": "freedom"}]
        }));
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            r.final_action("direct", Network::Tcp, at("127.0.0.1:8080"), false),
            Action::Direct(FreedomStrategy::AsIs.into())
        );
        assert_eq!(
            r.final_action("direct", Network::Tcp, at("127.0.0.1:22"), false),
            Action::Block(BlockAction::Hold(DEFAULT_FINAL_BLOCK))
        );
        assert_eq!(
            r.final_action("direct", Network::Udp, at("1.1.1.1:53"), false),
            Action::Block(BlockAction::Hold(FinalBlock {
                delay: (30, 90),
                log: FinalLog::Info
            }))
        );
        assert_eq!(
            r.final_action("plain", Network::Tcp, at("1.1.1.1:53"), false),
            Action::Direct(FreedomStrategy::AsIs.into())
        );
        assert_eq!(
            r.final_action("plain", Network::Tcp, at("192.168.1.1:80"), false),
            Action::Block(BlockAction::Hold(DEFAULT_FINAL_BLOCK))
        );
    }

    #[tokio::test]
    async fn blackhole_http_and_local_port_matching() {
        let r = router(json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "forbidden", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
                {"tag": "blocked", "protocol": "blackhole"}
            ],
            "routing": {"rules": [
                {"type": "field", "outboundTag": "forbidden", "localPort": "8443,9000-9100"},
                {"type": "field", "outboundTag": "blocked", "localPort": 1234}
            ]}
        }));

        let mut q = query(Some("example.com"), None, 80);
        q.inbound_port = 8443;
        assert_eq!(
            r.route(&q).await,
            Decision {
                open_private: false,
                tag: "forbidden".into(),
                action: Action::Block(BlockAction::Http403)
            }
        );

        q.inbound_port = 9050;
        assert_eq!(
            r.route(&q).await,
            Decision {
                open_private: false,
                tag: "forbidden".into(),
                action: Action::Block(BlockAction::Http403)
            }
        );

        q.inbound_port = 1234;
        assert_eq!(
            r.route(&q).await,
            Decision {
                open_private: false,
                tag: "blocked".into(),
                action: Action::Block(BlockAction::Drop)
            }
        );

        q.inbound_port = 443;
        assert_eq!(
            r.route(&q).await,
            Decision {
                open_private: false,
                tag: "direct".into(),
                action: Action::Direct(FreedomStrategy::AsIs.into())
            }
        );
    }

    #[tokio::test]
    async fn freedom_domain_strategy_parsing() {
        let r = router(json!({
            "outbounds": [
                {"tag": "v4only", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
                {"tag": "v6only", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv6"}},
                {"tag": "default", "protocol": "freedom"}
            ]
        }));
        assert_eq!(
            r.route(&query(Some("example.com"), None, 80)).await,
            Decision {
                open_private: false,
                tag: "v4only".into(),
                action: Action::Direct(FreedomStrategy::UseIPv4.into())
            }
        );
        assert!(Router::build(
            &json!({"outbounds": [{"tag": "bad", "protocol": "freedom", "settings": {"domainStrategy": "invalid"}}]}),
            &[]
        )
        .is_err());
        let err = match Router::build(
            &json!({"outbounds": [{
                "tag": "bad",
                "protocol": "freedom",
                "streamSettings": {
                    "sockopt": {"addressPortStrategy": "srvPortOnly"}
                }
            }]}),
            &[],
        ) {
            Err(e) => e,
            Ok(_) => panic!("expected freedom to reject addressPortStrategy"),
        };
        assert_eq!(
            err,
            "freedom outbound does not support \"sockopt.addressPortStrategy\""
        );
    }

    #[test]
    fn rejects_unknown_rule_fields() {
        let config = json!({"routing": {"rules": [{"type": "field", "outboundTag": "x", "unknownField": {"a": "b"}}]}});
        assert!(Router::build(&config, &[]).is_err());
    }

    #[test]
    fn sniffs_protocols() {
        let mut bt = vec![19u8];
        bt.extend_from_slice(b"BitTorrent protocol");
        assert_eq!(sniff(&bt, Network::Tcp), Some("bittorrent"));
        assert_eq!(
            sniff(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01], Network::Tcp),
            Some("tls")
        );
        assert_eq!(sniff(b"GET / HTTP/1.1\r\n", Network::Tcp), Some("http"));
        assert_eq!(
            sniff(
                b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe",
                Network::Udp
            ),
            Some("bittorrent")
        );
    }

    #[test]
    fn sniffs_domain_from_http_and_tls() {
        let http = b"GET /path HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(sniff_http_host(http), Some("example.com".to_owned()));
        let binary_body = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n\xff\xfe";
        assert_eq!(sniff_http_host(binary_body), Some("example.com".to_owned()));
        assert_eq!(
            sniff_http_host(b"GET / HTTP/1.1\r\n\r\nHost: late.com\r\n"),
            None
        );

        // Synthetic minimal TLS 1.2 ClientHello with SNI "test.domain.org"
        let sni_name = b"test.domain.org";
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0u16.to_be_bytes()); // Ext type = 0 (SNI)
        let list_len = 3 + sni_name.len() as u16;
        sni_ext.extend_from_slice(&(list_len + 2).to_be_bytes()); // Ext len
        sni_ext.extend_from_slice(&list_len.to_be_bytes()); // Server Name List len
        sni_ext.push(0); // Name type = host_name
        sni_ext.extend_from_slice(&(sni_name.len() as u16).to_be_bytes()); // Name len
        sni_ext.extend_from_slice(sni_name);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]); // TLS Record header
        hello.push(0x01); // ClientHello
        hello.extend_from_slice(&[0x00, 0x00, 0x00]); // Handshake len (dummy)
        hello.extend_from_slice(&[0x03, 0x03]); // Client version
        hello.extend_from_slice(&[0u8; 32]); // Random
        hello.push(0x00); // Session ID len = 0
        hello.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len = 2
        hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.push(0x01); // Compression methods len = 1
        hello.push(0x00); // null compression
        hello.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); // Ext total len
        hello.extend_from_slice(&sni_ext);

        let rec_len = (hello.len() - 5) as u16;
        hello[3..5].copy_from_slice(&rec_len.to_be_bytes());
        hello[6..9].copy_from_slice(&(rec_len as u32 - 4).to_be_bytes()[1..4]);

        assert_eq!(sniff_tls_sni(&hello), Some("test.domain.org".to_owned()));
    }

    #[tokio::test]
    async fn balancers_selection_and_fallback() {
        let r = router(json!({
            "outbounds": [
                {"tag": "node-1", "protocol": "freedom"},
                {"tag": "node-2", "protocol": "freedom"},
                {"tag": "fallback-node", "protocol": "freedom"}
            ],
            "routing": {
                "balancers": [
                    {
                        "tag": "round-robin",
                        "selector": ["node-"],
                        "strategy": "roundRobin"
                    },
                    {
                        "tag": "fallback-test",
                        "selector": ["non-existing-"],
                        "strategy": "random",
                        "fallbackTag": "fallback-node"
                    }
                ],
                "rules": [
                    {"type": "field", "port": 80, "balancerTag": "round-robin"},
                    {"type": "field", "port": 443, "balancerTag": "fallback-test"}
                ]
            }
        }));

        // Round robin should cycle node-1 and node-2
        let q80 = query(Some("example.com"), None, 80);
        let first = r.route(&q80).await;
        let second = r.route(&q80).await;
        let third = r.route(&q80).await;
        assert_ne!(first.tag, second.tag);
        assert_eq!(first.tag, third.tag);

        // Fallback test should pick fallback-node
        let q443 = query(Some("example.com"), None, 443);
        let fb = r.route(&q443).await;
        assert_eq!(fb.tag, "fallback-node");
    }

    #[test]
    fn parses_leastping_and_leastload_balancer_strategies() {
        let val = json!({
            "tag": "b1",
            "selector": ["node-"],
            "strategy": "leastPing"
        });
        let b1 = Balancer::parse(0, &val).expect("leastPing must parse");
        assert_eq!(b1.strategy, BalancerStrategy::LeastPing);

        let val_obj = json!({
            "tag": "b2",
            "selector": ["node-"],
            "strategy": {
                "type": "leastLoad",
                "settings": {
                    "expected": 2,
                    "maxRTT": "500ms",
                    "tolerance": 0.2,
                    "baselines": ["100ms", "200ms"],
                    "costs": [
                        {"match": "node-1", "value": 1.5}
                    ]
                }
            }
        });
        let b2 = Balancer::parse(1, &val_obj).expect("leastLoad must parse");
        match b2.strategy {
            BalancerStrategy::LeastLoad(cfg) => {
                assert_eq!(cfg.expected, 2);
                assert_eq!(cfg.max_rtt, Duration::from_millis(500));
                assert_eq!(cfg.tolerance, 0.2);
                assert_eq!(cfg.baselines.len(), 2);
                assert_eq!(cfg.costs.len(), 1);
            }
            _ => panic!("expected LeastLoad"),
        }
    }

    #[tokio::test]
    async fn loopback_rerouting() {
        let r = router(json!({
            "inbounds": [
                {"tag": "client-in", "protocol": "vless"},
                {"tag": "loop-in", "protocol": "socks"}
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "to-loop", "protocol": "loopback", "settings": {"inboundTag": "loop-in"}},
                {"tag": "blocked", "protocol": "blackhole"}
            ],
            "routing": {
                "rules": [
                    {"type": "field", "inboundTag": ["client-in"], "port": 80, "outboundTag": "to-loop"},
                    {"type": "field", "inboundTag": ["loop-in"], "port": 80, "outboundTag": "direct"},
                    {"type": "field", "inboundTag": ["client-in"], "port": 443, "outboundTag": "blocked"}
                ]
            }
        }));

        let mut q = query(Some("example.com"), None, 80);
        q.inbound = "client-in";
        let decision = r.route(&q).await;
        assert_eq!(decision.tag, "direct");
        // A VLESS client looped into a socks inbound keeps VLESS's block.
        assert!(!decision.open_private);

        q.port = 443;
        let decision = r.route(&q).await;
        assert_eq!(decision.tag, "blocked");
    }

    #[test]
    fn freedom_fragment_parsing() {
        let valid = json!({
            "packets": "tlshello",
            "length": "100-200",
            "interval": "10-20",
            "maxSplit": 4
        });
        let config = parse_fragment(&valid).unwrap();
        assert_eq!(config.packets, FreedomFragmentPackets::TlsHello);
        assert_eq!(config.length, (100, 200));
        assert_eq!(config.interval, (10, 20));
        assert_eq!(config.max_split, (4, 4));

        let invalid_packets = json!({
            "packets": "invalid",
            "length": "100-200"
        });
        assert!(parse_fragment(&invalid_packets).is_err());
    }

    #[test]
    fn freedom_redirect_parsing() {
        let r = parse_redirect("127.0.0.1:8080").unwrap().unwrap();
        assert_eq!(r.host, Some(Host::Ip("127.0.0.1".parse().unwrap())));
        assert_eq!(r.port, 8080);

        let r_v6 = parse_redirect("[::1]:9090").unwrap().unwrap();
        assert_eq!(r_v6.host, Some(Host::Ip("::1".parse().unwrap())));
        assert_eq!(r_v6.port, 9090);

        let r_domain = parse_redirect("proxy.local:1080").unwrap().unwrap();
        assert_eq!(r_domain.host, Some(Host::Domain("proxy.local".to_owned())));
        assert_eq!(r_domain.port, 1080);

        let r_empty_host = parse_redirect(":8080").unwrap().unwrap();
        assert_eq!(r_empty_host.host, None);
        assert_eq!(r_empty_host.port, 8080);
    }

    #[tokio::test]
    async fn extended_routing_attrs_vless_route_local_ip() {
        let r = router(json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "attr-out", "protocol": "freedom"},
                {"tag": "vless-out", "protocol": "freedom"},
                {"tag": "local-out", "protocol": "freedom"}
            ],
            "routing": {
                "domainMatcher": "hybrid",
                "rules": [
                    {
                        "type": "field",
                        "ruleTag": "rule-attr",
                        "domainMatcher": "linear",
                        "outboundTag": "attr-out",
                        "attrs": {"region": "us", "tier": "gold"}
                    },
                    {
                        "type": "field",
                        "ruleTag": "rule-vless",
                        "outboundTag": "vless-out",
                        "vlessRoute": "1000-2000, 3000"
                    },
                    {
                        "type": "field",
                        "ruleTag": "rule-local",
                        "outboundTag": "local-out",
                        "localIP": ["127.0.0.1", "10.0.0.1"]
                    }
                ]
            }
        }));

        // Test attrs matching
        let mut q_attr = query(Some("example.com"), None, 443);
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("region".to_string(), "us".to_string());
        attrs.insert("tier".to_string(), "gold".to_string());
        q_attr.attributes = Some(&attrs);
        assert_eq!(r.route(&q_attr).await.tag, "attr-out");

        let mut attrs_mismatch = std::collections::HashMap::new();
        attrs_mismatch.insert("region".to_string(), "eu".to_string());
        q_attr.attributes = Some(&attrs_mismatch);
        assert_eq!(r.route(&q_attr).await.tag, "direct");

        // Test vlessRoute matching
        let mut q_vless = query(Some("example.com"), None, 443);
        q_vless.vless_route = Some(1500);
        assert_eq!(r.route(&q_vless).await.tag, "vless-out");
        q_vless.vless_route = Some(3000);
        assert_eq!(r.route(&q_vless).await.tag, "vless-out");
        q_vless.vless_route = Some(2500);
        assert_eq!(r.route(&q_vless).await.tag, "direct");

        // Test localIP matching
        let mut q_local = query(Some("example.com"), None, 443);
        q_local.local_ip = Some("127.0.0.1".parse().unwrap());
        assert_eq!(r.route(&q_local).await.tag, "local-out");
        q_local.local_ip = Some("192.168.1.1".parse().unwrap());
        assert_eq!(r.route(&q_local).await.tag, "direct");
    }

    #[tokio::test]
    async fn dynamic_rules_manipulation() {
        let r = router(json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "proxy", "protocol": "freedom"}
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "ruleTag": "initial-rule",
                        "outboundTag": "proxy",
                        "domain": ["example.com"]
                    }
                ]
            }
        }));

        let q = query(Some("example.com"), None, 80);
        assert_eq!(r.route(&q).await.tag, "proxy");

        let rules = r.list_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], ("proxy".to_string(), "initial-rule".to_string()));

        // Remove rule
        assert_eq!(r.remove_rule(""), 0);
        assert_eq!(r.list_rules().len(), 1);
        let removed = r.remove_rule("initial-rule");
        assert_eq!(removed, 1);
        assert_eq!(r.route(&q).await.tag, "direct");
        assert_eq!(r.list_rules().len(), 0);

        // Add rule dynamically
        let new_rule_json = json!({
            "type": "field",
            "ruleTag": "added-rule",
            "outboundTag": "proxy",
            "domain": ["example.com"]
        });
        let parsed = r.parse_rule(&new_rule_json).unwrap();
        r.add_rule(parsed, false);

        assert_eq!(r.route(&q).await.tag, "proxy");
        assert_eq!(r.list_rules().len(), 1);
    }
}
