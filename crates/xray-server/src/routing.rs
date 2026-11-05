//! Xray routing for the server: rules pick an outbound tag, and only freedom
//! (direct) and blackhole outbounds are implemented. Traffic routed to any
//! other outbound is blocked so it never silently leaves via the server IP.
//!
//! Domain/IP/port/network/inboundTag matching, including geoip and geosite,
//! reuses xray-config's parser. Fields that parser does not know (user,
//! source, sourcePort, protocol) are matched here.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use regex::Regex;
use serde_json::{json, Value};
use xray_config::{Network, RoutingDomainStrategy, RoutingRule};

use crate::log;
use crate::socks::SocksOutbound;
use crate::vless::is_private;
use crate::wg::WgOutbound;

const STUB_TAG: &str = "rule";
const SERVER_FIELDS: [&str; 4] = ["user", "source", "sourcePort", "protocol"];
const IGNORED_FIELDS: [&str; 1] = ["ruleTag"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreedomStrategy {
    #[default]
    AsIs,
    UseIP,
    UseIPv4,
    UseIPv6,
}

#[derive(Debug, Clone)]
pub enum Action {
    Direct(FreedomStrategy),
    Block,
    Wireguard(Arc<WgOutbound>),
    Socks(Arc<SocksOutbound>),
}

impl PartialEq for Action {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct(a), Self::Direct(b)) => a == b,
            (Self::Wireguard(a), Self::Wireguard(b)) => Arc::ptr_eq(a, b),
            (Self::Socks(a), Self::Socks(b)) => Arc::ptr_eq(a, b),
            (a, b) => std::mem::discriminant(a) == std::mem::discriminant(b),
        }
    }
}

impl Eq for Action {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub tag: String,
    pub action: Action,
}

pub struct Query<'a> {
    pub inbound: &'a str,
    pub user: &'a str,
    pub source: SocketAddr,
    pub network: Network,
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: Option<&'static str>,
}

pub struct Router {
    rules: Vec<Rule>,
    strategy: RoutingDomainStrategy,
    outbounds: HashMap<String, Action>,
    default_tag: String,
    sniff: bool,
    // freedom `finalRules`, checked against the resolved address.
    final_rules: HashMap<String, Vec<(Action, RoutingRule)>>,
}

struct Rule {
    tag: String,
    matcher: RoutingRule,
    source: Option<RoutingRule>,
    users: Vec<UserMatcher>,
    protocols: Vec<String>,
}

enum UserMatcher {
    Exact(String),
    Regex(Regex),
}

impl Router {
    pub fn build(root: &Value, asset_dirs: &[PathBuf]) -> Result<Self, String> {
        let mut outbounds = HashMap::new();
        let mut default_tag = None;
        let mut synth_rules = Vec::new();
        let mut pending_final = Vec::new();
        for outbound in array(root, "outbounds") {
            let tag = str_field(outbound, "tag").to_owned();
            let protocol = str_field(outbound, "protocol");
            let action = match protocol {
                "freedom" => {
                    let settings = outbound.get("settings").unwrap_or(&Value::Null);
                    let domain_strategy = match str_field(settings, "domainStrategy") {
                        "" | "AsIs" => FreedomStrategy::AsIs,
                        "UseIP" => FreedomStrategy::UseIP,
                        "UseIPv4" | "UseIP4" => FreedomStrategy::UseIPv4,
                        "UseIPv6" | "UseIP6" => FreedomStrategy::UseIPv6,
                        other => {
                            return Err(format!(
                                "outbound {tag:?}: unknown domainStrategy {other:?}"
                            ))
                        }
                    };
                    for (index, raw) in array(settings, "finalRules").iter().enumerate() {
                        let action = match str_field(raw, "action") {
                            "allow" => Action::Direct(domain_strategy),
                            "block" => Action::Block,
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
                    Action::Direct(domain_strategy)
                }
                "blackhole" => Action::Block,
                "wireguard" => Action::Wireguard(Arc::new(WgOutbound::parse(
                    &tag,
                    outbound.get("settings").unwrap_or(&Value::Null),
                )?)),
                "socks" => Action::Socks(Arc::new(SocksOutbound::parse(
                    &tag,
                    outbound.get("settings").unwrap_or(&Value::Null),
                )?)),
                other => {
                    log::warn(format!("outbound {tag:?} ({other}) is not supported yet; traffic routed to it will be blocked"));
                    Action::Block
                }
            };
            default_tag.get_or_insert_with(|| tag.clone());
            outbounds.insert(tag, action);
        }

        let routing = root.get("routing").cloned().unwrap_or(Value::Null);
        let mut pending = Vec::new();
        for (index, raw) in array(&routing, "rules").iter().enumerate() {
            let Some(object) = raw.as_object() else {
                return Err(format!("routing.rules[{index}] must be an object"));
            };
            let mut rule = object.clone();
            let tag = match (rule.remove("outboundTag"), rule.remove("balancerTag")) {
                (Some(Value::String(tag)), _) => tag,
                (_, Some(Value::String(tag))) => {
                    log::warn(format!("balancer {tag:?} is not supported yet; traffic routed to it will be blocked"));
                    let tag = format!("balancer:{tag}");
                    outbounds.insert(tag.clone(), Action::Block);
                    tag
                }
                _ => {
                    return Err(format!(
                        "routing.rules[{index}] needs outboundTag or balancerTag"
                    ))
                }
            };
            let users = take_strings(&mut rule, "user")
                .into_iter()
                .map(|u| match u.strip_prefix("regexp:") {
                    Some(pattern) => Regex::new(pattern)
                        .map(UserMatcher::Regex)
                        .map_err(|e| format!("routing.rules[{index}].user: {e}")),
                    None => Ok(UserMatcher::Exact(u)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let protocols = take_strings(&mut rule, "protocol");
            let source = rule.remove("source").or_else(|| rule.remove("sourceIP"));
            let source_port = rule.remove("sourcePort");
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
            if let Some(unknown) = rule
                .keys()
                .find(|k| !known.contains(&k.as_str()) && !SERVER_FIELDS.contains(&k.as_str()))
            {
                return Err(format!(
                    "routing.rules[{index}]: field {unknown:?} is not supported yet"
                ));
            }
            // The parser rejects a rule without conditions; this one matches everything.
            if !rule.keys().any(|k| k != "type") {
                rule.insert("network".into(), json!("tcp,udp"));
            }
            rule.insert("outboundTag".into(), json!(STUB_TAG));
            let main = synth_rules.len();
            synth_rules.push(Value::Object(rule));
            let helper = (source.is_some() || source_port.is_some()).then(|| {
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
            pending.push((tag, main, helper, users, protocols));
        }

        let expected_rules = synth_rules.len();
        let mut synth_routing = json!({"rules": synth_rules});
        if let Some(strategy) = routing.get("domainStrategy") {
            synth_routing["domainStrategy"] = strategy.clone();
        }
        let synth = json!({"outbounds": [{"tag": STUB_TAG, "protocol": "freedom"}], "routing": synth_routing});
        let parsed = xray_config::parse_xray_json_with_geodata_dirs(&synth.to_string(), asset_dirs)
            .map_err(|e| {
                let messages: Vec<String> =
                    e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
                format!("routing: {}", messages.join("; "))
            })?;
        let parsed_rules = parsed.config.routing.rules;
        if parsed_rules.len() != expected_rules {
            return Err("routing: parser returned an unexpected number of rules".into());
        }

        let mut final_rules: HashMap<String, Vec<(Action, RoutingRule)>> = HashMap::new();
        for (tag, action, index) in pending_final {
            final_rules
                .entry(tag)
                .or_default()
                .push((action, parsed_rules[index].clone()));
        }

        let mut rules = Vec::with_capacity(pending.len());
        let mut sniff = false;
        for (tag, main, helper, users, protocols) in pending {
            if !outbounds.contains_key(&tag) {
                // 3x-ui routes its API inbound to the "api" tag, which is not an outbound.
                log::debug(format!(
                    "routing: outbound {tag:?} is not defined; matching traffic will be blocked"
                ));
                outbounds.insert(tag.clone(), Action::Block);
            }
            sniff |= !protocols.is_empty();
            rules.push(Rule {
                tag,
                matcher: parsed_rules[main].clone(),
                source: helper.map(|i| parsed_rules[i].clone()),
                users,
                protocols,
            });
        }

        Ok(Self {
            rules,
            strategy: parsed.config.routing.domain_strategy,
            outbounds,
            default_tag: default_tag.unwrap_or_default(),
            sniff,
            final_rules,
        })
    }

    /// Freedom's last check on the resolved address: the first matching
    /// `finalRules` entry wins, otherwise private addresses are blocked, as
    /// Xray does for VLESS inbounds.
    pub fn final_action(&self, outbound: &str, network: Network, addr: SocketAddr) -> Action {
        let ip = addr.ip();
        let rules = self
            .final_rules
            .get(outbound)
            .map_or(&[][..], Vec::as_slice);
        rules
            .iter()
            .find(|(_, rule)| {
                rule.matches_network(Some(network))
                    && rule.matches_port(Some(addr.port()))
                    && rule.matches_ip(Some(&ip))
            })
            .map_or(
                if is_private(ip) {
                    Action::Block
                } else {
                    self.outbounds
                        .get(outbound)
                        .cloned()
                        .unwrap_or(Action::Direct(FreedomStrategy::AsIs))
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
        if let Some(tag) = self.first_match(query, query.ip.or(resolved)) {
            return self.decision(tag);
        }
        if self.strategy == RoutingDomainStrategy::IpIfNonMatch && query.domain.is_some() {
            if let Some(ip) = self.resolve(query).await {
                if let Some(tag) = self.first_match(query, Some(ip)) {
                    return self.decision(tag);
                }
            }
        }
        self.decision(&self.default_tag)
    }

    async fn resolve(&self, query: &Query<'_>) -> Option<IpAddr> {
        let domain = query.domain?;
        tokio::net::lookup_host((domain, query.port))
            .await
            .ok()?
            .next()
            .map(|a| a.ip())
    }

    fn first_match(&self, query: &Query<'_>, ip: Option<IpAddr>) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.matches(query, ip))
            .map(|rule| rule.tag.as_str())
    }

    fn decision(&self, tag: &str) -> Decision {
        // No outbounds at all behaves like a lone freedom outbound.
        let action = if self.outbounds.is_empty() {
            Action::Direct(FreedomStrategy::AsIs)
        } else {
            self.outbounds.get(tag).cloned().unwrap_or(Action::Block)
        };
        // The tag stays as is, even empty: finalRules and stats are keyed by it.
        Decision {
            tag: tag.to_owned(),
            action,
        }
    }
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
            user: "alice",
            source: "203.0.113.5:40000".parse().unwrap(),
            network: Network::Tcp,
            domain,
            ip: ip.map(|i| i.parse().unwrap()),
            port,
            protocol: None,
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
            Action::Block
        );
        assert_eq!(
            r.route(&query(Some("example.com"), None, 443)).await,
            Decision {
                tag: "direct".into(),
                action: Action::Direct(FreedomStrategy::AsIs)
            }
        );
        let mut bt = query(None, Some("1.1.1.1"), 6881);
        bt.protocol = Some("bittorrent");
        assert_eq!(r.route(&bt).await.tag, "blocked");
    }

    #[tokio::test]
    async fn server_side_fields_and_unsupported_outbounds() {
        let r = router(json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "warp", "protocol": "vmess"}],
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
                tag: "warp".into(),
                action: Action::Block
            }
        );
        assert_eq!(
            r.route(&query(Some("example.com"), None, 443)).await.action,
            Action::Direct(FreedomStrategy::AsIs)
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
    fn freedom_final_rules() {
        let r = router(json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "ip": ["127.0.0.1/32"], "port": "8080"},
                {"action": "block", "ip": ["1.1.1.1"]}
            ]}}, {"tag": "plain", "protocol": "freedom"}]
        }));
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            r.final_action("direct", Network::Tcp, at("127.0.0.1:8080")),
            Action::Direct(FreedomStrategy::AsIs)
        );
        assert_eq!(
            r.final_action("direct", Network::Tcp, at("127.0.0.1:22")),
            Action::Block
        );
        assert_eq!(
            r.final_action("direct", Network::Udp, at("1.1.1.1:53")),
            Action::Block
        );
        assert_eq!(
            r.final_action("plain", Network::Tcp, at("1.1.1.1:53")),
            Action::Direct(FreedomStrategy::AsIs)
        );
        assert_eq!(
            r.final_action("plain", Network::Tcp, at("192.168.1.1:80")),
            Action::Block
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
                tag: "v4only".into(),
                action: Action::Direct(FreedomStrategy::UseIPv4)
            }
        );
        assert!(Router::build(
            &json!({"outbounds": [{"tag": "bad", "protocol": "freedom", "settings": {"domainStrategy": "invalid"}}]}),
            &[]
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_rule_fields() {
        let config = json!({"routing": {"rules": [{"type": "field", "outboundTag": "x", "attrs": {"a": "b"}}]}});
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
}
