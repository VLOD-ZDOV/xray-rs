//! WireGuard outbound (e.g. Cloudflare WARP from 3x-ui) over the userspace
//! client in xray-wireguard. The device starts on first use and restarts if
//! it closes; destination domains are resolved with the system resolver.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;
use tokio::sync::Mutex;
use xray_proxy::wireguard::{AllowedIp, KeyMaterial};
use xray_wireguard::{Client, Config, Options, PeerConfig, TcpStream, UdpSession};

use crate::log;
use crate::vless::{resolve_all, Host};

const DEFAULT_MTU: u16 = 1420;
// The client's defaults (16 TCP flows) are sized for one phone; a server
// relays every user's connections through one device.
const TCP_FLOWS: usize = 4096;
const PENDING_OPENS: usize = 512;
const BUSY_WARN_INTERVAL_SECS: u64 = 60;

impl std::fmt::Debug for WgOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgOutbound")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

pub struct WgOutbound {
    tag: String,
    secret_key: KeyMaterial,
    addresses: Vec<IpAddr>,
    peers: Vec<Peer>,
    mtu: u16,
    reserved: [u8; 3],
    prefer_v6: bool,
    sockopt: Option<Arc<crate::config::SockoptSettings>>,
    client: Mutex<Option<Client>>,
    started: Instant,
    last_busy_warn: AtomicU64,
}

struct Peer {
    public_key: KeyMaterial,
    preshared_key: Option<KeyMaterial>,
    endpoint: (String, u16),
    allowed_ips: Vec<AllowedIp>,
    keepalive: u16,
}

impl WgOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: String| format!("outbound {tag:?} (wireguard): {m}");
        let settings = outbound.get("settings").unwrap_or(outbound);
        let secret_key = KeyMaterial::parse(str_field(settings, "secretKey"))
            .map_err(|_| err("invalid secretKey".into()))?;
        let mut addresses = Vec::new();
        for raw in strings(settings.get("address")) {
            let ip = raw.split('/').next().unwrap_or_default();
            addresses.push(
                ip.parse::<IpAddr>()
                    .map_err(|_| err(format!("invalid address {raw:?}")))?,
            );
        }
        let mut peers = Vec::new();
        for peer in settings
            .get("peers")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
        {
            let endpoint = str_field(peer, "endpoint");
            let (host, port) = endpoint
                .rsplit_once(':')
                .ok_or_else(|| err(format!("invalid endpoint {endpoint:?}")))?;
            let port = port
                .parse::<u16>()
                .map_err(|_| err(format!("invalid endpoint {endpoint:?}")))?;
            let host = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            let mut allowed_ips = Vec::new();
            for raw in strings(peer.get("allowedIPs")) {
                allowed_ips.push(
                    raw.parse::<AllowedIp>()
                        .map_err(|_| err(format!("invalid allowedIPs entry {raw:?}")))?,
                );
            }
            if allowed_ips.is_empty() {
                allowed_ips = vec![
                    "0.0.0.0/0".parse().unwrap_or_else(|_| unreachable!()),
                    "::/0".parse().unwrap_or_else(|_| unreachable!()),
                ];
            }
            let preshared_key = match str_field(peer, "preSharedKey") {
                "" => None,
                key => {
                    Some(KeyMaterial::parse(key).map_err(|_| err("invalid preSharedKey".into()))?)
                }
            };
            peers.push(Peer {
                public_key: KeyMaterial::parse(str_field(peer, "publicKey"))
                    .map_err(|_| err("invalid publicKey".into()))?,
                preshared_key,
                endpoint: (host, port),
                allowed_ips,
                keepalive: peer
                    .get("keepAlive")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(u64::from(u16::MAX)) as u16,
            });
        }
        let mut mtu = settings
            .get("mtu")
            .and_then(Value::as_u64)
            .map_or(DEFAULT_MTU, |m| m.min(u64::from(u16::MAX)) as u16);
        if !(1280..=1420).contains(&mtu) {
            log::warn(err(format!(
                "mtu {mtu} is outside 1280..1420, using {DEFAULT_MTU}"
            )));
            mtu = DEFAULT_MTU;
        }
        let reserved = parse_reserved(settings.get("reserved"))
            .ok_or_else(|| err("reserved must be 3 bytes".into()))?;
        let strategy = str_field(settings, "domainStrategy").to_ascii_lowercase();
        let sockopt = crate::config::parse_sockopt(
            outbound
                .pointer("/streamSettings/sockopt")
                .unwrap_or(&Value::Null),
            &format!("outbound {tag:?}"),
        )?
        .map(Arc::new);
        let outbound = Self {
            tag: tag.to_owned(),
            secret_key,
            addresses,
            peers,
            mtu,
            reserved,
            prefer_v6: strategy.contains("v6v4") || strategy.ends_with("ipv6"),
            sockopt,
            client: Mutex::new(None),
            started: Instant::now(),
            last_busy_warn: AtomicU64::new(0),
        };
        // Validate everything except endpoint resolution, which waits for first use.
        outbound
            .config(vec![
                SocketAddr::from(([192, 0, 2, 1], 1));
                outbound.peers.len()
            ])
            .validate()
            .map_err(|e| err(e.to_string()))?;
        Ok(outbound)
    }

    fn config(&self, endpoints: Vec<SocketAddr>) -> Config {
        Config {
            secret_key: self.secret_key.clone(),
            peers: self
                .peers
                .iter()
                .zip(endpoints)
                .map(|(peer, endpoint)| PeerConfig {
                    public_key: peer.public_key.clone(),
                    preshared_key: peer.preshared_key.clone(),
                    endpoint,
                    allowed_ips: peer.allowed_ips.clone(),
                    keepalive: peer.keepalive,
                })
                .collect(),
            addresses: self.addresses.clone(),
            mtu: self.mtu,
        }
    }

    /// Brings the tunnel up at startup, as Xray does, so the first user connection does not race
    /// the handshake. Skipped outside a runtime (config test).
    pub fn warm_up(self: Arc<Self>) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(e) = self.client().await {
                    log::warn(format!("wireguard outbound {:?}: {e}", self.tag));
                }
            });
        }
    }

    async fn client(&self) -> io::Result<Client> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref().filter(|c| c.is_live()) {
            return Ok(client.clone());
        }
        let mut endpoints = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let host = match peer.endpoint.0.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Domain(peer.endpoint.0.clone()),
            };
            endpoints.push(resolve_all(&host, peer.endpoint.1).await?[0]);
        }
        let options = Options {
            reserved: self.reserved,
            tcp_flows: TCP_FLOWS,
            pending_opens: PENDING_OPENS,
        };
        let protector: Option<Arc<dyn xray_transport::SocketProtector>> =
            self.sockopt.as_ref().map(|s| {
                Arc::new(crate::outbound_transport::OutboundProtector::new(
                    Some(s.clone()),
                    None,
                    None,
                )) as _
            });
        let client = Client::start_with_options(self.config(endpoints), protector, options)
            .await
            .map_err(to_io)?;
        log::info(format!("wireguard outbound {:?} started", self.tag));
        *slot = Some(client.clone());
        Ok(client)
    }

    /// Resolved addresses usable through the tunnel, in preference order.
    async fn targets(&self, host: &Host, port: u16) -> io::Result<Vec<SocketAddr>> {
        let mut addrs = resolve_all(host, port).await?;
        addrs.retain(|a| {
            self.addresses
                .iter()
                .any(|local| local.is_ipv4() == a.is_ipv4())
        });
        if self.prefer_v6 {
            addrs.sort_by_key(SocketAddr::is_ipv4);
        }
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no address family usable through wireguard",
            ));
        }
        Ok(addrs)
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<TcpStream> {
        let client = self.client().await?;
        let mut last = None;
        for addr in self.targets(host, port).await? {
            match client.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(xray_wireguard::Error::Busy) => {
                    self.warn_busy();
                    return Err(to_io(xray_wireguard::Error::Busy));
                }
                Err(e) => last = Some(to_io(e)),
            }
        }
        Err(last.unwrap_or_else(|| io::ErrorKind::NotFound.into()))
    }

    /// Running out of flows silently drops users' connections, so say so (rate-limited).
    fn warn_busy(&self) {
        let now = self.started.elapsed().as_secs() + BUSY_WARN_INTERVAL_SECS;
        let last = self.last_busy_warn.load(Ordering::Relaxed);
        if now >= last + BUSY_WARN_INTERVAL_SECS
            && self
                .last_busy_warn
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            log::warn(format!("wireguard outbound {:?}: connection limit ({TCP_FLOWS}) reached, new connections are refused", self.tag));
        }
    }

    pub async fn open_udp(&self, addr: SocketAddr) -> io::Result<UdpSession> {
        self.client().await?.open_udp(addr).await.map_err(to_io)
    }

    pub async fn udp_target(&self, host: &Host, port: u16) -> io::Result<SocketAddr> {
        Ok(self.targets(host, port).await?[0])
    }
}

pub fn to_io(e: xray_wireguard::Error) -> io::Error {
    match e {
        xray_wireguard::Error::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// Xray takes `reserved` as `[a, b, c]`; some panels emit `"a,b,c"`.
fn parse_reserved(value: Option<&Value>) -> Option<[u8; 3]> {
    let bytes: Vec<u64> = match value {
        None | Some(Value::Null) => return Some([0; 3]),
        Some(Value::Array(items)) => items.iter().map(Value::as_u64).collect::<Option<_>>()?,
        Some(Value::String(s)) if s.is_empty() => return Some([0; 3]),
        Some(Value::String(s)) => s
            .split(',')
            .map(|p| p.trim().parse().ok())
            .collect::<Option<_>>()?,
        _ => return None,
    };
    match bytes.as_slice() {
        [] => Some([0; 3]),
        [a, b, c] => Some([
            u8::try_from(*a).ok()?,
            u8::try_from(*b).ok()?,
            u8::try_from(*c).ok()?,
        ]),
        _ => None,
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
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

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_panel_warp_outbound() {
        let settings = json!({
            "mtu": 1420,
            "secretKey": "cKE7LmCF61IhqqABGhvJ44jWXp8fKymcMAEVAzbDF2k=",
            "address": ["172.16.0.2/32", "2606:4700:110:8a36::1/128"],
            "workers": 2,
            "domainStrategy": "ForceIPv6v4",
            "reserved": [12, 34, 56],
            "peers": [{"publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "allowedIPs": ["0.0.0.0/0", "::/0"], "endpoint": "engage.cloudflareclient.com:2408"}],
            "noKernelTun": false
        });
        let wg = WgOutbound::parse("warp", &settings).unwrap();
        assert_eq!(wg.reserved, [12, 34, 56]);
        assert!(wg.prefer_v6);
        assert_eq!(
            wg.peers[0].endpoint,
            ("engage.cloudflareclient.com".to_owned(), 2408)
        );
        assert_eq!(wg.addresses.len(), 2);
    }

    #[test]
    fn reserved_forms() {
        assert_eq!(parse_reserved(Some(&json!("1, 2, 3"))), Some([1, 2, 3]));
        assert_eq!(parse_reserved(None), Some([0; 3]));
        assert_eq!(parse_reserved(Some(&json!([1, 2]))), None);
        assert_eq!(parse_reserved(Some(&json!([1, 2, 300]))), None);
    }
}
