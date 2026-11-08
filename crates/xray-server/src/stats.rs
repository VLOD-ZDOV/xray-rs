//! Xray-compatible traffic counters and online-user tracking, read by the
//! StatsService API. Counter names follow Xray: `user>>>EMAIL>>>traffic>>>uplink`,
//! `inbound>>>TAG>>>traffic>>>downlink`, `outbound>>>TAG>>>traffic>>>uplink`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

static STATS: OnceLock<Stats> = OnceLock::new();

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub enabled: bool,
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

impl Policy {
    /// Reads `policy` from the config. Without a `stats` section Xray keeps no counters.
    pub fn from_config(root: &Value) -> Self {
        if root.get("stats").is_none() {
            return Self::default();
        }
        let flag = |v: Option<&Value>, key: &str| {
            v.and_then(|v| v.get(key))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        };
        let level = root.pointer("/policy/levels/0");
        let system = root.pointer("/policy/system");
        Self {
            enabled: true,
            user_uplink: flag(level, "statsUserUplink"),
            user_downlink: flag(level, "statsUserDownlink"),
            user_online: flag(level, "statsUserOnline"),
            inbound_uplink: flag(system, "statsInboundUplink"),
            inbound_downlink: flag(system, "statsInboundDownlink"),
            outbound_uplink: flag(system, "statsOutboundUplink"),
            outbound_downlink: flag(system, "statsOutboundDownlink"),
        }
    }
}

pub struct Stats {
    policy: Policy,
    counters: Mutex<HashMap<String, Arc<AtomicI64>>>,
    online: Mutex<HashMap<String, HashMap<IpAddr, Online>>>,
    started: Instant,
}

struct Online {
    connections: usize,
    last_seen: i64,
}

pub fn init(policy: Policy) {
    let _ = STATS.set(Stats::new(policy));
}

pub fn get() -> &'static Stats {
    STATS.get_or_init(|| Stats::new(Policy::default()))
}

impl Stats {
    fn new(policy: Policy) -> Self {
        Self {
            policy,
            counters: Mutex::new(HashMap::new()),
            online: Mutex::new(HashMap::new()),
            started: Instant::now(),
        }
    }

    pub fn uptime_secs(&self) -> u32 {
        self.started.elapsed().as_secs().min(u64::from(u32::MAX)) as u32
    }

    fn counter(&self, name: String) -> Arc<AtomicI64> {
        lock(&self.counters).entry(name).or_default().clone()
    }

    /// Xray creates an inbound's or outbound's counters with its handler, so
    /// they are listed at zero before any traffic.
    pub fn register(&self, kind: &str, tag: &str) {
        let p = self.policy;
        let (up, down) = match kind {
            "inbound" => (p.inbound_uplink, p.inbound_downlink),
            _ => (p.outbound_uplink, p.outbound_downlink),
        };
        if !self.policy.enabled || tag.is_empty() {
            return;
        }
        if up {
            self.counter(format!("{kind}>>>{tag}>>>traffic>>>uplink"));
        }
        if down {
            self.counter(format!("{kind}>>>{tag}>>>traffic>>>downlink"));
        }
    }

    /// Counters for one proxied connection, honoring the policy flags.
    pub fn traffic(&self, inbound: &str, email: &str, level: u32, outbound: &str) -> Traffic {
        if !self.policy.enabled {
            return Traffic::default();
        }
        let p = self.policy;
        let user_policy = crate::policy::for_level(level);
        let mut traffic = Traffic::default();
        let mut add = |enabled: bool, name: String, up: bool| {
            if enabled {
                let counter = self.counter(name);
                if up {
                    traffic.up.push(counter)
                } else {
                    traffic.down.push(counter)
                }
            }
        };
        if !email.is_empty() {
            add(
                user_policy.stats_user_uplink,
                format!("user>>>{email}>>>traffic>>>uplink"),
                true,
            );
            add(
                user_policy.stats_user_downlink,
                format!("user>>>{email}>>>traffic>>>downlink"),
                false,
            );
        }
        if !inbound.is_empty() {
            add(
                p.inbound_uplink,
                format!("inbound>>>{inbound}>>>traffic>>>uplink"),
                true,
            );
            add(
                p.inbound_downlink,
                format!("inbound>>>{inbound}>>>traffic>>>downlink"),
                false,
            );
        }
        if !outbound.is_empty() {
            add(
                p.outbound_uplink,
                format!("outbound>>>{outbound}>>>traffic>>>uplink"),
                true,
            );
            add(
                p.outbound_downlink,
                format!("outbound>>>{outbound}>>>traffic>>>downlink"),
                false,
            );
        }
        traffic
    }

    /// `QueryStats`: every counter whose name contains `pattern`.
    pub fn query(&self, pattern: &str, reset: bool) -> Vec<(String, i64)> {
        let counters = lock(&self.counters);
        let mut out: Vec<(String, i64)> = counters
            .iter()
            .filter(|(name, _)| name.contains(pattern))
            .map(|(name, c)| {
                (
                    name.clone(),
                    if reset {
                        c.swap(0, Ordering::Relaxed)
                    } else {
                        c.load(Ordering::Relaxed)
                    },
                )
            })
            .collect();
        out.sort();
        out
    }

    pub fn get_counter(&self, name: &str, reset: bool) -> Option<i64> {
        let counters = lock(&self.counters);
        let c = counters.get(name)?;
        Some(if reset {
            c.swap(0, Ordering::Relaxed)
        } else {
            c.load(Ordering::Relaxed)
        })
    }

    /// Marks a live connection from `ip` for `email` until the guard drops.
    pub fn connect(&'static self, email: &str, level: u32, ip: IpAddr) -> Option<OnlineGuard> {
        if !self.policy.enabled || email.is_empty() {
            return None;
        }
        let user_policy = crate::policy::for_level(level);
        if !user_policy.stats_user_online {
            return None;
        }
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            ip => ip,
        };
        if ip == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            return None;
        }
        let mut online = lock(&self.online);
        let entry = online
            .entry(email.to_owned())
            .or_default()
            .entry(ip)
            .or_insert(Online {
                connections: 0,
                last_seen: 0,
            });
        entry.connections += 1;
        entry.last_seen = unix_now();
        Some(OnlineGuard {
            stats: self,
            email: email.to_owned(),
            ip,
        })
    }

    /// Users with live connections and, per IP, the last time one was opened.
    pub fn online_users(&self) -> Vec<(String, Vec<(String, i64)>)> {
        let online = lock(&self.online);
        let mut users: Vec<_> = online
            .iter()
            .map(|(email, ips)| {
                let mut ips: Vec<_> = ips
                    .iter()
                    .map(|(ip, o)| (ip.to_string(), o.last_seen))
                    .collect();
                ips.sort();
                (email.clone(), ips)
            })
            .collect();
        users.sort();
        users
    }
}

pub struct OnlineGuard {
    stats: &'static Stats,
    email: String,
    ip: IpAddr,
}

impl Drop for OnlineGuard {
    fn drop(&mut self) {
        let mut online = lock(&self.stats.online);
        if let Some(ips) = online.get_mut(&self.email) {
            if let Some(entry) = ips.get_mut(&self.ip) {
                entry.connections -= 1;
                if entry.connections == 0 {
                    ips.remove(&self.ip);
                }
            }
            if ips.is_empty() {
                online.remove(&self.email);
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct Traffic {
    up: Vec<Arc<AtomicI64>>,
    down: Vec<Arc<AtomicI64>>,
}

impl Traffic {
    pub fn up(&self, bytes: usize) {
        for c in &self.up {
            c.fetch_add(bytes as i64, Ordering::Relaxed);
        }
    }

    pub fn down(&self, bytes: usize) {
        for c in &self.down {
            c.fetch_add(bytes as i64, Ordering::Relaxed);
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn leaked(policy: Policy) -> &'static Stats {
        Box::leak(Box::new(Stats::new(policy)))
    }

    #[test]
    fn counts_and_resets_like_xray() {
        let _lock = crate::policy::TEST_LOCK.lock().unwrap();
        let panel = json!({"stats": {}, "policy": {"levels": {"99": {"statsUserUplink": true, "statsUserDownlink": true}},
            "system": {"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": false}}});
        crate::policy::init(crate::policy::PolicyManager::from_config(&panel));
        let stats = leaked(Policy::from_config(&panel));
        let t = stats.traffic("in-1", "alice", 99, "direct");
        t.up(100);
        t.down(1000);
        let all = stats.query("", false);
        assert_eq!(all.len(), 4, "outbound counters are disabled by policy");
        assert_eq!(
            stats.query("user>>>", true),
            vec![
                ("user>>>alice>>>traffic>>>downlink".into(), 1000),
                ("user>>>alice>>>traffic>>>uplink".into(), 100),
            ]
        );
        assert_eq!(
            stats.get_counter("user>>>alice>>>traffic>>>uplink", false),
            Some(0)
        );
        assert_eq!(
            stats.get_counter("inbound>>>in-1>>>traffic>>>downlink", false),
            Some(1000)
        );
    }

    #[test]
    fn no_stats_section_means_no_counters() {
        assert_eq!(
            Policy::from_config(&json!({"policy": {"levels": {"0": {"statsUserUplink": true}}}})),
            Policy::default()
        );
    }

    #[test]
    fn tracks_online_ips() {
        let _lock = crate::policy::TEST_LOCK.lock().unwrap();
        let panel = json!({"stats": {}, "policy": {"levels": {"99": {"statsUserOnline": true}}}});
        crate::policy::init(crate::policy::PolicyManager::from_config(&panel));
        let stats = leaked(Policy::from_config(&panel));
        let a = stats.connect("bob", 99, "1.2.3.4".parse().unwrap());
        let b = stats.connect("bob", 99, "::ffff:1.2.3.4".parse().unwrap());
        assert_eq!(stats.online_users()[0].1.len(), 1);
        drop(a);
        assert_eq!(stats.online_users().len(), 1);
        drop(b);
        assert!(stats.online_users().is_empty());
    }
}
