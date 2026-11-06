//! Runtime timeouts, buffer sizes, and per-user stats configured by the `policy` section.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySettings {
    pub handshake: Duration,
    pub conn_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
    pub buffer_size: usize,
    pub stats_user_uplink: bool,
    pub stats_user_downlink: bool,
    pub stats_user_online: bool,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(4),
            conn_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(2),
            downlink_only: Duration::from_secs(5),
            buffer_size: 32 * 1024,
            stats_user_uplink: false,
            stats_user_downlink: false,
            stats_user_online: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyManager {
    levels: HashMap<u32, PolicySettings>,
    default_policy: PolicySettings,
}

impl PolicyManager {
    pub fn from_config(root: &Value) -> Self {
        let mut mgr = Self::default();
        if let Some(levels) = root.pointer("/policy/levels").and_then(Value::as_object) {
            for (key, val) in levels {
                if let Ok(lvl) = key.parse::<u32>() {
                    let mut settings = mgr.default_policy;
                    let secs = |name: &str| {
                        val.get(name)
                            .and_then(Value::as_u64)
                            .map(Duration::from_secs)
                    };
                    if let Some(v) = secs("handshake") {
                        settings.handshake = v;
                    }
                    if let Some(v) = secs("connIdle") {
                        settings.conn_idle = v;
                    }
                    if let Some(v) = secs("uplinkOnly") {
                        settings.uplink_only = v;
                    }
                    if let Some(v) = secs("downlinkOnly") {
                        settings.downlink_only = v;
                    }
                    if let Some(kib) = val.get("bufferSize").and_then(Value::as_u64) {
                        if kib > 0 {
                            settings.buffer_size = kib as usize * 1024;
                        }
                    }
                    if let Some(b) = val.get("statsUserUplink").and_then(Value::as_bool) {
                        settings.stats_user_uplink = b;
                    }
                    if let Some(b) = val.get("statsUserDownlink").and_then(Value::as_bool) {
                        settings.stats_user_downlink = b;
                    }
                    if let Some(b) = val.get("statsUserOnline").and_then(Value::as_bool) {
                        settings.stats_user_online = b;
                    }
                    mgr.levels.insert(lvl, settings);
                }
            }
        }
        mgr
    }

    pub fn for_level(&self, level: u32) -> PolicySettings {
        self.levels
            .get(&level)
            .copied()
            .unwrap_or(self.default_policy)
    }
}

static POLICY_MANAGER: RwLock<Option<PolicyManager>> = RwLock::new(None);

pub fn init(manager: PolicyManager) {
    if let Ok(mut lock) = POLICY_MANAGER.write() {
        *lock = Some(manager);
    }
}

#[allow(dead_code)]
pub fn init_single(settings: PolicySettings) {
    let mut mgr = PolicyManager::default();
    mgr.levels.insert(0, settings);
    init(mgr);
}

pub fn for_level(level: u32) -> PolicySettings {
    if let Ok(lock) = POLICY_MANAGER.read() {
        if let Some(mgr) = lock.as_ref() {
            return mgr.for_level(level);
        }
    }
    PolicySettings::default()
}

pub fn get() -> PolicySettings {
    for_level(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_multiple_levels() {
        let root = serde_json::json!({"policy": {"levels": {
            "0": {
                "handshake": 10, "connIdle": 60, "uplinkOnly": 3, "downlinkOnly": 7,
                "bufferSize": 64, "statsUserOnline": true
            },
            "1": {
                "handshake": 5, "connIdle": 120, "uplinkOnly": 1, "downlinkOnly": 2,
                "bufferSize": 128, "statsUserUplink": true, "statsUserDownlink": true
            }
        }}});
        let manager = PolicyManager::from_config(&root);
        let l0 = manager.for_level(0);
        assert_eq!(l0.handshake, Duration::from_secs(10));
        assert_eq!(l0.conn_idle, Duration::from_secs(60));
        assert_eq!(l0.uplink_only, Duration::from_secs(3));
        assert_eq!(l0.downlink_only, Duration::from_secs(7));
        assert_eq!(l0.buffer_size, 64 * 1024);
        assert!(l0.stats_user_online);
        assert!(!l0.stats_user_uplink);
        assert!(!l0.stats_user_downlink);

        let l1 = manager.for_level(1);
        assert_eq!(l1.handshake, Duration::from_secs(5));
        assert_eq!(l1.conn_idle, Duration::from_secs(120));
        assert_eq!(l1.uplink_only, Duration::from_secs(1));
        assert_eq!(l1.downlink_only, Duration::from_secs(2));
        assert_eq!(l1.buffer_size, 128 * 1024);
        assert!(!l1.stats_user_online);
        assert!(l1.stats_user_uplink);
        assert!(l1.stats_user_downlink);

        let l99 = manager.for_level(99);
        assert_eq!(l99, PolicySettings::default());

        assert_eq!(
            PolicyManager::from_config(&serde_json::json!({})).for_level(0),
            PolicySettings::default()
        );
    }
}
