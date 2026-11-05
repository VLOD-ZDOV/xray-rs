//! Runtime timeouts and buffer sizes configured by the `policy` section.

use serde_json::Value;
use std::sync::RwLock;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySettings {
    pub handshake: Duration,
    pub conn_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
    pub buffer_size: usize,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(4),
            conn_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(2),
            downlink_only: Duration::from_secs(5),
            buffer_size: 32 * 1024,
        }
    }
}

static POLICY: RwLock<PolicySettings> = RwLock::new(PolicySettings {
    handshake: Duration::from_secs(4),
    conn_idle: Duration::from_secs(300),
    uplink_only: Duration::from_secs(2),
    downlink_only: Duration::from_secs(5),
    buffer_size: 32 * 1024,
});

impl PolicySettings {
    /// Level 0 of the `policy` section; other levels are not applied.
    pub fn from_config(root: &Value) -> Self {
        let mut current = Self::default();
        let level = &root["policy"]["levels"]["0"];
        let secs = |name: &str| {
            level
                .get(name)
                .and_then(Value::as_u64)
                .map(Duration::from_secs)
        };
        if let Some(v) = secs("handshake") {
            current.handshake = v;
        }
        if let Some(v) = secs("connIdle") {
            current.conn_idle = v;
        }
        if let Some(v) = secs("uplinkOnly") {
            current.uplink_only = v;
        }
        if let Some(v) = secs("downlinkOnly") {
            current.downlink_only = v;
        }
        if let Some(kib) = level.get("bufferSize").and_then(Value::as_u64) {
            if kib > 0 {
                current.buffer_size = kib as usize * 1024;
            }
        }
        current
    }
}

pub fn init(settings: PolicySettings) {
    if let Ok(mut lock) = POLICY.write() {
        *lock = settings;
    }
}

pub fn get() -> PolicySettings {
    POLICY.read().map(|p| *p).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_level_zero() {
        let root = serde_json::json!({"policy": {"levels": {"0": {
            "handshake": 10, "connIdle": 60, "uplinkOnly": 3, "downlinkOnly": 7,
            "bufferSize": 64, "statsUserOnline": true
        }}}});
        let settings = PolicySettings::from_config(&root);
        assert_eq!(settings.handshake, Duration::from_secs(10));
        assert_eq!(settings.conn_idle, Duration::from_secs(60));
        assert_eq!(settings.uplink_only, Duration::from_secs(3));
        assert_eq!(settings.downlink_only, Duration::from_secs(7));
        assert_eq!(settings.buffer_size, 64 * 1024);
        assert_eq!(
            PolicySettings::from_config(&serde_json::json!({})),
            PolicySettings::default()
        );
    }
}
