//! Runtime timeouts and buffer sizes configured by the `policy` section.

use std::sync::RwLock;
use std::time::Duration;
use xray_config::PolicyConfig;

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

pub fn init(config: Option<&PolicyConfig>) {
    let mut current = PolicySettings::default();
    if let Some(cfg) = config {
        if let Some(level0) = cfg.levels.get(&0) {
            if let Some(hs) = level0.handshake {
                current.handshake = Duration::from_secs(hs as u64);
            }
            if let Some(idle) = level0.conn_idle {
                current.conn_idle = Duration::from_secs(idle as u64);
            }
            if let Some(up) = level0.uplink_only {
                current.uplink_only = Duration::from_secs(up as u64);
            }
            if let Some(down) = level0.downlink_only {
                current.downlink_only = Duration::from_secs(down as u64);
            }
            if let Some(buf) = level0.buffer_size {
                if buf > 0 {
                    current.buffer_size = (buf as usize) * 1024;
                }
            }
        }
    }
    if let Ok(mut lock) = POLICY.write() {
        *lock = current;
    }
}

pub fn get() -> PolicySettings {
    POLICY
        .read()
        .map(|p| *p)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use xray_config::PolicyLevelConfig;

    #[test]
    fn test_policy_init() {
        let mut levels = BTreeMap::new();
        levels.insert(
            0,
            PolicyLevelConfig {
                handshake: Some(10),
                conn_idle: Some(60),
                uplink_only: Some(3),
                downlink_only: Some(7),
                buffer_size: Some(64),
                ..Default::default()
            },
        );

        let cfg = PolicyConfig {
            levels,
            ..Default::default()
        };

        init(Some(&cfg));
        let settings = get();
        assert_eq!(settings.handshake, Duration::from_secs(10));
        assert_eq!(settings.conn_idle, Duration::from_secs(60));
        assert_eq!(settings.uplink_only, Duration::from_secs(3));
        assert_eq!(settings.downlink_only, Duration::from_secs(7));
        assert_eq!(settings.buffer_size, 64 * 1024);
    }
}
