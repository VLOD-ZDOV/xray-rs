//! Hysteria (Hysteria 2) outbound supporting TCP streams via multiplexed QUIC.

use std::fmt;
use std::io;

use serde_json::Value;
use tokio::sync::Mutex;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::{HysteriaClient, HysteriaConfig};
use xray_transport::{TlsClientConfig, TlsConnector};

use crate::config::str_field;
use crate::outbound::Stream;
use crate::vless::{resolve, Host};

pub struct HysteriaOutbound {
    pub tag: String,
    pub address: String,
    pub port: u16,
    pub auth: String,
    pub tls_config: TlsClientConfig,
    client: Mutex<Option<HysteriaClient>>,
}

impl fmt::Debug for HysteriaOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaOutbound")
            .field("tag", &self.tag)
            .field("address", &self.address)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl HysteriaOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let address = str_field(settings, "address");
        if address.is_empty() {
            return Err("no target server found".into());
        }
        let port = settings.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
        if port == 0 {
            return Err("no target server found".into());
        }

        let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
        let h_settings = stream.get("hysteriaSettings").unwrap_or(&Value::Null);
        let top_auth = str_field(settings, "auth");
        let stream_auth = str_field(h_settings, "auth");
        let auth = if !top_auth.is_empty() {
            top_auth
        } else {
            stream_auth
        };

        let tls_settings = stream.get("tlsSettings").unwrap_or(&Value::Null);
        let server_name = tls_settings
            .get("serverName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| address.to_string());
        let allow_insecure = tls_settings
            .get("allowInsecure")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let tls_config = TlsClientConfig {
            server_name,
            allow_insecure,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: vec!["h3".to_string()],
            fingerprint: None,
        };

        Ok(Self {
            tag: tag.to_owned(),
            address: address.to_owned(),
            port,
            auth: auth.to_owned(),
            tls_config,
            client: Mutex::new(None),
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<Box<dyn Stream>> {
        let mut guard = self.client.lock().await;
        let client = match &*guard {
            Some(c) if c.is_live() => c.clone(),
            _ => {
                let resolved = resolve(&Host::Domain(self.address.clone()), self.port)
                    .await
                    .map_err(|e| io::Error::other(format!("Hysteria resolve failed: {e}")))?;
                let cfg = HysteriaConfig::new(resolved, self.tls_config.clone(), self.auth.clone());
                let tls_connector = TlsConnector::system()
                    .map_err(|e| io::Error::other(format!("Hysteria TLS init failed: {e}")))?;
                let c = HysteriaClient::connect(cfg, &tls_connector)
                    .await
                    .map_err(|e| io::Error::other(format!("Hysteria connect failed: {e}")))?;
                *guard = Some(c.clone());
                c
            }
        };

        let target_addr = match host {
            Host::Ip(ip) => TargetAddr::Ip(*ip),
            Host::Domain(d) => TargetAddr::Domain(d.clone()),
        };
        let target = Target::new(target_addr, port, Network::Tcp);
        let stream = client
            .open_tcp(&target)
            .await
            .map_err(|e| io::Error::other(format!("Hysteria open_tcp failed: {e}")))?;
        Ok(Box::new(stream))
    }
}
