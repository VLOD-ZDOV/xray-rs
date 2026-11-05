//! Trojan outbound supporting TCP and common transports.

use std::fmt;
use std::io;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use xray_proxy::trojan::{encode_request_header, TrojanAuth};
use xray_routing::{Network, Target, TargetAddr};

use crate::outbound::Stream;
use crate::outbound_transport::ServerConnector;
use crate::vless::Host;

pub struct TrojanOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub auth: TrojanAuth,
}

impl fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl TrojanOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (trojan): {m}");
        let connector = ServerConnector::parse(tag, "trojan", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let password = if let Some(server) = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
        {
            server
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing password in servers[0]"))?
        } else if let Some(p) = settings.get("password").and_then(Value::as_str) {
            p
        } else {
            return Err(err("missing password in settings"));
        };

        let auth = TrojanAuth::new(password).map_err(|e| err(&e.to_string()))?;

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            auth,
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<Box<dyn Stream>> {
        let mut carrier = self.connector.connect().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Tcp,
        );
        let header = encode_request_header(&self.auth, &target)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        carrier.write_all(header.as_bytes()).await?;
        carrier.flush().await?;
        Ok(Box::new(carrier))
    }
}
