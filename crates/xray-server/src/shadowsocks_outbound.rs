//! Shadowsocks outbound supporting AEAD 2017 and Shadowsocks 2022.

use std::fmt;
use std::io;
use std::sync::Arc;

use serde_json::Value;
use xray_proxy::shadowsocks::aead2017::{
    Cipher, ClientStream as ClientStream2017, Method as Method2017,
};
use xray_proxy::shadowsocks2022::{ClientStream as ClientStream2022, Method as Method2022};
use xray_routing::{Network, Target, TargetAddr};

use crate::outbound::Stream;
use crate::outbound_transport::ServerConnector;
use crate::vless::Host;

pub enum ShadowsocksMethod {
    Aead2017(Arc<Method2017>),
    Ss2022(Arc<Method2022>),
}

pub struct ShadowsocksOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub method: ShadowsocksMethod,
}

impl fmt::Debug for ShadowsocksOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl ShadowsocksOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (shadowsocks): {m}");
        let connector = ServerConnector::parse(tag, "shadowsocks", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let (method_str, password) = if let Some(server) = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
        {
            let m = server
                .get("method")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing method in servers[0]"))?;
            let p = server
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| err("missing password in servers[0]"))?;
            (m, p)
        } else if let (Some(m), Some(p)) = (
            settings.get("method").and_then(Value::as_str),
            settings.get("password").and_then(Value::as_str),
        ) {
            (m, p)
        } else {
            return Err(err("missing method or password in settings"));
        };

        let method = if Cipher::parse(method_str).is_some() {
            ShadowsocksMethod::Aead2017(Arc::new(
                Method2017::new(method_str, password).map_err(|e| err(&e.to_string()))?,
            ))
        } else {
            match Method2022::new(method_str, password) {
                Ok(m) => ShadowsocksMethod::Ss2022(Arc::new(m)),
                Err(e) => {
                    return Err(err(&format!(
                        "unsupported shadowsocks method or key {method_str:?}: {e}"
                    )))
                }
            }
        };

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            method,
        })
    }

    pub async fn connect(&self, host: &Host, port: u16) -> io::Result<Box<dyn Stream>> {
        let carrier = self.connector.connect().await?;
        let target = Target::new(
            match host {
                Host::Ip(ip) => TargetAddr::Ip(*ip),
                Host::Domain(d) => TargetAddr::Domain(d.clone()),
            },
            port,
            Network::Tcp,
        );
        match &self.method {
            ShadowsocksMethod::Aead2017(m) => {
                let stream = ClientStream2017::new(carrier, m.clone(), &target)?;
                Ok(Box::new(stream))
            }
            ShadowsocksMethod::Ss2022(m) => {
                let stream = ClientStream2022::new(carrier, m.clone(), &target)?;
                Ok(Box::new(stream))
            }
        }
    }
}
