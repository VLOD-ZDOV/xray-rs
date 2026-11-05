//! HTTP CONNECT proxy outbound for TCP relaying.

use std::fmt;
use std::io;

use serde_json::Value;
use xray_proxy::outbound::{encode_connect_request, http_connect, HttpAccount};
use xray_routing::{Network, Target, TargetAddr};

use crate::outbound::Stream;
use crate::outbound_transport::{PrefixedStream, ServerConnector};
use crate::vless::Host;

pub struct HttpOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub account: Option<HttpAccount>,
    pub headers: Vec<(String, String)>,
}

impl fmt::Debug for HttpOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl HttpOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (http): {m}");
        let connector = ServerConnector::parse(tag, "http", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let account = if let Some(server) = settings
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
        {
            if let Some(user_obj) = server
                .get("users")
                .and_then(Value::as_array)
                .and_then(|u| u.first())
            {
                let user = user_obj
                    .get("user")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let pass = user_obj
                    .get("pass")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !user.is_empty() {
                    Some(
                        HttpAccount::new(user, pass)
                            .ok_or_else(|| err("invalid HTTP credentials"))?,
                    )
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut headers = Vec::new();
        if let Some(obj) = settings.get("headers").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(v_str) = v.as_str() {
                    headers.push((k.clone(), v_str.to_owned()));
                }
            }
        }

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            account,
            headers,
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

        let header_refs: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let request = encode_connect_request(&target, self.account.as_ref(), &header_refs)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let initial_bytes = http_connect(&mut carrier, &request)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

        if initial_bytes.is_empty() {
            Ok(Box::new(carrier))
        } else {
            Ok(Box::new(PrefixedStream::new(carrier, initial_bytes)))
        }
    }
}
