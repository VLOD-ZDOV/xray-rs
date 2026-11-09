//! HTTP CONNECT proxy outbound for TCP relaying.

use std::fmt;
use std::io;

use serde_json::Value;
use xray_proxy::outbound::{encode_connect_request, http_connect, HttpAccount};
use xray_routing::{Network, Target, TargetAddr};

use crate::outbound::Stream;
use crate::outbound_transport::{PrefixedStream, ServerConnector};
use crate::vless::{Host, CONNECT_TIMEOUT};

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

        // Xray: the flat form takes user/pass from the top level; otherwise exactly
        // one server with at most one user.
        fn text<'a>(obj: &'a Value, key: &str) -> Result<&'a str, String> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(""),
                Some(Value::String(s)) => Ok(s.as_str()),
                Some(_) => Err(format!("{key:?} must be a string")),
            }
        }
        let creds = if settings.get("address").is_some() {
            let user = text(settings, "user").map_err(|m| err(&m))?;
            if user.is_empty() {
                None
            } else {
                Some((user, text(settings, "pass").map_err(|m| err(&m))?))
            }
        } else {
            let servers = settings.get("servers").and_then(Value::as_array);
            if servers.is_some_and(|s| s.len() > 1) {
                return Err(err("\"servers\" should have one and only one member"));
            }
            let users = servers
                .and_then(|s| s.first())
                .and_then(|s| s.get("users"))
                .and_then(Value::as_array);
            if users.is_some_and(|u| u.len() > 1) {
                return Err(err("\"users\" should have one member at most"));
            }
            match users.and_then(|u| u.first()) {
                Some(u) => match (
                    text(u, "user").map_err(|m| err(&m))?,
                    text(u, "pass").map_err(|m| err(&m))?,
                ) {
                    ("", "") => None,
                    creds => Some(creds),
                },
                None => None,
            }
        };
        let account = match creds {
            Some((user, pass)) => {
                Some(HttpAccount::new(user, pass).ok_or_else(|| err("invalid HTTP credentials"))?)
            }
            None => None,
        };

        let mut headers = Vec::new();
        if let Some(obj) = settings.get("headers").and_then(Value::as_object) {
            for (k, v) in obj {
                let v_str = v
                    .as_str()
                    .ok_or_else(|| err(&format!("header {k:?} must be a string")))?;
                headers.push((k.clone(), v_str.to_owned()));
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

        let initial_bytes =
            tokio::time::timeout(CONNECT_TIMEOUT, http_connect(&mut carrier, &request))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "http proxy CONNECT timed out")
                })?
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

        if initial_bytes.is_empty() {
            Ok(Box::new(carrier))
        } else {
            Ok(Box::new(PrefixedStream::new(carrier, initial_bytes)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(settings: Value) -> Result<HttpOutbound, String> {
        HttpOutbound::parse("t", &json!({"protocol": "http", "settings": settings}))
    }

    #[test]
    fn flat_form_keeps_credentials() {
        let o =
            parse(json!({"address": "192.0.2.1", "port": 3128, "user": "u", "pass": "p"})).unwrap();
        assert!(o.account.is_some());
    }

    #[test]
    fn rejects_extra_servers_users_and_bad_types() {
        let server = json!({"address": "192.0.2.1", "port": 1});
        assert!(parse(json!({"servers": [server, server]})).is_err());
        let two_users = json!({"address": "192.0.2.1", "port": 1,
            "users": [{"user": "a", "pass": "b"}, {"user": "c", "pass": "d"}]});
        assert!(parse(json!({"servers": [two_users]})).is_err());
        let bad_pass = json!({"address": "192.0.2.1", "port": 1,
            "users": [{"user": "a", "pass": 5}]});
        assert!(parse(json!({"servers": [bad_pass]})).is_err());
        assert!(parse(json!({"address": "192.0.2.1", "port": 1, "headers": {"X": 5}})).is_err());
    }
}
