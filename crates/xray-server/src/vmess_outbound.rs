//! VMess outbound supporting TCP and common transports.

use std::fmt;
use std::io;

use serde_json::Value;
use uuid::Uuid;
use xray_proxy::vmess::{Account, Cipher, ClientStream, Options};
use xray_routing::{Network, Target, TargetAddr};

use crate::outbound::Stream;
use crate::outbound_transport::ServerConnector;
use crate::vless::Host;

pub struct VmessOutbound {
    pub tag: String,
    pub connector: ServerConnector,
    pub account: Account,
}

impl fmt::Debug for VmessOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmessOutbound")
            .field("tag", &self.tag)
            .field("server", &self.connector.server)
            .finish_non_exhaustive()
    }
}

impl VmessOutbound {
    pub fn parse(tag: &str, outbound: &Value) -> Result<Self, String> {
        let err = |m: &str| format!("outbound {tag:?} (vmess): {m}");
        let connector = ServerConnector::parse(tag, "vmess", outbound)?;
        let settings = outbound.get("settings").unwrap_or(&Value::Null);

        let vnext = settings
            .get("vnext")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .unwrap_or(settings);
        let user = vnext
            .get("users")
            .and_then(Value::as_array)
            .and_then(|u| u.first())
            .unwrap_or(vnext);

        let id_str = user
            .get("id")
            .or_else(|| settings.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| err("missing user id"))?;
        let user_id = Uuid::parse_str(id_str)
            .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id_str.as_bytes()));

        let security_str = user
            .get("security")
            .or_else(|| settings.get("security"))
            .and_then(Value::as_str)
            .unwrap_or("auto");
        let cipher_name = match security_str {
            "zero" | "none" => "auto",
            other => other,
        };
        let cipher = Cipher::parse(cipher_name).map_err(|e| err(&e.to_string()))?;
        let account = Account::new(
            user_id.as_bytes(),
            cipher,
            Options {
                authenticated_length: true,
                no_termination_signal: false,
            },
        );

        Ok(Self {
            tag: tag.to_owned(),
            connector,
            account,
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
        let stream = ClientStream::new(carrier, &self.account, &target)?;
        Ok(Box::new(stream))
    }
}
