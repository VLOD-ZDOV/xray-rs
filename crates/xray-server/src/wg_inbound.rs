//! WireGuard server inbound over userspace smoltcp stack in xray-wireguard.

use crate::config::Inbound;
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Query, Router};
use crate::stats;
use crate::vless::{copy_buf, relay_policy, Activity, Host};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use xray_config::Network;
use xray_proxy::wireguard::{AllowedIp, KeyMaterial};
use xray_wireguard::{
    IncomingTcpStream, IncomingUdpSession, Server, ServerConfig, ServerPeerConfig,
};

pub fn parse(tag: &str, item: &Value) -> Result<ServerConfig, String> {
    let settings = item.get("settings").unwrap_or(&Value::Null);
    let secret_key_str = settings
        .get("secretKey")
        .and_then(Value::as_str)
        .unwrap_or("");
    if secret_key_str.is_empty() {
        return Err("invalid WireGuard secret key: %winfra/conf: key must not be empty".into());
    }
    let secret_key = KeyMaterial::parse(secret_key_str).map_err(|_| {
        "invalid WireGuard secret key: %winfra/conf: failed to deserialize key".to_string()
    })?;

    let mut addresses = Vec::new();
    match settings.get("address").and_then(Value::as_array) {
        Some(addrs) => {
            for a in addrs {
                let s = a.as_str().unwrap_or("");
                let ip_str = s.split('/').next().unwrap_or(s);
                let ip = ip_str
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid WireGuard address {s:?}"))?;
                addresses.push(ip);
            }
        }
        None => {
            addresses = vec![
                "10.0.0.1".parse().unwrap(),
                "fd59:7153:2388:b5fd::1".parse().unwrap(),
            ];
        }
    }

    let mut peers = Vec::new();
    if let Some(peer_list) = settings.get("peers").and_then(Value::as_array) {
        for p in peer_list {
            let pub_key_str = p.get("publicKey").and_then(Value::as_str).unwrap_or("");
            if pub_key_str.is_empty() {
                continue;
            }
            let public_key = KeyMaterial::parse(pub_key_str)
                .map_err(|_| "failed to deserialize key".to_string())?;

            let psk_str = p.get("preSharedKey").and_then(Value::as_str).unwrap_or("");
            let preshared_key = if !psk_str.is_empty() {
                Some(
                    KeyMaterial::parse(psk_str)
                        .map_err(|_| "failed to deserialize key".to_string())?,
                )
            } else {
                None
            };

            let allowed_ips = match p.get("allowedIPs").and_then(Value::as_array) {
                Some(ips) => {
                    let mut out = Vec::new();
                    for ip in ips {
                        let s = ip.as_str().unwrap_or("");
                        out.push(
                            s.parse::<AllowedIp>()
                                .map_err(|_| format!("invalid WireGuard allowedIPs entry {s:?}"))?,
                        );
                    }
                    out
                }
                None => vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            };

            let keepalive = u16::try_from(p.get("keepAlive").and_then(Value::as_u64).unwrap_or(0))
                .map_err(|_| "WireGuard keepAlive is out of range".to_string())?;

            peers.push(ServerPeerConfig {
                public_key,
                preshared_key,
                endpoint: None,
                allowed_ips,
                keepalive,
                email: p
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                level: p.get("level").and_then(Value::as_u64).unwrap_or(0) as u32,
            });
        }
    }

    let mtu = settings.get("mtu").and_then(Value::as_u64).unwrap_or(1420) as u16;
    let mtu = if (1280..=1420).contains(&mtu) {
        mtu
    } else {
        1420
    };

    let mut reserved = [0u8; 3];
    if let Some(res_arr) = settings.get("reserved").and_then(Value::as_array) {
        if res_arr.len() == 3 {
            for (i, v) in res_arr.iter().enumerate() {
                reserved[i] = v
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| "\"reserved\" bytes must be in 0..=255".to_string())?;
            }
        } else if !res_arr.is_empty() {
            return Err("\"reserved\" should be empty or 3 bytes".into());
        }
    }

    let listen = item.get("listen").and_then(Value::as_str).unwrap_or("");
    let port = u16::try_from(item.get("port").and_then(Value::as_u64).unwrap_or(0))
        .map_err(|_| format!("inbound {tag:?}: port is out of range"))?;
    let listen_ip = if listen.is_empty() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        listen
            .parse()
            .map_err(|e| format!("inbound {tag:?}: invalid listen address: {e}"))?
    };
    let listen_addr = SocketAddr::new(listen_ip, port);

    Ok(ServerConfig {
        secret_key,
        peers,
        addresses,
        listen_addr,
        mtu,
        reserved,
    })
}

/// Xray's server-side user lookup: the first configured peer whose
/// `allowedIPs` contains the traffic's source address.
struct PeerUser {
    allowed_ips: Vec<AllowedIp>,
    email: String,
    level: u32,
}

fn peer_users(config: &ServerConfig) -> Vec<PeerUser> {
    config
        .peers
        .iter()
        .map(|peer| PeerUser {
            allowed_ips: peer.allowed_ips.clone(),
            email: peer.email.clone(),
            level: peer.level,
        })
        .collect()
}

fn user_for_source(peers: &[PeerUser], source: IpAddr) -> (&str, u32) {
    peers
        .iter()
        .find(|peer| peer.allowed_ips.iter().any(|range| range.contains(source)))
        .map_or(("", 0), |peer| (peer.email.as_str(), peer.level))
}

pub async fn start(
    inbound: &Inbound,
    ctx: Arc<crate::vless::Context>,
    router: Arc<Router>,
) -> Result<tokio::task::AbortHandle, String> {
    let config = inbound
        .wireguard
        .as_ref()
        .ok_or_else(|| "missing wireguard settings".to_string())?;

    let server = Server::start((**config).clone())
        .await
        .map_err(|e| format!("failed to start wireguard server: {e}"))?;

    crate::log::info!(
        "listening {} (wireguard) on {}",
        inbound.tag,
        config.listen_addr
    );

    let users: Arc<Vec<PeerUser>> = Arc::new(peer_users(config));

    let server = Arc::new(server);
    let server_run = server.clone();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(tcp) = server_run.accept_tcp() => {
                    let ctx = ctx.clone();
                    let router = router.clone();
                    let users = users.clone();
                    tokio::spawn(async move {
                        handle_tcp(tcp, ctx, router, users).await;
                    });
                }
                Some(udp) = server_run.accept_udp() => {
                    let ctx = ctx.clone();
                    let router = router.clone();
                    let users = users.clone();
                    tokio::spawn(async move {
                        Box::pin(handle_udp(udp, ctx, router, users)).await;
                    });
                }
                else => break,
            }
        }
    });

    Ok(task.abort_handle())
}

async fn handle_tcp(
    tcp: IncomingTcpStream,
    ctx: Arc<crate::vless::Context>,
    router: Arc<Router>,
    users: Arc<Vec<PeerUser>>,
) {
    let (user, level) = user_for_source(&users, tcp.src.ip());
    let query = Query {
        inbound: &ctx.tag,
        inbound_port: ctx.port,
        user,
        source: tcp.src,
        network: Network::Tcp,
        domain: None,
        ip: Some(tcp.dst.ip()),
        port: tcp.dst.port(),
        protocol: None,
        attributes: None,
        local_ip: None,
        vless_route: None,
        process_info: None,
    };
    let decision = router.route(&query).await;
    // Xray's dispatcher logs a routed session as accepted, blackhole or not.
    let accepted = true;
    log::access(
        tcp.src,
        "tcp",
        accepted,
        format!("tcp:{}:{}", tcp.dst.ip(), tcp.dst.port()),
        &ctx.tag,
        &decision.tag,
        decision.detour.separator(),
        user,
    );
    if !accepted {
        return;
    }
    let host = Host::Ip(tcp.dst.ip());
    let target_stream = match outbound::connect(&router, &decision, &host, tcp.dst.port()).await {
        Ok(s) => s,
        Err(e) => {
            crate::log::warn!("wireguard tcp connect {}: {e}", tcp.dst);
            return;
        }
    };
    let traffic = stats::get().traffic(&ctx.tag, user, level, &decision.tag);
    let policy = crate::policy::for_level(level);
    let (mut client_r, mut client_w) = tokio::io::split(tcp.stream);
    let (mut target_r, mut target_w) = tokio::io::split(target_stream);
    let activity = Activity::new();
    let _ = relay_policy(
        copy_buf(
            &mut client_r,
            &mut target_w,
            &activity,
            |n| traffic.up(n),
            policy.buffer_size,
        ),
        copy_buf(
            &mut target_r,
            &mut client_w,
            &activity,
            |n| traffic.down(n),
            policy.buffer_size,
        ),
        &activity,
        policy,
    )
    .await;
}

async fn handle_udp(
    mut udp: IncomingUdpSession,
    ctx: Arc<crate::vless::Context>,
    router: Arc<Router>,
    users: Arc<Vec<PeerUser>>,
) {
    let (user, level) = user_for_source(&users, udp.src.ip());
    let query = Query {
        inbound: &ctx.tag,
        inbound_port: ctx.port,
        user,
        source: udp.src,
        network: Network::Udp,
        domain: None,
        ip: Some(udp.dst.ip()),
        port: udp.dst.port(),
        protocol: None,
        attributes: None,
        local_ip: None,
        vless_route: None,
        process_info: None,
    };
    let decision = router.route(&query).await;
    // Xray's dispatcher logs a routed session as accepted, blackhole or not.
    let accepted = true;
    log::access(
        udp.src,
        "udp",
        accepted,
        format!("udp:{}:{}", udp.dst.ip(), udp.dst.port()),
        &ctx.tag,
        &decision.tag,
        decision.detour.separator(),
        user,
    );
    if !accepted {
        return;
    }
    let cone = match ConeUdp::open(router.clone(), &decision).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            crate::log::warn!("wireguard udp open {}: {e}", udp.dst);
            return;
        }
    };
    let traffic = stats::get().traffic(&ctx.tag, user, level, &decision.tag);
    let activity = Activity::new();
    let host = Host::Ip(udp.dst.ip());
    let port = udp.dst.port();

    if let Ok(addr) = cone.target(&host, port).await {
        let _ = cone.send_to(&udp.first_packet, addr).await;
        traffic.up(udp.first_packet.len());
    }

    let up = {
        let host = host.clone();
        let cone = cone.clone();
        let activity = &activity;
        let traffic = traffic.clone();
        async move {
            while let Some(packet) = udp.rx.recv().await {
                activity.touch();
                if let Ok(addr) = cone.target(&host, port).await {
                    let _ = cone.send_to(&packet, addr).await;
                    traffic.up(packet.len());
                }
            }
            Ok(())
        }
    };

    let down = {
        let cone = cone.clone();
        let response_tx = udp.response_tx;
        let src = udp.src;
        let dst = udp.dst;
        let activity = &activity;
        let traffic = traffic.clone();
        async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, _from) = cone.recv_from(&mut buf).await?;
                activity.touch();
                let _ = response_tx.send((dst, src, buf[..n].to_vec())).await;
                traffic.down(n);
            }
        }
    };

    let policy = crate::policy::for_level(level);
    let _ = Box::pin(relay_policy(up, down, &activity, policy)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn item(settings: Value) -> Value {
        let mut s = json!({"secretKey": KEY});
        s.as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        json!({"port": 51820, "settings": s})
    }

    #[test]
    fn invalid_allowed_ips_and_address_are_rejected() {
        let peer = |ips: Value| json!({"peers": [{"publicKey": KEY, "allowedIPs": ips}]});
        assert!(parse("t", &item(peer(json!(["10.0.0.5/33"])))).is_err());
        assert!(parse("t", &item(peer(json!(["10.0.0.5"])))).is_err());
        let ok = parse("t", &item(peer(json!([])))).unwrap();
        assert!(ok.peers[0].allowed_ips.is_empty());
        assert!(parse("t", &item(json!({"address": ["garbage"]}))).is_err());
        assert_eq!(parse("t", &item(json!({}))).unwrap().addresses.len(), 2);
    }

    #[test]
    fn peer_identity_follows_allowed_ips() {
        let cfg = parse(
            "t",
            &item(json!({"peers": [
                {"publicKey": KEY, "allowedIPs": ["10.0.0.5/32"], "email": "alice", "level": 2},
                {"publicKey": KEY, "allowedIPs": ["10.0.0.0/24"], "email": "bob", "level": 3}
            ]})),
        )
        .unwrap();
        assert_eq!(cfg.peers[0].email, "alice");
        assert_eq!(cfg.peers[0].level, 2);
        let users = peer_users(&cfg);
        assert_eq!(
            user_for_source(&users, "10.0.0.5".parse().unwrap()),
            ("alice", 2)
        );
        assert_eq!(
            user_for_source(&users, "10.0.0.9".parse().unwrap()),
            ("bob", 3)
        );
        assert_eq!(
            user_for_source(&users, "192.0.2.1".parse().unwrap()),
            ("", 0)
        );
    }

    #[test]
    fn out_of_range_numbers_are_rejected() {
        let ka = json!({"peers": [{"publicKey": KEY, "keepAlive": 65537}]});
        assert!(parse("t", &item(ka)).is_err());
        assert!(parse("t", &item(json!({"reserved": [1, 2, 300]}))).is_err());
    }
}
