//! WireGuard server inbound over userspace smoltcp stack in xray-wireguard.

use crate::config::Inbound;
use crate::log;
use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, Query, Router};
use crate::stats;
use crate::vless::{copy, relay, Activity, Host};
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
    if let Some(addrs) = settings.get("address").and_then(Value::as_array) {
        for a in addrs {
            if let Some(s) = a.as_str() {
                let ip_str = s.split('/').next().unwrap_or(s);
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    addresses.push(ip);
                }
            }
        }
    }
    if addresses.is_empty() {
        addresses = vec!["10.0.0.1".parse().unwrap()];
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

            let mut allowed_ips = Vec::new();
            if let Some(ips) = p.get("allowedIPs").and_then(Value::as_array) {
                for ip in ips {
                    if let Some(s) = ip.as_str() {
                        if let Ok(a) = s.parse::<AllowedIp>() {
                            allowed_ips.push(a);
                        }
                    }
                }
            }
            if allowed_ips.is_empty() {
                allowed_ips = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
            }

            let keepalive = p.get("keepAlive").and_then(Value::as_u64).unwrap_or(0) as u16;

            peers.push(ServerPeerConfig {
                public_key,
                preshared_key,
                endpoint: None,
                allowed_ips,
                keepalive,
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
                reserved[i] = v.as_u64().unwrap_or(0) as u8;
            }
        } else if !res_arr.is_empty() {
            return Err("\"reserved\" should be empty or 3 bytes".into());
        }
    }

    let listen = item.get("listen").and_then(Value::as_str).unwrap_or("");
    let port = item.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
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

    log::info(format!(
        "listening {} (wireguard) on {}",
        inbound.tag, config.listen_addr
    ));

    let server = Arc::new(server);
    let server_run = server.clone();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(tcp) = server_run.accept_tcp() => {
                    let ctx = ctx.clone();
                    let router = router.clone();
                    tokio::spawn(async move {
                        handle_tcp(tcp, ctx, router).await;
                    });
                }
                Some(udp) = server_run.accept_udp() => {
                    let ctx = ctx.clone();
                    let router = router.clone();
                    tokio::spawn(async move {
                        Box::pin(handle_udp(udp, ctx, router)).await;
                    });
                }
                else => break,
            }
        }
    });

    Ok(task.abort_handle())
}

async fn handle_tcp(tcp: IncomingTcpStream, ctx: Arc<crate::vless::Context>, router: Arc<Router>) {
    let query = Query {
        inbound: &ctx.tag,
        inbound_port: ctx.port,
        user: "",
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
    let accepted = !matches!(decision.action, Action::Block(_));
    log::access(
        tcp.src,
        accepted,
        format!("tcp:{}:{}", tcp.dst.ip(), tcp.dst.port()),
        &ctx.tag,
        &decision.tag,
        "",
    );
    if !accepted {
        return;
    }
    let host = Host::Ip(tcp.dst.ip());
    let target_stream = match outbound::connect(&router, &decision, &host, tcp.dst.port()).await {
        Ok(s) => s,
        Err(e) => {
            log::warn(format!("wireguard tcp connect {}: {e}", tcp.dst));
            return;
        }
    };
    let traffic = stats::get().traffic(&ctx.tag, "", 0, &decision.tag);
    let (mut client_r, mut client_w) = tokio::io::split(tcp.stream);
    let (mut target_r, mut target_w) = tokio::io::split(target_stream);
    let activity = Activity::new();
    let _ = relay(
        copy(&mut client_r, &mut target_w, &activity, |n| traffic.up(n)),
        copy(&mut target_r, &mut client_w, &activity, |n| traffic.down(n)),
        &activity,
    )
    .await;
}

async fn handle_udp(
    mut udp: IncomingUdpSession,
    ctx: Arc<crate::vless::Context>,
    router: Arc<Router>,
) {
    let query = Query {
        inbound: &ctx.tag,
        inbound_port: ctx.port,
        user: "",
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
    let accepted = !matches!(decision.action, Action::Block(_));
    log::access(
        udp.src,
        accepted,
        format!("udp:{}:{}", udp.dst.ip(), udp.dst.port()),
        &ctx.tag,
        &decision.tag,
        "",
    );
    if !accepted {
        return;
    }
    let cone = match ConeUdp::open(router.clone(), &decision).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            log::warn(format!("wireguard udp open {}: {e}", udp.dst));
            return;
        }
    };
    let traffic = stats::get().traffic(&ctx.tag, "", 0, &decision.tag);
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

    let _ = Box::pin(relay(up, down, &activity)).await;
}
