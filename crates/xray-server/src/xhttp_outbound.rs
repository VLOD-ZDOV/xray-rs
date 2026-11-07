//! XHTTP for outbounds: the outbound's `streamSettings` go through the upstream config parser and
//! become the upstream XHTTP client, supporting standard XHTTP, HTTP/3, and split downloadSettings.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xray_config::{
    QuicCongestion, QuicParamsSettings, StreamSecurity, StreamTransport, UdpNoiseSettings,
    XhttpSettings,
};
use xray_transport::stream::{
    H3Congestion, H3QuicConfig, H3UdpHopConfig, HeaderMap, TransportLayer, XhttpConfig,
    XhttpConfigInput, XhttpEndpoint, XhttpHttpVersion, XhttpMetadataPlacement, XhttpModeSelection,
    XhttpPaddingMethod, XhttpPaddingPlacement, XhttpRange, XhttpScheme, XhttpTransport,
    XhttpUplinkDataPlacement, XhttpXmuxPolicy,
};
use xray_transport::udp_noise::{NoiseRange, UdpNoiseConfig, UdpNoiseItem};
use xray_transport::ConnectorConfig;

use crate::vless::Host;

/// An independently addressed and configured XHTTP download leg.
#[derive(Clone, Debug)]
pub struct XhttpDownloadTarget {
    pub server: (Host, u16),
    pub connector: ConnectorConfig,
    pub transport: XhttpTransport,
}

/// `authority` is the fallback host: the TLS or REALITY server name, else the server address.
pub fn transport(
    stream: &Value,
    authority: &str,
) -> Result<(TransportLayer, Option<Arc<XhttpDownloadTarget>>), String> {
    let mut xhttp_settings = stream
        .get("xhttpSettings")
        .or_else(|| stream.get("splithttpSettings"))
        .cloned()
        .unwrap_or(json!({}));
    if let Some(ds) = xhttp_settings
        .get_mut("downloadSettings")
        .and_then(Value::as_object_mut)
    {
        if !ds.contains_key("network") && !ds.contains_key("method") {
            ds.insert("network".to_string(), json!("xhttp"));
        }
        if let Some(tls) = ds.get_mut("tlsSettings").and_then(Value::as_object_mut) {
            tls.remove("certificates");
        }
    } else if let Some(extra) = xhttp_settings
        .get_mut("extra")
        .and_then(Value::as_object_mut)
    {
        if let Some(ds) = extra
            .get_mut("downloadSettings")
            .and_then(Value::as_object_mut)
        {
            if !ds.contains_key("network") && !ds.contains_key("method") {
                ds.insert("network".to_string(), json!("xhttp"));
            }
            if let Some(tls) = ds.get_mut("tlsSettings").and_then(Value::as_object_mut) {
                tls.remove("certificates");
            }
        }
    }

    let mut synth_stream = json!({
        "network": "xhttp",
        "xhttpSettings": xhttp_settings,
    });
    if let Some(fm) = stream.get("finalmask") {
        synth_stream["finalmask"] = fm.clone();
    }
    if let Some(qp) = stream.get("quicParams") {
        synth_stream["quicParams"] = qp.clone();
    }

    let synth = json!({"outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
            "users": [{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}]}]},
        "streamSettings": synth_stream,
    }]});
    let parsed = xray_config::parse_xray_json(&synth.to_string()).map_err(|e| {
        let messages: Vec<String> = e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
        format!("xhttpSettings: {}", messages.join("; "))
    })?;
    let parsed_stream = &parsed.config.outbounds[0].stream;
    let StreamTransport::Xhttp(settings) = &parsed_stream.transport else {
        return Err("streamSettings.network is not xhttp".to_owned());
    };

    let security = stream
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let alpn: Vec<&str> = stream
        .get("tlsSettings")
        .and_then(|tls| tls.get("alpn"))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let is_reality = security == "reality";
    let http_version = match security {
        "tls" => match alpn.as_slice() {
            ["http/1.1"] => XhttpHttpVersion::Http1,
            ["h3"] => XhttpHttpVersion::Http3,
            _ => XhttpHttpVersion::Http2,
        },
        "reality" => XhttpHttpVersion::Http2,
        _ => XhttpHttpVersion::Http1,
    };

    let mut h3_quic = if http_version == XhttpHttpVersion::Http3 {
        xhttp_h3_quic_config(parsed_stream.quic_params.as_ref())?
    } else {
        H3QuicConfig::default()
    };
    if parsed_stream.udp_noise.is_some() && http_version != XhttpHttpVersion::Http3 {
        return Err("UDP noise requires XHTTP H3".to_owned());
    }
    h3_quic.udp_noise = parsed_stream
        .udp_noise
        .as_ref()
        .map(udp_noise_config)
        .transpose()?;

    let scheme = match security {
        "tls" | "reality" => XhttpScheme::Https,
        _ => XhttpScheme::Http,
    };
    let authority = settings
        .host
        .as_deref()
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| match authority.parse::<Ipv6Addr>() {
            Ok(ip) => format!("[{ip}]"),
            Err(_) => authority.to_owned(),
        });
    let endpoint = XhttpEndpoint::new(scheme, authority).map_err(|e| e.to_string())?;
    let upload_transport = XhttpTransport::new_with_h3_quic(
        config(settings, is_reality, settings.download.is_some())?,
        endpoint,
        http_version,
        xmux(settings),
        h3_quic,
    )
    .map_err(|e| e.to_string())?;

    let download_target = if let Some(down) = &settings.download {
        let StreamTransport::Xhttp(down_settings) = &down.stream.transport else {
            return Err("downloadSettings requires XHTTP".to_owned());
        };
        if down_settings.download.is_some()
            || settings.mode == xray_config::XhttpMode::StreamOne
            || down.port == 0
            || down.stream.network != xray_config::Network::Tcp
        {
            return Err("invalid nested downloadSettings or stream-one combination".to_owned());
        }
        let is_protected_upload = matches!(security, "tls" | "reality");
        if is_protected_upload && down.stream.security == StreamSecurity::None {
            return Err("protected upload cannot use plaintext download".to_owned());
        }

        let down_host = match &down.address {
            xray_config::TargetAddr::Ip(ip) => Host::Ip(*ip),
            xray_config::TargetAddr::Domain(domain) if !domain.is_empty() => {
                Host::Domain(domain.clone())
            }
            _ => return Err("downloadSettings requires a non-empty address".to_owned()),
        };
        let down_port = down.port;

        let xhttp_val = stream
            .get("xhttpSettings")
            .or_else(|| stream.get("splithttpSettings"));
        let down_val = xhttp_val.and_then(|x| {
            x.get("downloadSettings")
                .or_else(|| x.get("extra").and_then(|e| e.get("downloadSettings")))
        });

        let down_security = down_val
            .and_then(|v| v.get("security"))
            .and_then(Value::as_str)
            .unwrap_or(match &down.stream.security {
                StreamSecurity::None => "none",
                StreamSecurity::Tls(_) => "tls",
                StreamSecurity::Reality(_) => "reality",
            });
        let down_connector = match down_security {
            "" | "none" => ConnectorConfig::Tcp,
            "tls" => {
                let tls_val = down_val
                    .and_then(|v| v.get("tlsSettings"))
                    .unwrap_or(&Value::Null);
                crate::outbound_transport::parse_tls(tls_val, &down_host)?
            }
            "reality" => {
                let reality_val = down_val
                    .and_then(|v| v.get("realitySettings"))
                    .unwrap_or(&Value::Null);
                crate::outbound_transport::parse_reality(reality_val, &down_host)?
            }
            other => return Err(format!("downloadSettings: unsupported security {other:?}")),
        };

        let down_alpn: Vec<&str> = down_val
            .and_then(|v| v.get("tlsSettings"))
            .and_then(|t| t.get("alpn"))
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).collect())
            .unwrap_or_else(|| match &down.stream.security {
                StreamSecurity::Tls(t) => t.alpn.iter().map(String::as_str).collect(),
                _ => Vec::new(),
            });
        let is_down_reality = down_security == "reality";
        let down_http_version = match down_security {
            "tls" => match down_alpn.as_slice() {
                ["http/1.1"] => XhttpHttpVersion::Http1,
                ["h3"] => XhttpHttpVersion::Http3,
                _ => XhttpHttpVersion::Http2,
            },
            "reality" => XhttpHttpVersion::Http2,
            _ => XhttpHttpVersion::Http1,
        };

        let mut down_h3_quic = if down_http_version == XhttpHttpVersion::Http3 {
            xhttp_h3_quic_config(down.stream.quic_params.as_ref())?
        } else {
            H3QuicConfig::default()
        };
        if down.stream.udp_noise.is_some() && down_http_version != XhttpHttpVersion::Http3 {
            return Err("UDP noise requires XHTTP H3".to_owned());
        }
        down_h3_quic.udp_noise = down
            .stream
            .udp_noise
            .as_ref()
            .map(udp_noise_config)
            .transpose()?;

        let down_scheme = match down_security {
            "tls" | "reality" => XhttpScheme::Https,
            _ => XhttpScheme::Http,
        };
        let down_authority = down_settings
            .host
            .as_deref()
            .filter(|host| !host.is_empty())
            .or(match &down_connector {
                ConnectorConfig::Tls(t) if !t.server_name.is_empty() => {
                    Some(t.server_name.as_str())
                }
                ConnectorConfig::Reality(r) if !r.server_name.is_empty() => {
                    Some(r.server_name.as_str())
                }
                _ => None,
            })
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| match &down.address {
                xray_config::TargetAddr::Domain(domain) => domain.clone(),
                xray_config::TargetAddr::Ip(ip) => match ip.to_canonical() {
                    IpAddr::V4(address) => address.to_string(),
                    IpAddr::V6(address) => format!("[{address}]"),
                },
            });
        let down_endpoint =
            XhttpEndpoint::new(down_scheme, down_authority).map_err(|e| e.to_string())?;
        let down_transport = XhttpTransport::new_with_h3_quic(
            config(down_settings, is_down_reality, false)?,
            down_endpoint,
            down_http_version,
            xmux(down_settings),
            down_h3_quic,
        )
        .map_err(|e| e.to_string())?;

        Some(Arc::new(XhttpDownloadTarget {
            server: (down_host, down_port),
            connector: down_connector,
            transport: down_transport,
        }))
    } else {
        None
    };

    Ok((TransportLayer::Xhttp(upload_transport), download_target))
}

const QUIC_VARINT_MAX: u64 = (1_u64 << 62) - 1;

fn quic_u64_or_default(name: &'static str, value: u64, default: u64) -> Result<u64, String> {
    if value == 0 {
        Ok(default)
    } else {
        quic_varint(name, value)
    }
}

fn quic_optional_u64(name: &'static str, value: u64) -> Result<Option<u64>, String> {
    if value == 0 {
        Ok(None)
    } else {
        quic_varint(name, value).map(Some)
    }
}

fn quic_varint(name: &'static str, value: u64) -> Result<u64, String> {
    if value <= QUIC_VARINT_MAX {
        Ok(value)
    } else {
        Err(format!(
            "finalmask.quicParams.{name}={value} exceeds QUIC's 62-bit varint limit"
        ))
    }
}

fn quic_incoming_streams_or_default(
    name: &'static str,
    value: i64,
    default: u64,
) -> Result<u64, String> {
    if value == 0 {
        return Ok(default);
    }
    let value = u64::try_from(value)
        .map_err(|_| format!("finalmask.quicParams.{name}={value} cannot be negative"))?;
    Ok(value.min(QUIC_VARINT_MAX))
}

fn quic_i32_seconds(name: &'static str, value: i32) -> Result<Duration, String> {
    if value >= 0 {
        Ok(Duration::from_secs(value as u64))
    } else {
        Err(format!("finalmask.quicParams.{name} cannot be negative"))
    }
}

fn udp_hop_config(
    hop: &xray_config::QuicUdpHopSettings,
    interval_min: Duration,
    interval_max: Duration,
) -> H3UdpHopConfig {
    H3UdpHopConfig {
        ports: hop.ports.clone(),
        interval_min,
        interval_max,
        local: hop.local,
        remote: hop.remote,
        remote_once: hop.remote_once,
        remote_ips: hop
            .remote_ips
            .iter()
            .map(|cidr| (cidr.network(), cidr.prefix()))
            .collect(),
    }
}

const fn bbr_congestion(profile: xray_config::QuicBbrProfile) -> H3Congestion {
    match profile {
        xray_config::QuicBbrProfile::Conservative => H3Congestion::BbrConservative,
        xray_config::QuicBbrProfile::Standard => H3Congestion::BbrStandard,
        xray_config::QuicBbrProfile::Aggressive => H3Congestion::BbrAggressive,
    }
}

pub fn xhttp_h3_quic_config(settings: Option<&QuicParamsSettings>) -> Result<H3QuicConfig, String> {
    let Some(settings) = settings else {
        return Ok(H3QuicConfig::default());
    };
    let mut config = H3QuicConfig::default();
    config.initial_stream_receive_window = quic_u64_or_default(
        "initStreamReceiveWindow",
        settings.init_stream_receive_window,
        config.initial_stream_receive_window,
    )?;
    config.max_stream_receive_window =
        quic_optional_u64("maxStreamReceiveWindow", settings.max_stream_receive_window)?;
    config.initial_connection_receive_window = quic_u64_or_default(
        "initConnectionReceiveWindow",
        settings.init_connection_receive_window,
        config.initial_connection_receive_window,
    )?;
    config.max_connection_receive_window = quic_optional_u64(
        "maxConnectionReceiveWindow",
        settings.max_connection_receive_window,
    )?;
    match settings.max_idle_timeout_secs {
        0 => {}
        value if value > 0 => {
            config.max_idle_timeout = Duration::from_secs(
                u64::try_from(value)
                    .map_err(|_| "finalmask.quicParams.maxIdleTimeout is negative".to_owned())?,
            );
        }
        _ => {
            return Err("finalmask.quicParams.maxIdleTimeout is negative".to_owned());
        }
    }
    config.keep_alive_interval = match settings.keep_alive_period_secs {
        0 => None,
        value if value > 0 => {
            Some(Duration::from_secs(u64::try_from(value).map_err(|_| {
                "finalmask.quicParams.keepAlivePeriod is negative".to_owned()
            })?))
        }
        _ => {
            return Err("finalmask.quicParams.keepAlivePeriod is negative".to_owned());
        }
    };
    config.max_incoming_bidirectional_streams = quic_incoming_streams_or_default(
        "maxIncomingStreams",
        settings.max_incoming_streams,
        config.max_incoming_bidirectional_streams,
    )?;
    config.disable_path_mtu_discovery = settings.disable_path_mtu_discovery
        || !cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        ));
    config.disable_gso = settings.disable_gso;
    config.congestion = match settings.congestion {
        QuicCongestion::Reno => H3Congestion::Reno,
        QuicCongestion::Brutal => H3Congestion::Brutal {
            up_bytes_per_second: settings.brutal_up_bytes_per_sec,
        },
        QuicCongestion::ForceBrutal => H3Congestion::ForceBrutal {
            bytes_per_second: settings.brutal_up_bytes_per_sec,
        },
        QuicCongestion::Default | QuicCongestion::Bbr => bbr_congestion(settings.bbr_profile),
    };
    config.brutal_disable_loss_compensation = settings.brutal_disable_loss_compensation;
    config.udp_hop = udp_hop_config(
        &settings.udp_hop,
        quic_i32_seconds("udpHop.interval.from", settings.udp_hop.interval.from)?,
        quic_i32_seconds("udpHop.interval.to", settings.udp_hop.interval.to)?,
    );
    config.debug = settings.debug;
    Ok(config)
}

pub fn udp_noise_config(noise: &UdpNoiseSettings) -> Result<UdpNoiseConfig, String> {
    let range = |r: xray_config::FragmentRange| NoiseRange {
        from: r.from,
        to: r.to,
    };
    let config = UdpNoiseConfig {
        reset_secs: range(noise.reset_secs),
        before_salamander: noise.before_salamander,
        items: noise
            .items
            .iter()
            .map(|i| UdpNoiseItem {
                packet: i.packet.clone(),
                random_length: range(i.random_length),
                random_bytes: range(i.random_bytes),
                delay_ms: range(i.delay_ms),
            })
            .collect(),
    };
    config.validate().map_err(|e| e.to_string())?;
    Ok(config)
}

fn config(
    settings: &XhttpSettings,
    is_reality: bool,
    has_download: bool,
) -> Result<XhttpConfig, String> {
    let mut headers = HeaderMap::new();
    for (name, value) in &settings.headers {
        // Xray adds each pair with http.Header.Add, so keys differing only by case keep both values.
        headers.add(name, value);
    }
    XhttpConfig::normalize(XhttpConfigInput {
        h2_stream_receive_window: settings.h2_stream_receive_window,
        mode: if is_reality && has_download && settings.mode == xray_config::XhttpMode::Auto {
            XhttpModeSelection::StreamUp
        } else {
            match settings.mode {
                xray_config::XhttpMode::Auto => XhttpModeSelection::Auto,
                xray_config::XhttpMode::PacketUp => XhttpModeSelection::PacketUp,
                xray_config::XhttpMode::StreamUp => XhttpModeSelection::StreamUp,
                xray_config::XhttpMode::StreamOne => XhttpModeSelection::StreamOne,
            }
        },
        is_reality,
        path: settings.path.clone(),
        headers,
        x_padding_bytes: range(settings.x_padding_bytes),
        x_padding_obfs_mode: settings.x_padding_obfs_mode,
        x_padding_key: settings.x_padding_key.clone(),
        x_padding_header: settings.x_padding_header.clone(),
        x_padding_placement: match settings.x_padding_placement {
            xray_config::XhttpPaddingPlacement::Cookie => XhttpPaddingPlacement::Cookie,
            xray_config::XhttpPaddingPlacement::Header => XhttpPaddingPlacement::Header,
            xray_config::XhttpPaddingPlacement::Query => XhttpPaddingPlacement::Query,
            xray_config::XhttpPaddingPlacement::QueryInHeader => {
                XhttpPaddingPlacement::QueryInHeader
            }
        },
        x_padding_method: match settings.x_padding_method {
            xray_config::XhttpPaddingMethod::RepeatX => XhttpPaddingMethod::RepeatX,
            xray_config::XhttpPaddingMethod::Tokenish => XhttpPaddingMethod::Tokenish,
        },
        uplink_http_method: settings.uplink_http_method.clone(),
        session_placement: placement(settings.session_placement),
        session_key: settings.session_key.clone(),
        session_id_table: settings.session_id_table.clone(),
        session_id_length: range(settings.session_id_length),
        seq_placement: placement(settings.seq_placement),
        seq_key: settings.seq_key.clone(),
        uplink_data_placement: match settings.uplink_data_placement {
            xray_config::XhttpUplinkDataPlacement::Auto => XhttpUplinkDataPlacement::Auto,
            xray_config::XhttpUplinkDataPlacement::Body => XhttpUplinkDataPlacement::Body,
            xray_config::XhttpUplinkDataPlacement::Cookie => XhttpUplinkDataPlacement::Cookie,
            xray_config::XhttpUplinkDataPlacement::Header => XhttpUplinkDataPlacement::Header,
        },
        uplink_data_key: settings.uplink_data_key.clone(),
        uplink_chunk_size: range(settings.uplink_chunk_size),
        no_grpc_header: settings.no_grpc_header,
        sc_max_each_post_bytes: range(settings.sc_max_each_post_bytes),
        sc_min_posts_interval_ms: range(settings.sc_min_posts_interval_ms),
        sc_max_buffered_posts: settings.sc_max_buffered_posts,
        sc_stream_up_server_secs: range(settings.sc_stream_up_server_secs),
    })
    .map_err(|e| e.to_string())
}

fn xmux(settings: &XhttpSettings) -> XhttpXmuxPolicy {
    XhttpXmuxPolicy {
        max_concurrency: range(settings.xmux.max_concurrency),
        max_connections: range(settings.xmux.max_connections),
        c_max_reuse_times: range(settings.xmux.c_max_reuse_times),
        h_max_request_times: range(settings.xmux.h_max_request_times),
        h_max_reusable_secs: range(settings.xmux.h_max_reusable_secs),
        h_keep_alive_period_secs: settings.xmux.h_keep_alive_period_secs,
    }
}

const fn range(range: xray_config::XhttpRange) -> XhttpRange {
    XhttpRange {
        from: range.from,
        to: range.to,
    }
}

const fn placement(placement: xray_config::XhttpPlacement) -> XhttpMetadataPlacement {
    match placement {
        xray_config::XhttpPlacement::Path => XhttpMetadataPlacement::Path,
        xray_config::XhttpPlacement::Cookie => XhttpMetadataPlacement::Cookie,
        xray_config::XhttpPlacement::Header => XhttpMetadataPlacement::Header,
        xray_config::XhttpPlacement::Query => XhttpMetadataPlacement::Query,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xhttp_outbound_h3() {
        let stream = json!({
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "example.com",
                "alpn": ["h3"]
            },
            "xhttpSettings": {
                "path": "/xhttp-h3"
            }
        });
        let (layer, down) = transport(&stream, "example.com").unwrap();
        assert!(down.is_none());
        let TransportLayer::Xhttp(t) = layer else {
            panic!("expected Xhttp layer");
        };
        assert_eq!(t.http_version(), XhttpHttpVersion::Http3);
    }

    #[test]
    fn test_xhttp_outbound_download_settings() {
        let stream = json!({
            "network": "xhttp",
            "security": "tls",
            "sockopt": {
                "penetrate": true,
                "mark": 42
            },
            "tlsSettings": {
                "serverName": "example.com",
                "alpn": ["h2"]
            },
            "xhttpSettings": {
                "path": "/up",
                "mode": "packet-up",
                "downloadSettings": {
                    "address": "down.example.com",
                    "port": 8443,
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "down.example.com",
                        "alpn": ["h3"]
                    },
                    "xhttpSettings": {
                        "path": "/down"
                    }
                }
            }
        });
        let (layer, down) = transport(&stream, "example.com").unwrap();
        let TransportLayer::Xhttp(up) = layer else {
            panic!("expected Xhttp layer");
        };
        assert_eq!(up.http_version(), XhttpHttpVersion::Http2);

        let down = down.expect("expected download target");
        assert_eq!(down.server.1, 8443);
        match &down.server.0 {
            Host::Domain(d) => assert_eq!(d, "down.example.com"),
            _ => panic!("expected domain"),
        }
        assert_eq!(down.transport.http_version(), XhttpHttpVersion::Http3);
    }

    #[test]
    fn test_xhttp_outbound_rejects_stream_one_with_download() {
        let stream = json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "/up",
                "mode": "stream-one",
                "downloadSettings": {
                    "address": "127.0.0.1",
                    "port": 8443,
                    "xhttpSettings": {
                        "path": "/down"
                    }
                }
            }
        });
        let err = transport(&stream, "127.0.0.1").unwrap_err();
        assert!(err.contains("stream-one"), "unexpected error: {err}");
    }
}
