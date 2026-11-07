//! XHTTP for outbounds: the outbound's `streamSettings` go through the upstream config parser and
//! become the upstream XHTTP client, as `xray-core-rs` builds it.

use std::net::Ipv6Addr;

use serde_json::{json, Value};
use xray_config::{StreamTransport, XhttpSettings};
use xray_transport::stream::{
    HeaderMap, TransportLayer, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpHttpVersion,
    XhttpMetadataPlacement, XhttpModeSelection, XhttpPaddingMethod, XhttpPaddingPlacement,
    XhttpRange, XhttpScheme, XhttpTransport, XhttpUplinkDataPlacement, XhttpXmuxPolicy,
};

/// `authority` is the fallback host: the TLS or REALITY server name, else the server address.
pub fn transport(stream: &Value, authority: &str) -> Result<TransportLayer, String> {
    let synth = json!({"outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
            "users": [{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}]}]},
        "streamSettings": {"network": "xhttp", "xhttpSettings": stream.get("xhttpSettings")
            .or_else(|| stream.get("splithttpSettings"))},
    }]});
    let parsed = xray_config::parse_xray_json(&synth.to_string()).map_err(|e| {
        let messages: Vec<String> = e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
        format!("xhttpSettings: {}", messages.join("; "))
    })?;
    let parsed_stream = &parsed.config.outbounds[0].stream;
    let StreamTransport::Xhttp(settings) = &parsed_stream.transport else {
        return Err("streamSettings.network is not xhttp".to_owned());
    };
    if settings.download.is_some() {
        return Err("xhttpSettings.downloadSettings is not supported yet".to_owned());
    }
    // Only xhttpSettings go to the upstream parser; security is read here as Xray's decideHTTPVersion does.
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
    if http_version == XhttpHttpVersion::Http3 {
        return Err("XHTTP over HTTP/3 is not supported yet for outbounds".to_owned());
    }
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
    XhttpTransport::new(
        config(settings, is_reality)?,
        endpoint,
        http_version,
        xmux(settings),
    )
    .map(TransportLayer::Xhttp)
    .map_err(|e| e.to_string())
}

fn config(settings: &XhttpSettings, is_reality: bool) -> Result<XhttpConfig, String> {
    let mut headers = HeaderMap::new();
    for (name, value) in &settings.headers {
        // Xray adds each pair with http.Header.Add, so keys differing only by case keep both values.
        headers.add(name, value);
    }
    XhttpConfig::normalize(XhttpConfigInput {
        h2_stream_receive_window: settings.h2_stream_receive_window,
        mode: match settings.mode {
            xray_config::XhttpMode::Auto => XhttpModeSelection::Auto,
            xray_config::XhttpMode::PacketUp => XhttpModeSelection::PacketUp,
            xray_config::XhttpMode::StreamUp => XhttpModeSelection::StreamUp,
            xray_config::XhttpMode::StreamOne => XhttpModeSelection::StreamOne,
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
