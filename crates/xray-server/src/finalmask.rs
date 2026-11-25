use std::ops::RangeInclusive;
use std::sync::Arc;

use serde_json::Value;
use xray_transport::TcpFragmentConfig;

use crate::routing::{
    parse_fragment, FreedomFragmentSetting, FreedomNoiseFamily, FreedomNoisePacket,
    FreedomNoiseSetting,
};

/// Parses `streamSettings.finalmask.tcp` to extract a TCP fragment configuration for proxy outbounds.
pub fn parse_finalmask_tcp_fragment(
    stream: &Value,
) -> Result<Option<Arc<TcpFragmentConfig>>, String> {
    let finalmask = match stream.get("finalmask") {
        Some(f) if !f.is_null() => f,
        _ => return Ok(None),
    };
    let tcp = match finalmask.get("tcp") {
        Some(t) if !t.is_null() => t,
        _ => return Ok(None),
    };
    let Some(arr) = tcp.as_array() else {
        return Err("streamSettings.finalmask.tcp must be an array or null".to_string());
    };
    // Xray-core keeps every fragment mask in the list and applies them in
    // order; the first is the head of the chain, the rest follow it.
    let mut fragments = Vec::new();
    for mask in arr {
        let mask_type = mask.get("type").and_then(Value::as_str).unwrap_or("");
        if mask_type.eq_ignore_ascii_case("fragment") {
            let settings = mask.get("settings").unwrap_or(&Value::Null);
            fragments.push(parse_tcp_fragment_settings(settings)?);
        }
    }
    match fragments.split_first() {
        None => Ok(None),
        Some((head, rest)) => head
            .as_ref()
            .clone()
            .with_chained(rest.iter().map(|arc| arc.as_ref().clone()).collect())
            .map(|config| Some(Arc::new(config)))
            .map_err(|e| format!("invalid fragment configuration: {e}")),
    }
}

/// Parses TCP fragment settings into `Arc<TcpFragmentConfig>`.
pub fn parse_tcp_fragment_settings(v: &Value) -> Result<Arc<TcpFragmentConfig>, String> {
    let length_val = v
        .get("lengths")
        .or_else(|| v.get("length"))
        .ok_or_else(|| "Length can't be empty".to_string())?;
    let mut lengths = parse_ranges_list(length_val)?;
    for r in &mut lengths {
        // As in Xray-core, a 0 length is legal in any entry but the last:
        // it emits an empty segment and moves to the next entry. It is not
        // clamped up to 1, which would change the wire pattern.
        let start = (*r.start()).min(16384);
        let end = (*r.end()).clamp(start, 16384);
        *r = start..=end;
    }

    let delay_val = v
        .get("delays")
        .or_else(|| v.get("delay"))
        .or_else(|| v.get("intervals"))
        .or_else(|| v.get("interval"))
        .ok_or_else(|| "Interval can't be empty".to_string())?;
    let mut delays = parse_ranges_list(delay_val)?;
    for r in &mut delays {
        let start = (*r.start()).min(1000);
        let end = (*r.end()).clamp(start, 1000);
        *r = start..=end;
    }

    let max_split = if let Some(ms) = v.get("maxSplit") {
        let (from, to) = parse_range_val(ms)?;
        let start = from.min(4096);
        let end = to.clamp(start, 4096);
        start..=end
    } else {
        0..=0
    };

    // `packets`, as Xray-core reads it: `tlshello`, empty or absent for
    // every write, or a write number / `from-to` range counting from one.
    let packets = match v.get("packets").and_then(Value::as_str) {
        None => xray_transport::FragmentPackets::AllWrites,
        Some(raw) => {
            let raw = raw.trim().to_ascii_lowercase();
            if raw.is_empty() {
                xray_transport::FragmentPackets::AllWrites
            } else if raw == "tlshello" {
                xray_transport::FragmentPackets::TlsHello
            } else {
                let (from, to) = parse_range_val(&Value::String(raw.clone()))
                    .map_err(|e| format!("invalid fragment packets {raw:?}: {e}"))?;
                if from == 0 {
                    return Err("PacketsFrom can't be 0".to_string());
                }
                xray_transport::FragmentPackets::Writes(u64::from(from)..=u64::from(to))
            }
        }
    };

    TcpFragmentConfig::new(lengths, delays, max_split)
        .and_then(|config| config.with_packets(packets))
        .map(Arc::new)
        .map_err(|e| format!("invalid fragment configuration: {e}"))
}

/// Parses `streamSettings.finalmask.tcp` fragment for Freedom outbound.
pub fn parse_freedom_fragment_from_finalmask(
    stream: &Value,
) -> Result<Option<FreedomFragmentSetting>, String> {
    let finalmask = match stream.get("finalmask") {
        Some(f) if !f.is_null() => f,
        _ => return Ok(None),
    };
    let tcp = match finalmask.get("tcp") {
        Some(t) if !t.is_null() => t,
        _ => return Ok(None),
    };
    let Some(arr) = tcp.as_array() else {
        return Err("streamSettings.finalmask.tcp must be an array or null".to_string());
    };
    for mask in arr {
        let mask_type = mask.get("type").and_then(Value::as_str).unwrap_or("");
        if mask_type.eq_ignore_ascii_case("fragment") {
            let settings = mask.get("settings").unwrap_or(&Value::Null);
            return parse_fragment(settings).map(Some);
        }
    }
    Ok(None)
}

/// Parses `streamSettings.finalmask.udp` to extract noise items for Freedom outbound.
pub fn parse_finalmask_udp_noises(stream: &Value) -> Result<Vec<FreedomNoiseSetting>, String> {
    let finalmask = match stream.get("finalmask") {
        Some(f) if !f.is_null() => f,
        _ => return Ok(Vec::new()),
    };
    let udp = match finalmask.get("udp") {
        Some(u) if !u.is_null() => u,
        _ => return Ok(Vec::new()),
    };
    let Some(arr) = udp.as_array() else {
        return Err("streamSettings.finalmask.udp must be an array or null".to_string());
    };
    let mut result = Vec::new();
    for mask in arr {
        let mask_type = mask.get("type").and_then(Value::as_str).unwrap_or("");
        if mask_type.eq_ignore_ascii_case("noise") {
            let settings = mask.get("settings").unwrap_or(&Value::Null);
            let items = settings
                .get("noise")
                .or_else(|| settings.get("noises"))
                .and_then(Value::as_array);
            if let Some(items) = items {
                for item in items {
                    let (min_delay, max_delay) = if let Some(d) = item.get("delay") {
                        parse_range_val(d)?
                    } else {
                        (0, 0)
                    };
                    let apply_to = match item
                        .get("applyTo")
                        .and_then(Value::as_str)
                        .unwrap_or("ip")
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "" | "ip" | "all" => FreedomNoiseFamily::Ip,
                        "ipv4" => FreedomNoiseFamily::Ipv4,
                        "ipv6" => FreedomNoiseFamily::Ipv6,
                        _ => {
                            return Err(
                                "Invalid applyTo, only ip/ipv4/ipv6 are supported".to_string()
                            )
                        }
                    };
                    let noise_type = item.get("type").and_then(Value::as_str).unwrap_or("");
                    let packet = if let Some(rand_val) = item.get("rand") {
                        let (min, max) = parse_range_val(rand_val)?;
                        if min == 0 {
                            return Err("rand lengthMin or lengthMax cannot be 0".to_string());
                        }
                        FreedomNoisePacket::Random(min as u64, max as u64)
                    } else if let Some(packet_val) = item.get("packet") {
                        let packet_str = packet_val.as_str().unwrap_or("");
                        match noise_type {
                            "rand" => {
                                let (min, max) = parse_range_val(packet_val)?;
                                if min == 0 {
                                    return Err(
                                        "rand lengthMin or lengthMax cannot be 0".to_string()
                                    );
                                }
                                FreedomNoisePacket::Random(min as u64, max as u64)
                            }
                            "hex" => {
                                let clean = packet_str.strip_prefix("0x").unwrap_or(packet_str);
                                let bytes = decode_hex(clean)
                                    .map_err(|_| "Invalid hex string".to_string())?;
                                FreedomNoisePacket::Bytes(bytes)
                            }
                            "base64" => {
                                use base64::Engine;
                                let clean = packet_str
                                    .replace('+', "-")
                                    .replace('/', "_")
                                    .replace('=', "");
                                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                    .decode(&clean)
                                    .or_else(|_| {
                                        base64::engine::general_purpose::STANDARD.decode(packet_str)
                                    })
                                    .map_err(|_| "Invalid base64 string".to_string())?;
                                FreedomNoisePacket::Bytes(bytes)
                            }
                            _ => FreedomNoisePacket::Bytes(packet_str.as_bytes().to_vec()),
                        }
                    } else {
                        continue;
                    };
                    result.push(FreedomNoiseSetting {
                        apply_to,
                        packet,
                        delay_ms: (min_delay as u64, max_delay as u64),
                    });
                }
            }
        }
    }
    Ok(result)
}

/// Validates `finalmask.quicParams` against official Xray bounds.
pub fn validate_finalmask_quic_params(stream: &Value, tag: &str) -> Result<(), String> {
    validate_quic_params_inner(stream, "outbound", tag)
}

/// Validates inbound `quicParams` against official Xray bounds.
pub fn validate_inbound_quic_params(stream: &Value, tag: &str) -> Result<(), String> {
    validate_quic_params_inner(stream, "inbound", tag)
}

fn validate_quic_params_inner(stream: &Value, kind: &str, tag: &str) -> Result<(), String> {
    let quic = match stream
        .pointer("/finalmask/quicParams")
        .or_else(|| stream.get("quicParams"))
    {
        Some(q) if !q.is_null() => q,
        _ => return Ok(()),
    };
    let Some(obj) = quic.as_object() else {
        return Err(format!("{kind} {tag:?}: quicParams must be an object"));
    };

    if let Some(congestion) = obj.get("congestion").and_then(Value::as_str) {
        let c = congestion.to_ascii_lowercase();
        if !matches!(c.as_str(), "" | "bbr" | "reno" | "brutal" | "force-brutal") {
            return Err(format!(
                "{kind} {tag:?}: unknown congestion control: {congestion}, valid values: reno, bbr, brutal, force-brutal"
            ));
        }
    }

    if let Some(bbr_profile) = obj.get("bbrProfile").and_then(Value::as_str) {
        let p = bbr_profile.to_ascii_lowercase();
        if !matches!(p.as_str(), "" | "conservative" | "standard" | "aggressive") {
            return Err(format!("{kind} {tag:?}: unknown bbr profile"));
        }
    }

    let check_bandwidth = |key: &str, field_name: &str| -> Result<Option<u64>, String> {
        if let Some(val) = obj.get(key).or_else(|| obj.get(field_name)) {
            let bps = if let Some(n) = val.as_u64() {
                n
            } else if let Some(s) = val.as_str() {
                parse_bandwidth_str(s)?
            } else {
                return Ok(None);
            };
            if bps > 0 && bps < 65536 {
                return Err(format!(
                    "{kind} {tag:?}: {field_name} must be at least 65536 bytes per second"
                ));
            }
            return Ok(Some(bps));
        }
        Ok(None)
    };

    let brutal_up = check_bandwidth("brutalUp", "BrutalUp")?.unwrap_or(0);
    let _brutal_down = check_bandwidth("brutalDown", "BrutalDown")?;

    if let Some(congestion) = obj
        .get("congestion")
        .or_else(|| obj.get("Congestion"))
        .and_then(Value::as_str)
    {
        if congestion.eq_ignore_ascii_case("force-brutal") && brutal_up == 0 {
            return Err(format!("{kind} {tag:?}: force-brutal requires up"));
        }
    }

    let check_window = |key: &str, field_name: &str| -> Result<(), String> {
        if let Some(w) = obj
            .get(key)
            .or_else(|| obj.get(field_name))
            .and_then(Value::as_u64)
        {
            if w > 0 && w < 16384 {
                return Err(format!(
                    "{kind} {tag:?}: {field_name} must be at least 16384"
                ));
            }
        }
        Ok(())
    };
    check_window("initStreamReceiveWindow", "InitStreamReceiveWindow")?;
    check_window("maxStreamReceiveWindow", "MaxStreamReceiveWindow")?;
    check_window("initConnectionReceiveWindow", "InitConnectionReceiveWindow")?;
    check_window("maxConnectionReceiveWindow", "MaxConnectionReceiveWindow")?;

    if let Some(timeout) = obj
        .get("maxIdleTimeout")
        .or_else(|| obj.get("MaxIdleTimeout"))
        .and_then(Value::as_i64)
    {
        if timeout != 0 && !(4..=120).contains(&timeout) {
            return Err(format!(
                "{kind} {tag:?}: MaxIdleTimeout must be between 4 and 120"
            ));
        }
    }

    if let Some(keepalive) = obj
        .get("keepAlivePeriod")
        .or_else(|| obj.get("KeepAlivePeriod"))
        .and_then(Value::as_i64)
    {
        if keepalive != 0 && !(2..=60).contains(&keepalive) {
            return Err(format!(
                "{kind} {tag:?}: KeepAlivePeriod must be between 2 and 60"
            ));
        }
    }

    if let Some(streams) = obj
        .get("maxIncomingStreams")
        .or_else(|| obj.get("MaxIncomingStreams"))
        .and_then(Value::as_i64)
    {
        if streams != 0 && streams < 8 {
            return Err(format!(
                "{kind} {tag:?}: MaxIncomingStreams must be at least 8"
            ));
        }
    }

    Ok(())
}

/// Validates outbound finalmask and logs warnings on unsupported mask types.
/// Inbound masks the server runs: `header-custom` and `sudoku` on TCP,
/// Salamander on Hysteria and `mkcp-legacy` on mKCP; the rest are skipped
/// with a warning.
pub fn warn_inbound_finalmask(stream: &Value, protocol: &str, tag: &str) {
    let Some(finalmask) = stream.get("finalmask").and_then(Value::as_object) else {
        return;
    };
    let network = stream
        .get("method")
        .or_else(|| stream.get("network"))
        .or_else(|| stream.get("transport"))
        .and_then(Value::as_str)
        .unwrap_or("");
    for (layer, masks) in [("tcp", finalmask.get("tcp")), ("udp", finalmask.get("udp"))] {
        for mask in masks.and_then(Value::as_array).into_iter().flatten() {
            let kind = mask.get("type").and_then(Value::as_str).unwrap_or("");
            let supported = match (layer, kind.to_ascii_lowercase().as_str()) {
                ("tcp", "header-custom" | "sudoku") => true,
                ("udp", "salamander" | "udphop") => protocol.starts_with("hysteria"),
                ("udp", "mkcp-legacy") => matches!(network, "kcp" | "mkcp"),
                _ => false,
            };
            if !supported {
                crate::log::warn!(
                    "inbound {tag:?}: streamSettings.finalmask.{layer}: mask type {kind:?} is not supported yet, ignored"
                );
            }
        }
    }
}

/// The `filter` mask itself is client-only here, but Xray's decoder still
/// type-checks its settings before the mask is skipped.
fn geodata_file_exists(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == ".." {
        return false;
    }
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::current_dir() {
        dirs.push(dir);
    }
    if let Ok(path) = std::env::current_exe() {
        if let Some(dir) = path.parent() {
            dirs.push(dir.to_path_buf());
        }
    }
    if let Some(dir) = crate::config::get_env("XRAY_LOCATION_ASSET") {
        dirs.push(dir.into());
    }
    dirs.iter().any(|dir| dir.join(name).is_file())
}

/// The subset of `geodata.ParseIPRules` that decides whether a rule is valid:
/// inverse prefixes, `geoip:`/`ext:` specs whose file must exist, and CIDRs.
fn valid_filter_ip_rule(text: &str) -> bool {
    let mut rule = text;
    while let Some(stripped) = rule.strip_prefix('!') {
        rule = stripped;
    }
    if let Some(spec) = rule.strip_prefix("geoip:") {
        let (code, _) = spec.split_once('@').unwrap_or((spec, ""));
        let code = code.strip_prefix('!').unwrap_or(code);
        return !code.is_empty() && geodata_file_exists("geoip.dat");
    }
    for prefix in ["ext:", "ext-ip:"] {
        if let Some(spec) = rule.strip_prefix(prefix) {
            let Some((file, code)) = spec.split_once(':') else {
                return false;
            };
            let code = code.split_once('@').map_or(code, |(code, _)| code);
            let code = code.strip_prefix('!').unwrap_or(code);
            return !file.is_empty() && !code.is_empty() && geodata_file_exists(file);
        }
    }
    let (address, prefix) = rule.split_once('/').unwrap_or((rule, ""));
    let address = address.trim_matches(|c: char| !c.is_alphanumeric() && c != ':' && c != '.');
    let address = address
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(address);
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = match address {
        std::net::IpAddr::V4(_) => 32u32,
        std::net::IpAddr::V6(address) if address.to_ipv4_mapped().is_some() => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    if prefix.is_empty() {
        return true;
    }
    prefix.bytes().all(|byte| byte.is_ascii_digit())
        && prefix.parse::<u32>().is_ok_and(|prefix| prefix <= max)
}

fn validate_filter_mask(mask: &Value, at: &str) -> Result<(), String> {
    let settings = mask.get("settings").filter(|value| !value.is_null());
    let Some(settings) = settings else {
        return Ok(());
    };
    let Some(object) = settings.as_object() else {
        return Err(format!("{at}: filter settings must be an object or null"));
    };
    for key in ["blockedSourceIPs", "allowedSourceIPs"] {
        let value = object.iter().find(|(name, _)| {
            name.to_lowercase().trim_start_matches('İ')
                == key.to_lowercase().trim_start_matches('İ')
        });
        match value.map(|(_, value)| value) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    let rule = match item {
                        Value::Null => "",
                        Value::String(rule) => rule.as_str(),
                        _ => return Err(format!("{at}: filter.{key} must hold strings")),
                    };
                    if !valid_filter_ip_rule(rule) {
                        return Err(format!("{at}: filter.{key}: illegal ip rule {rule:?}"));
                    }
                }
            }
            Some(_) => return Err(format!("{at}: filter.{key} must be an array or null")),
        }
    }
    Ok(())
}

pub fn validate_and_log_finalmask(outbound: &Value, tag: &str) -> Result<(), String> {
    let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
    validate_finalmask_quic_params(stream, tag)?;
    let Some(finalmask) = stream.get("finalmask").and_then(Value::as_object) else {
        return Ok(());
    };
    if let Some(tcp) = finalmask.get("tcp").and_then(Value::as_array) {
        for mask in tcp {
            let mask_type = mask.get("type").and_then(Value::as_str).unwrap_or("");
            if mask_type.eq_ignore_ascii_case("filter") {
                validate_filter_mask(mask, &format!("outbound {tag:?}"))?;
            }
            if !["fragment", "header-custom", "sudoku"]
                .iter()
                .any(|kind| mask_type.eq_ignore_ascii_case(kind))
            {
                crate::log::warn!(
                    "outbound {tag:?}: streamSettings.finalmask.tcp: mask type {mask_type:?} is not supported yet, ignored"
                );
            }
        }
    }
    if let Some(udp) = finalmask.get("udp").and_then(Value::as_array) {
        for mask in udp {
            let mask_type = mask.get("type").and_then(Value::as_str).unwrap_or("");
            if mask_type.eq_ignore_ascii_case("filter") {
                validate_filter_mask(mask, &format!("outbound {tag:?}"))?;
            }
            if !mask_type.eq_ignore_ascii_case("noise") && !mask_type.eq_ignore_ascii_case("udphop")
            {
                crate::log::warn!(
                    "outbound {tag:?}: streamSettings.finalmask.udp: mask type {mask_type:?} is not supported yet, ignored"
                );
            }
        }
    }
    Ok(())
}

fn parse_range_val(v: &Value) -> Result<(u32, u32), String> {
    match v {
        Value::Number(n) => {
            let val = n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| "number out of range".to_string())?;
            Ok((val, val))
        }
        Value::String(s) => {
            let s = s.trim();
            if let Some((start_s, end_s)) = s.split_once('-') {
                let start: u32 = start_s
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid range start in {s:?}"))?;
                let end: u32 = end_s
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid range end in {s:?}"))?;
                Ok((start.min(end), start.max(end)))
            } else {
                let val: u32 = s.parse().map_err(|_| format!("invalid number in {s:?}"))?;
                Ok((val, val))
            }
        }
        Value::Object(obj) => {
            let get = |k: &str| -> Result<Option<u32>, String> {
                match obj.get(k).and_then(Value::as_u64) {
                    Some(v) => u32::try_from(v)
                        .map(Some)
                        .map_err(|_| "number out of range".to_string()),
                    None => Ok(None),
                }
            };
            let from = get("from")?.unwrap_or(0);
            let to = get("to")?.unwrap_or(from);
            Ok((from.min(to), from.max(to)))
        }
        Value::Array(arr) if !arr.is_empty() => parse_range_val(&arr[0]),
        _ => Err("expected number, string or range object".to_string()),
    }
}

fn parse_ranges_list(v: &Value) -> Result<Vec<RangeInclusive<u32>>, String> {
    if let Some(arr) = v.as_array() {
        if arr.is_empty() {
            return Err("ranges array cannot be empty".to_string());
        }
        let mut list = Vec::with_capacity(arr.len().min(16));
        for item in arr.iter().take(16) {
            let (from, to) = parse_range_val(item)?;
            list.push(from..=to);
        }
        Ok(list)
    } else {
        let (from, to) = parse_range_val(v)?;
        Ok(vec![from..=to])
    }
}

fn parse_bandwidth_str(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let unit_idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num_str, unit_str) = s.split_at(unit_idx);
    let num = num_str
        .parse::<f64>()
        .map_err(|_| "invalid bandwidth number".to_string())?;
    let unit = unit_str.trim().to_ascii_lowercase();
    let mult = match unit.as_str() {
        "" | "b" | "bps" => 1u64,
        "k" | "kb" | "kbps" => 1024,
        "m" | "mb" | "mbps" => 1024 * 1024,
        "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
        _ => 1u64,
    };
    Ok(((num * mult as f64) / 8.0) as u64)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let h = std::str::from_utf8(c).map_err(|_| ())?;
            u8::from_str_radix(h, 16).map_err(|_| ())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fragment_out_of_range_values_do_not_panic() {
        let v = json!({"lengths": "20000-30000", "delays": 2000});
        assert!(parse_tcp_fragment_settings(&v).is_ok());
        assert!(decode_hex("a\u{e9}a").is_err());
    }

    #[test]
    fn two_fragment_masks_chain_and_keep_their_packets() {
        let stream = json!({
            "finalmask": {
                "tcp": [
                    {
                        "type": "fragment",
                        "settings": {
                            "packets": "tlshello",
                            "lengths": ["0", "104", "1"],
                            "delays": ["0"],
                            "maxSplit": "0"
                        }
                    },
                    {
                        "type": "fragment",
                        "settings": {
                            "packets": "1-1",
                            "lengths": ["114", "1"],
                            "delays": ["1"],
                            "maxSplit": "11"
                        }
                    }
                ]
            }
        });
        let frag = parse_finalmask_tcp_fragment(&stream).unwrap().unwrap();
        let expected = TcpFragmentConfig::new(vec![0..=0, 104..=104, 1..=1], vec![0..=0], 0..=0)
            .unwrap()
            .with_chained(vec![TcpFragmentConfig::new(
                vec![114..=114, 1..=1],
                vec![1..=1],
                11..=11,
            )
            .unwrap()
            .with_packets(xray_transport::FragmentPackets::Writes(1..=1))
            .unwrap()])
            .unwrap();
        assert_eq!(frag, Arc::new(expected));
    }

    #[test]
    fn test_finalmask_tcp_fragment_parsing() {
        let stream = json!({
            "finalmask": {
                "tcp": [
                    {
                        "type": "fragment",
                        "settings": {
                            "packets": "tlshello",
                            "lengths": ["100-200", 300],
                            "delays": [10, "20-30"],
                            "maxSplit": 50
                        }
                    }
                ]
            }
        });
        let frag = parse_finalmask_tcp_fragment(&stream).unwrap().unwrap();
        assert_eq!(
            frag,
            TcpFragmentConfig::new(vec![100..=200, 300..=300], vec![10..=10, 20..=30], 50..=50)
                .unwrap()
                .into()
        );

        let freedom_frag = parse_freedom_fragment_from_finalmask(&stream)
            .unwrap()
            .unwrap();
        assert_eq!(freedom_frag.length, (100, 200));
        assert_eq!(freedom_frag.interval, (10, 10));
        assert_eq!(freedom_frag.max_split, (50, 50));
        assert!(freedom_frag.tcp_fragment.is_some());
    }

    #[test]
    fn test_finalmask_udp_noises_parsing() {
        let stream = json!({
            "finalmask": {
                "udp": [
                    {
                        "type": "noise",
                        "settings": {
                            "noise": [
                                { "type": "str", "packet": "synthetic", "delay": "2-5", "applyTo": "ipv4" },
                                { "rand": "16-24", "delay": 1 },
                                { "type": "hex", "packet": "01020304", "delay": 0 }
                            ]
                        }
                    }
                ]
            }
        });
        let noises = parse_finalmask_udp_noises(&stream).unwrap();
        assert_eq!(noises.len(), 3);
        assert_eq!(noises[0].apply_to, FreedomNoiseFamily::Ipv4);
        assert_eq!(
            noises[0].packet,
            FreedomNoisePacket::Bytes(b"synthetic".to_vec())
        );
        assert_eq!(noises[0].delay_ms, (2, 5));
        assert_eq!(noises[1].apply_to, FreedomNoiseFamily::Ip);
        assert_eq!(noises[1].packet, FreedomNoisePacket::Random(16, 24));
        assert_eq!(noises[1].delay_ms, (1, 1));
        assert_eq!(
            noises[2].packet,
            FreedomNoisePacket::Bytes(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn test_validate_finalmask_quic_params() {
        let valid = json!({
            "finalmask": {
                "quicParams": {
                    "congestion": "bbr",
                    "bbrProfile": "standard",
                    "initStreamReceiveWindow": 32768,
                    "maxStreamReceiveWindow": 65536,
                    "maxIdleTimeout": 30,
                    "keepAlivePeriod": 15,
                    "maxIncomingStreams": 16
                }
            }
        });
        assert!(validate_finalmask_quic_params(&valid, "test").is_ok());

        let invalid_congestion = json!({
            "finalmask": { "quicParams": { "congestion": "unknown_algo" } }
        });
        assert!(validate_finalmask_quic_params(&invalid_congestion, "test")
            .unwrap_err()
            .contains("unknown congestion control"));

        let invalid_bbr = json!({
            "finalmask": { "quicParams": { "bbrProfile": "turbo" } }
        });
        assert!(validate_finalmask_quic_params(&invalid_bbr, "test")
            .unwrap_err()
            .contains("unknown bbr profile"));

        let small_window = json!({
            "finalmask": { "quicParams": { "initStreamReceiveWindow": 100 } }
        });
        assert!(validate_finalmask_quic_params(&small_window, "test")
            .unwrap_err()
            .contains("InitStreamReceiveWindow must be at least 16384"));

        let bad_timeout = json!({
            "finalmask": { "quicParams": { "maxIdleTimeout": 200 } }
        });
        assert!(validate_finalmask_quic_params(&bad_timeout, "test")
            .unwrap_err()
            .contains("MaxIdleTimeout must be between 4 and 120"));
    }
}
