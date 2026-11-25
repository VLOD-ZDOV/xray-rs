//! Xray-style logging driven by the config's `log` section. Access lines
//! (who connected where) go only to the access log, which 3x-ui disables
//! with `"access": "none"`.

use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const DEBUG: u8 = 0;
const INFO: u8 = 1;
const WARNING: u8 = 2;
const ERROR: u8 = 3;
const NONE: u8 = 4;

static LEVEL: AtomicU8 = AtomicU8::new(WARNING);
/// IPv4/IPv6 prefix lengths kept by `maskAddress`; 32/128 means no masking.
static MASK4: AtomicU8 = AtomicU8::new(32);
static MASK6: AtomicI32 = AtomicI32::new(128);
static DNS_LOG: AtomicBool = AtomicBool::new(false);
static ERROR_SINK: RwLock<Option<Option<Sink>>> = RwLock::new(None);
static ACCESS_SINK: RwLock<Option<Option<Sink>>> = RwLock::new(None);
static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

type Sink = Mutex<Box<dyn Write + Send>>;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Settings {
    pub level: String,
    pub access: String,
    pub error: String,
    pub mask_address: String,
    pub dns_log: bool,
}

pub fn init(settings: &Settings) -> Result<(), String> {
    let level = match settings.level.to_ascii_lowercase().as_str() {
        "debug" => DEBUG,
        "info" => INFO,
        "error" => ERROR,
        "none" => NONE,
        _ => WARNING,
    };
    let debug_override = crate::config::get_env("XRAY_SERVER_DEBUG").is_some();
    LEVEL.store(
        if debug_override { DEBUG } else { level },
        Ordering::Relaxed,
    );
    let mask = parse_mask_address(&settings.mask_address)?;
    MASK4.store(mask.0, Ordering::Relaxed);
    MASK6.store(mask.1, Ordering::Relaxed);
    DNS_LOG.store(settings.dns_log, Ordering::Relaxed);
    let (err, acc) = open_sinks(settings)?;
    *ERROR_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(err);
    *ACCESS_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(acc);
    *SETTINGS.write().unwrap_or_else(|e| e.into_inner()) = Some(settings.clone());
    Ok(())
}

pub fn restart() -> Result<(), String> {
    let settings = SETTINGS.read().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(settings) = settings {
        let (err, acc) = open_sinks(&settings)?;
        *ERROR_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(err);
        *ACCESS_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(acc);
    }
    Ok(())
}

/// Level `none` turns both logs off, access included.
fn open_sinks(settings: &Settings) -> Result<(Option<Sink>, Option<Sink>), String> {
    if settings.level.eq_ignore_ascii_case("none") {
        return Ok((None, None));
    }
    Ok((open_sink(&settings.error)?, open_sink(&settings.access)?))
}

/// `""` is stdout, `"none"` disables the log, anything else is a file path.
fn open_sink(target: &str) -> Result<Option<Sink>, String> {
    match target {
        "none" => Ok(None),
        "" => Ok(Some(Mutex::new(Box::new(std::io::stdout())))),
        path => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("failed to open log {path}: {e}"))?;
            Ok(Some(Mutex::new(Box::new(LineWriter::new(file)))))
        }
    }
}

#[allow(dead_code)]
pub fn is_debug_enabled() -> bool {
    LEVEL.load(Ordering::Relaxed) == DEBUG
}

#[allow(dead_code)]
pub fn is_info_enabled() -> bool {
    LEVEL.load(Ordering::Relaxed) <= INFO
}

#[allow(dead_code)]
pub fn is_warn_enabled() -> bool {
    LEVEL.load(Ordering::Relaxed) <= WARNING
}

#[allow(dead_code)]
pub fn is_error_enabled() -> bool {
    LEVEL.load(Ordering::Relaxed) <= ERROR
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::log::is_debug_enabled() {
            $crate::log::debug(format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::log::is_info_enabled() {
            $crate::log::info(format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::log::is_warn_enabled() {
            $crate::log::warn(format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::log::is_error_enabled() {
            $crate::log::error(format_args!($($arg)*));
        }
    };
}

#[allow(unused_imports)]
pub use crate::{log_debug as debug, log_error as error, log_info as info, log_warn as warn};

pub fn debug(message: impl Display) {
    write_error(DEBUG, "Debug", message);
}

pub fn info(message: impl Display) {
    write_error(INFO, "Info", message);
}

pub fn warn(message: impl Display) {
    write_error(WARNING, "Warning", message);
}

pub fn error(message: impl Display) {
    write_error(ERROR, "Error", message);
}

pub fn dns(message: impl Display) {
    // Xray writes DNS lines to the access log, and only when dnsLog is on.
    if !DNS_LOG.load(Ordering::Relaxed) {
        return;
    }
    let guard = ACCESS_SINK.read().unwrap_or_else(|e| e.into_inner());
    if let Some(Some(sink)) = &*guard {
        write_line(sink, format_args!("{message}"));
    }
}

fn write_error(level: u8, label: &str, message: impl Display) {
    if level < LEVEL.load(Ordering::Relaxed) {
        return;
    }
    // Before init (config parsing) messages go to stdout.
    let guard = ERROR_SINK.read().unwrap_or_else(|e| e.into_inner());
    match &*guard {
        Some(Some(sink)) => write_line(sink, format_args!("[{label}] {message}")),
        Some(None) => {}
        None => println!("{} [{label}] {message}", timestamp()),
    }
}

/// One access log line in Xray's format:
/// `from tcp:1.2.3.4:5 accepted tcp:example.com:443 [in -> out] email: user`.
#[allow(clippy::too_many_arguments)]
pub fn access(
    from: SocketAddr,
    network: &str,
    accepted: bool,
    to: impl Display,
    inbound: &str,
    outbound: &str,
    separator: &str,
    email: &str,
) {
    let guard = ACCESS_SINK.read().unwrap_or_else(|e| e.into_inner());
    let Some(Some(sink)) = &*guard else {
        return;
    };
    let status = if accepted { "accepted" } else { "rejected" };
    let from = display_addr(from);
    // VLESS/Trojan/VMess log a raw `net.Addr`, which has no network prefix;
    // WireGuard and MASQUE log a `net.Destination`, which does.
    let from = if network.is_empty() {
        from
    } else {
        format!("{network}:{from}")
    };
    // Xray writes the detour only when the outbound has a tag, and drops the
    // inbound part when the inbound tag is empty.
    let detour = if outbound.is_empty() {
        String::new()
    } else if inbound.is_empty() {
        format!(" [{outbound}]")
    } else {
        format!(" [{inbound} {separator} {outbound}]")
    };
    if email.is_empty() {
        write_line(sink, format_args!("from {from} {status} {to}{detour}"));
    } else {
        write_line(
            sink,
            format_args!("from {from} {status} {to}{detour} email: {email}"),
        );
    }
}

/// `SocketAddr` the way Go prints it: IPv4-mapped IPv6 shows as IPv4.
fn display_addr(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| addr.to_string(), |v4| format!("{v4}:{}", addr.port())),
        IpAddr::V4(_) => addr.to_string(),
    }
}

/// Parses Xray's `maskAddress` values: `quarter`, `half`, `full`, or explicit
/// `/N+/M` prefix lengths. The empty string disables masking.
fn parse_mask_address(value: &str) -> Result<(u8, i32), String> {
    let (mut m4, mut m6) = (32u32, 128i32);
    match value {
        "" => {}
        "half" => {
            m4 = 16;
            m6 = 32;
        }
        "quarter" => {
            m4 = 8;
            m6 = 16;
        }
        "full" => {
            m4 = 0;
            m6 = 0;
        }
        custom => {
            // As in Xray: unset parts default to 0, not to "no mask".
            m4 = 0;
            m6 = 0;
            let mut parts = custom.split('+');
            if let Some(part) = parts.next().filter(|part| !part.is_empty()) {
                m4 = part
                    .trim_start_matches('/')
                    .parse()
                    .map_err(|e| format!("invalid maskAddress {value:?}: {e}"))?;
            }
            if let Some(part) = parts.next().filter(|part| !part.is_empty()) {
                m6 = part
                    .trim_start_matches('/')
                    .parse()
                    .map_err(|e| format!("invalid maskAddress {value:?}: {e}"))?;
            }
        }
    }
    if m4 % 8 != 0 || m4 > 32 {
        return Err("Log Mask: ipv4 mask must be divisible by 8 and between 0-32".into());
    }
    Ok((m4 as u8, m6))
}

/// Formats a client address for a log message. Masking is applied once, to the
/// finished line, in [`write_line`].
pub fn mask(addr: SocketAddr) -> String {
    display_addr(addr)
}

fn mask_ipv4_text(text: &str) -> String {
    let m4 = MASK4.load(Ordering::Relaxed);
    if m4 == 32 {
        return text.to_string();
    }
    if m4 == 0 {
        return "[Masked IPv4]".into();
    }
    let mut parts: Vec<&str> = text.split('.').collect();
    for part in parts.iter_mut().skip(usize::from(m4) / 8) {
        *part = "*";
    }
    parts.join(".")
}

fn mask_ip(ip: IpAddr) -> String {
    let (m4, m6) = (MASK4.load(Ordering::Relaxed), MASK6.load(Ordering::Relaxed));
    match ip {
        IpAddr::V4(v4) if m4 == 32 => v4.to_string(),
        IpAddr::V4(_) if m4 == 0 => "[Masked IPv4]".into(),
        IpAddr::V4(v4) => {
            let mut parts = v4.octets().map(|octet| octet.to_string());
            for part in parts.iter_mut().skip(usize::from(m4) / 8) {
                *part = "*".into();
            }
            parts.join(".")
        }
        IpAddr::V6(v6) if m6 == 128 => v6.to_string(),
        IpAddr::V6(_) if m6 == 0 => "Masked IPv6".into(),
        IpAddr::V6(_) if !(1..=128).contains(&m6) => format!("<nil>/{m6}"),
        IpAddr::V6(v6) => {
            let bits = usize::try_from(m6).unwrap_or_default();
            let mask = if bits == 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - bits)
            };
            format!("{}/{}", std::net::Ipv6Addr::from(u128::from(v6) & mask), m6)
        }
    }
}

/// Xray's masker runs over the finished line, so destination addresses are
/// masked too. Same regular expressions as `app/log/log.go`.
fn mask_text(line: &str) -> String {
    let (m4, m6) = (MASK4.load(Ordering::Relaxed), MASK6.load(Ordering::Relaxed));
    if m4 == 32 && m6 == 128 {
        return line.to_string();
    }
    use std::sync::LazyLock;
    static IPV4: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(\d{1,3}\.){3}\d{1,3}").expect("valid IPv4 expression")
    });
    static IPV6: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?:[\da-fA-F]{0,4}:[\da-fA-F]{0,4}){2,7}")
            .expect("valid IPv6 expression")
    });
    // Xray masks any four dot-separated groups, even a value that is not a
    // valid address: the regex decides, not the parser.
    let masked = IPV4.replace_all(line, |caps: &regex::Captures<'_>| mask_ipv4_text(&caps[0]));
    IPV6.replace_all(&masked, |caps: &regex::Captures<'_>| {
        let text = &caps[0];
        match text.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => mask_ip(IpAddr::V6(ip)),
            Err(_) => text.to_string(),
        }
    })
    .into_owned()
}

fn write_line(sink: &Sink, line: std::fmt::Arguments<'_>) {
    let mut out = sink.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(out, "{} {}", timestamp(), mask_text(&line.to_string()));
}

/// A parsed TZif transition table. `transitions` holds `(unix time, offset)`
/// pairs sorted by time; `initial` is the offset before the first transition.
#[derive(Debug)]
struct Zone {
    transitions: Vec<(i64, i32)>,
    initial: i32,
}

impl Zone {
    fn fixed(offset: i64) -> Self {
        Self {
            transitions: Vec::new(),
            initial: offset.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
        }
    }

    fn offset_at(&self, at: i64) -> i64 {
        let index = self.transitions.partition_point(|(time, _)| *time <= at);
        if index == 0 {
            i64::from(self.initial)
        } else {
            i64::from(self.transitions[index - 1].1)
        }
    }
}

fn local_zone() -> &'static Option<Zone> {
    static ZONE: OnceLock<Option<Zone>> = OnceLock::new();
    ZONE.get_or_init(|| {
        if let Some(tz) = crate::config::get_env("TZ") {
            if tz.is_empty() || tz == "UTC" {
                return None;
            }
            let name = tz.strip_prefix(':').unwrap_or(&tz);
            if let Ok(data) = std::fs::read(name) {
                if let Some(zone) = parse_tzif(&data) {
                    return Some(zone);
                }
            }
            if let Ok(data) = std::fs::read(format!("/usr/share/zoneinfo/{name}")) {
                if let Some(zone) = parse_tzif(&data) {
                    return Some(zone);
                }
            }
            if let Some(offset) = parse_tz_string(name) {
                return Some(Zone::fixed(offset));
            }
        }
        std::fs::read("/etc/localtime")
            .ok()
            .and_then(|data| parse_tzif(&data))
    })
}

/// Follows a TZif file's 64-bit transition table (version 2 and later). Version
/// 1 files are parsed too; their timestamps end in 2038.
fn parse_tzif(data: &[u8]) -> Option<Zone> {
    const HEADER: usize = 44;
    if data.len() < HEADER || &data[..4] != b"TZif" {
        return None;
    }
    let version = data[4];
    let counts = |pos: usize| -> Option<[usize; 6]> {
        let raw = data.get(pos + 20..pos + 44)?;
        let mut counts = [0usize; 6];
        for (index, chunk) in raw.chunks_exact(4).enumerate() {
            counts[index] = usize::try_from(u32::from_be_bytes(chunk.try_into().ok()?)).ok()?;
        }
        Some(counts)
    };
    let first = counts(0)?;
    let (pos, wide, counts) = if version == 0 {
        (HEADER, false, first)
    } else {
        let block = first[3]
            .checked_mul(5)?
            .checked_add(first[4].checked_mul(6)?)?
            .checked_add(first[5])?
            .checked_add(first[2].checked_mul(8)?)?
            .checked_add(first[0])?
            .checked_add(first[1])?;
        let second_header = HEADER.checked_add(block)?;
        (
            second_header.checked_add(HEADER)?,
            true,
            counts(second_header)?,
        )
    };
    let (timecnt, typecnt) = (counts[3], counts[4]);
    if timecnt > 1_000_000 || typecnt > 256 || counts[5] > 1_000_000 {
        return None;
    }
    let time_size = if wide { 8 } else { 4 };
    let transitions_end = pos.checked_add(timecnt.checked_mul(time_size)?)?;
    let indices_end = transitions_end.checked_add(timecnt)?;
    let types_end = indices_end.checked_add(typecnt.checked_mul(6)?)?;
    if types_end > data.len() {
        return None;
    }
    let mut transitions = Vec::with_capacity(timecnt);
    for index in 0..timecnt {
        let raw = &data[pos + index * time_size..pos + (index + 1) * time_size];
        let time = if wide {
            i64::from_be_bytes(raw.try_into().ok()?)
        } else {
            i64::from(i32::from_be_bytes(raw.try_into().ok()?))
        };
        let kind = usize::from(data[transitions_end + index]);
        let offset_at = indices_end + kind * 6;
        if kind >= typecnt || offset_at + 4 > data.len() {
            return None;
        }
        let offset = i32::from_be_bytes(data[offset_at..offset_at + 4].try_into().ok()?);
        transitions.push((time, offset));
    }
    let mut initial = None;
    let mut first_standard = None;
    for kind in 0..typecnt {
        let offset_at = indices_end + kind * 6;
        let offset = i32::from_be_bytes(data[offset_at..offset_at + 4].try_into().ok()?);
        let is_dst = data[offset_at + 4] != 0;
        if kind == 0 {
            initial = Some(offset);
        }
        if !is_dst && first_standard.is_none() {
            first_standard = Some(offset);
        }
    }
    // tzcode uses the first standard-time type before the first transition.
    let initial = first_standard.or(initial)?;
    transitions.sort_by_key(|(time, _)| *time);
    Some(Zone {
        transitions,
        initial,
    })
}

fn local_offset_seconds(now: i64) -> i64 {
    local_zone().as_ref().map_or(0, |zone| zone.offset_at(now))
}

fn parse_tz_string(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = if let Some(stripped) = s.strip_prefix('<') {
        let end = stripped.find('>')?;
        &stripped[end + 1..]
    } else {
        let non_alpha = s.find(|c: char| !c.is_alphabetic())?;
        &s[non_alpha..]
    };
    let (sign, s) = match s.chars().next() {
        Some('-') => (-1, &s[1..]),
        Some('+') => (1, &s[1..]),
        _ => (1, s),
    };
    let digit_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let hours: i64 = s[..digit_end].parse().ok()?;
    let rest = &s[digit_end..];
    let (mins, secs) = if let Some(rest) = rest.strip_prefix(':') {
        let digit_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let mins: i64 = rest[..digit_end].parse().unwrap_or(0);
        let rest2 = &rest[digit_end..];
        let secs: i64 = if let Some(rest2) = rest2.strip_prefix(':') {
            let digit_end = rest2
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest2.len());
            rest2[..digit_end].parse().unwrap_or(0)
        } else {
            0
        };
        (mins, secs)
    } else {
        (0, 0)
    };
    let total = hours * 3600 + mins * 60 + secs;
    // POSIX TZ sign convention is inverted: negative sign in POSIX string means ahead of UTC.
    Some(-sign * total)
}

/// `YYYY/MM/DD HH:MM:SS.micros` in local time.
fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let local_secs = (secs as i64 + local_offset_seconds(secs as i64)).max(0) as u64;
    let (days, rem) = (local_secs / 86_400, local_secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}/{month:02}/{day:02} {:02}:{:02}:{:02}.{:06}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        now.subsec_micros()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mask atomics are process-wide; tests that change them take turns.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn masks_addresses() {
        let _guard = TEST_LOCK.lock().unwrap();
        MASK4.store(8, Ordering::Relaxed);
        MASK6.store(16, Ordering::Relaxed);
        assert_eq!(mask_ip("1.2.3.4".parse().unwrap()), "1.*.*.*");
        assert_eq!(mask_ip("2001:db8::1".parse().unwrap()), "2001::/16");
        assert_eq!(
            mask("1.2.3.4:5".parse().unwrap()),
            "1.2.3.4:5",
            "masking runs over the finished line, not in mask()"
        );

        MASK4.store(0, Ordering::Relaxed);
        MASK6.store(0, Ordering::Relaxed);
        assert_eq!(mask_ip("1.2.3.4".parse().unwrap()), "[Masked IPv4]");
        assert_eq!(mask_ip("2001:db8::1".parse().unwrap()), "Masked IPv6");

        MASK4.store(32, Ordering::Relaxed);
        MASK6.store(200, Ordering::Relaxed);
        assert_eq!(mask_ip("2001:db8::1".parse().unwrap()), "<nil>/200");

        MASK4.store(32, Ordering::Relaxed);
        MASK6.store(128, Ordering::Relaxed);
        assert_eq!(mask_ip("1.2.3.4".parse().unwrap()), "1.2.3.4");
    }

    #[test]
    fn parses_mask_addresses() {
        assert_eq!(parse_mask_address("quarter"), Ok((8, 16)));
        assert_eq!(parse_mask_address("half"), Ok((16, 32)));
        assert_eq!(parse_mask_address("full"), Ok((0, 0)));
        assert_eq!(parse_mask_address(""), Ok((32, 128)));
        assert_eq!(parse_mask_address("/24+/64"), Ok((24, 64)));
        assert_eq!(parse_mask_address("/8"), Ok((8, 0)));
        assert_eq!(parse_mask_address("/24+/200"), Ok((24, 200)));
        assert_eq!(parse_mask_address("/24+-1"), Ok((24, -1)));
        assert!(parse_mask_address("domain").is_err());
        assert!(parse_mask_address("/7+/64").is_err());
    }

    #[test]
    fn mask_text_covers_destinations() {
        let _guard = TEST_LOCK.lock().unwrap();
        MASK4.store(16, Ordering::Relaxed);
        MASK6.store(0, Ordering::Relaxed);
        assert_eq!(
            mask_text("from 203.0.113.9:5 accepted tcp:198.51.100.7:443"),
            "from 203.0.*.*:5 accepted tcp:198.51.*.*:443"
        );
        assert_eq!(mask_text("no addresses here"), "no addresses here");
        assert_eq!(
            mask_text("tcp:999.1.2.3:5"),
            "tcp:999.1.*.*:5",
            "Xray masks address-shaped text even when it is not a valid IP"
        );
    }

    #[test]
    fn timestamp_shape() {
        let ts = timestamp();
        assert_eq!(ts.len(), 26);
        assert_eq!(&ts[4..5], "/");
    }

    #[test]
    fn parses_posix_tz_offsets() {
        assert_eq!(parse_tz_string("<+07>-7"), Some(7 * 3600));
        assert_eq!(parse_tz_string("MSK-3"), Some(3 * 3600));
        assert_eq!(parse_tz_string("EST5EDT"), Some(-5 * 3600));
        assert_eq!(parse_tz_string("UTC0"), Some(0));
        assert_eq!(parse_tz_string("JST-9"), Some(9 * 3600));
    }

    fn synthetic_tzif() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"TZif");
        data.push(0); // version 1 files use a NUL version byte
        data.extend_from_slice(&[0u8; 15]);
        for count in [0u32, 0, 0, 2, 2, 4] {
            data.extend_from_slice(&count.to_be_bytes());
        }
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&1000i32.to_be_bytes());
        data.push(0);
        data.push(1);
        // Standard time, then DST at +1 h.
        data.extend_from_slice(&0i32.to_be_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&3600i32.to_be_bytes());
        data.push(1);
        data.push(0);
        data.extend_from_slice(b"UTC\0");
        data
    }

    #[test]
    fn tzif_transitions_pick_the_offset_for_the_instant() {
        let zone = parse_tzif(&synthetic_tzif()).expect("parse synthetic TZif");
        assert_eq!(zone.offset_at(-1), 0);
        assert_eq!(zone.offset_at(500), 0);
        assert_eq!(zone.offset_at(1000), 3600);
        assert!(parse_tzif(b"not a tzif").is_none());
    }
}
