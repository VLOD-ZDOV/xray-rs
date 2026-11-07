//! Xray-style logging driven by the config's `log` section. Access lines
//! (who connected where) go only to the access log, which 3x-ui disables
//! with `"access": "none"`.

use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const DEBUG: u8 = 0;
const INFO: u8 = 1;
const WARNING: u8 = 2;
const ERROR: u8 = 3;
const NONE: u8 = 4;

static LEVEL: AtomicU8 = AtomicU8::new(WARNING);
static MASK: AtomicU8 = AtomicU8::new(0);
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
        "" | "warning" => WARNING,
        "error" => ERROR,
        "none" => NONE,
        other => return Err(format!("unknown log level {other:?}")),
    };
    let debug_override = crate::config::get_env("XRAY_SERVER_DEBUG").is_some();
    LEVEL.store(
        if debug_override { DEBUG } else { level },
        Ordering::Relaxed,
    );
    MASK.store(
        match settings.mask_address.as_str() {
            "quarter" => 1,
            "half" => 2,
            "full" => 3,
            _ => 0,
        },
        Ordering::Relaxed,
    );
    DNS_LOG.store(settings.dns_log, Ordering::Relaxed);
    let err = open_sink(&settings.error)?;
    let acc = open_sink(&settings.access)?;
    *ERROR_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(err);
    *ACCESS_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(acc);
    *SETTINGS.write().unwrap_or_else(|e| e.into_inner()) = Some(settings.clone());
    Ok(())
}

pub fn restart() -> Result<(), String> {
    let settings = SETTINGS.read().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(settings) = settings {
        let err = open_sink(&settings.error)?;
        let acc = open_sink(&settings.access)?;
        *ERROR_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(err);
        *ACCESS_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(acc);
    }
    Ok(())
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
    if DNS_LOG.load(Ordering::Relaxed) || LEVEL.load(Ordering::Relaxed) <= INFO {
        info(format!("[DNS] {message}"));
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
/// `from 1.2.3.4:5 accepted tcp:example.com:443 [in -> out] email: user`.
pub fn access(
    from: SocketAddr,
    accepted: bool,
    to: impl Display,
    inbound: &str,
    outbound: &str,
    email: &str,
) {
    let guard = ACCESS_SINK.read().unwrap_or_else(|e| e.into_inner());
    let Some(Some(sink)) = &*guard else {
        return;
    };
    let status = if accepted { "accepted" } else { "rejected" };
    let from = mask(from);
    if email.is_empty() {
        write_line(
            sink,
            format_args!("from {from} {status} {to} [{inbound} -> {outbound}]"),
        );
    } else {
        write_line(
            sink,
            format_args!("from {from} {status} {to} [{inbound} -> {outbound}] email: {email}"),
        );
    }
}

/// Applies `maskAddress` to a client address shown in logs.
pub fn mask(addr: SocketAddr) -> String {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        ip => ip,
    };
    let keep = MASK.load(Ordering::Relaxed);
    let shown = match (ip, keep) {
        (ip, 0) => ip.to_string(),
        (IpAddr::V4(v4), level) => {
            let o = v4.octets();
            match level {
                1 => format!("{}.{}.{}.*", o[0], o[1], o[2]),
                2 => format!("{}.{}.*.*", o[0], o[1]),
                _ => "*.*.*.*".into(),
            }
        }
        (IpAddr::V6(v6), level) => {
            let s = v6.segments();
            match level {
                1 => format!("{:x}:{:x}:{:x}::*", s[0], s[1], s[2]),
                2 => format!("{:x}:{:x}::*", s[0], s[1]),
                _ => "*::*".into(),
            }
        }
    };
    match ip {
        IpAddr::V6(_) => format!("[{shown}]:{}", addr.port()),
        IpAddr::V4(_) => format!("{shown}:{}", addr.port()),
    }
}

fn write_line(sink: &Sink, line: std::fmt::Arguments<'_>) {
    let mut out = sink.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(out, "{} {line}", timestamp());
}

fn local_offset_seconds() -> i64 {
    static OFFSET: OnceLock<i64> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        if let Some(tz) = crate::config::get_env("TZ") {
            if let Some(off) = parse_tz_string(&tz) {
                return off;
            }
        }
        if let Ok(data) = std::fs::read("/etc/localtime") {
            if let Some(off) = parse_tzif_file(&data) {
                return off;
            }
        }
        0
    })
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

fn parse_tzif_file(data: &[u8]) -> Option<i64> {
    if !data.starts_with(b"TZif") {
        return None;
    }
    for line in data.rsplit(|&b| b == b'\n') {
        let line = line.trim_ascii();
        if !line.is_empty() {
            if let Ok(s) = std::str::from_utf8(line) {
                if let Some(off) = parse_tz_string(s) {
                    return Some(off);
                }
            }
            break;
        }
    }
    None
}

/// `YYYY/MM/DD HH:MM:SS.micros` in local time.
fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let local_secs = (secs as i64 + local_offset_seconds()).max(0) as u64;
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

    #[test]
    fn masks_addresses() {
        MASK.store(1, Ordering::Relaxed);
        assert_eq!(mask("1.2.3.4:5".parse().unwrap()), "1.2.3.*:5");
        assert_eq!(mask("[::ffff:1.2.3.4]:5".parse().unwrap()), "1.2.3.*:5");
        MASK.store(0, Ordering::Relaxed);
        assert_eq!(mask("[::ffff:1.2.3.4]:5".parse().unwrap()), "1.2.3.4:5");
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
}
