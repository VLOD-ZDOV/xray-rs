//! Xray-style logging driven by the config's `log` section. Access lines
//! (who connected where) go only to the access log, which 3x-ui disables
//! with `"access": "none"`.

use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const DEBUG: u8 = 0;
const INFO: u8 = 1;
const WARNING: u8 = 2;
const ERROR: u8 = 3;
const NONE: u8 = 4;

static LEVEL: AtomicU8 = AtomicU8::new(WARNING);
static MASK: AtomicU8 = AtomicU8::new(0);
static ERROR_SINK: OnceLock<Option<Sink>> = OnceLock::new();
static ACCESS_SINK: OnceLock<Option<Sink>> = OnceLock::new();

type Sink = Mutex<Box<dyn Write + Send>>;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Settings {
    pub level: String,
    pub access: String,
    pub error: String,
    pub mask_address: String,
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
    let debug_override = std::env::var_os("XRAY_SERVER_DEBUG").is_some();
    LEVEL.store(if debug_override { DEBUG } else { level }, Ordering::Relaxed);
    MASK.store(
        match settings.mask_address.as_str() {
            "quarter" => 1,
            "half" => 2,
            "full" => 3,
            _ => 0,
        },
        Ordering::Relaxed,
    );
    let _ = ERROR_SINK.set(open_sink(&settings.error)?);
    let _ = ACCESS_SINK.set(open_sink(&settings.access)?);
    Ok(())
}

/// `""` is stdout, `"none"` disables the log, anything else is a file path.
fn open_sink(target: &str) -> Result<Option<Sink>, String> {
    match target {
        "none" => Ok(None),
        "" => Ok(Some(Mutex::new(Box::new(std::io::stdout())))),
        path => {
            let file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("failed to open log {path}: {e}"))?;
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

fn write_error(level: u8, label: &str, message: impl Display) {
    if level < LEVEL.load(Ordering::Relaxed) {
        return;
    }
    // Before init (config parsing) messages go to stdout.
    match ERROR_SINK.get() {
        Some(Some(sink)) => write_line(sink, format_args!("[{label}] {message}")),
        Some(None) => {}
        None => println!("{} [{label}] {message}", timestamp()),
    }
}

/// One access log line in Xray's format:
/// `from 1.2.3.4:5 accepted tcp:example.com:443 [in -> out] email: user`.
pub fn access(from: SocketAddr, accepted: bool, to: impl Display, inbound: &str, outbound: &str, email: &str) {
    let Some(Some(sink)) = ACCESS_SINK.get() else { return };
    let status = if accepted { "accepted" } else { "rejected" };
    let from = mask(from);
    if email.is_empty() {
        write_line(sink, format_args!("from {from} {status} {to} [{inbound} -> {outbound}]"));
    } else {
        write_line(sink, format_args!("from {from} {status} {to} [{inbound} -> {outbound}] email: {email}"));
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

/// `YYYY/MM/DD HH:MM:SS.micros` in UTC.
fn timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
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
}
