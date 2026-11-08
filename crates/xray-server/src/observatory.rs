//! Observatory and BurstObservatory health checks and status reporting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use xray_config::parse_xray_duration;

use crate::log;
use crate::outbound::{self, Stream};
use crate::routing::Router;
use crate::vless::Host;

pub const DEFAULT_OBSERVATORY_PROBE_URL: &str = "https://www.google.com/generate_204";
pub const DEFAULT_BURST_DESTINATION: &str = "https://connectivitycheck.gstatic.com/generate_204";
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_BURST_INTERVAL: Duration = Duration::from_secs(60);
pub const MIN_BURST_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_SAMPLING_COUNT: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryConfig {
    pub subject_selector: Vec<String>,
    pub probe_url: String,
    pub probe_interval: Duration,
    pub enable_concurrency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatoryConfig {
    pub subject_selector: Vec<String>,
    pub destination: String,
    pub connectivity: String,
    pub interval: Duration,
    pub sampling_count: usize,
    pub timeout: Duration,
    pub http_method: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthPingStats {
    pub all: i64,
    pub fail: i64,
    pub deviation: i64,
    pub average: i64,
    pub max: i64,
    pub min: i64,
}

#[derive(Debug, Clone)]
struct PingRecord {
    time: Instant,
    value_ns: i64,
}

const RTT_FAILED: i64 = -1;
const RTT_UNTESTED: i64 = -2;

pub struct HealthPingRTTS {
    cap: usize,
    validity: Duration,
    idx: usize,
    records: Vec<PingRecord>,
}

impl HealthPingRTTS {
    pub fn new(cap: usize, validity: Duration) -> Self {
        Self {
            cap,
            validity,
            idx: 0,
            records: vec![
                PingRecord {
                    time: Instant::now(),
                    value_ns: RTT_UNTESTED,
                };
                cap
            ],
        }
    }

    pub fn put(&mut self, value_ns: i64) {
        if self.records.is_empty() {
            return;
        }
        self.records[self.idx] = PingRecord {
            time: Instant::now(),
            value_ns,
        };
        self.idx = (self.idx + 1) % self.cap;
    }

    pub fn get_statistics(&self) -> HealthPingStats {
        let mut fail = 0i64;
        let mut max = 0i64;
        let mut min = i64::MAX;
        let mut sum = 0i64;
        let mut cnt = 0i64;
        let mut valid_rtts = Vec::new();

        let now = Instant::now();
        for r in &self.records {
            if r.value_ns == RTT_UNTESTED || now.duration_since(r.time) > self.validity {
                continue;
            }
            if r.value_ns == RTT_FAILED {
                fail += 1;
                continue;
            }
            cnt += 1;
            sum += r.value_ns;
            valid_rtts.push(r.value_ns);
            if r.value_ns > max {
                max = r.value_ns;
            }
            if r.value_ns < min {
                min = r.value_ns;
            }
        }

        let all = cnt + fail;
        if cnt == 0 {
            return HealthPingStats {
                all,
                fail,
                deviation: 0,
                average: 0,
                max: 0,
                min: 0,
            };
        }

        let average = sum / cnt;
        let std = if cnt < 2 {
            average / 2
        } else {
            let mut variance = 0.0f64;
            let avg_f = average as f64;
            for val in valid_rtts {
                variance += (val as f64 - avg_f).powi(2);
            }
            (variance / cnt as f64).sqrt() as i64
        };

        HealthPingStats {
            all,
            fail,
            deviation: std,
            average,
            max,
            min: if min == i64::MAX { 0 } else { min },
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundStatus {
    pub alive: bool,
    pub delay: i64,
    pub last_error_reason: String,
    pub outbound_tag: String,
    pub last_seen_time: i64,
    pub last_try_time: i64,
    pub health_ping: Option<HealthPingStats>,
}

pub struct Observatory {
    pub config: Option<ObservatoryConfig>,
    pub burst_config: Option<BurstObservatoryConfig>,
    status: RwLock<HashMap<String, OutboundStatus>>,
    burst_results: RwLock<HashMap<String, HealthPingRTTS>>,
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Observatory {
    pub fn from_config(root: &Value) -> Result<Option<Arc<Self>>, String> {
        let obs_val = root.get("observatory");
        let burst_val = root.get("burstObservatory");

        if (obs_val.is_none() || obs_val.unwrap().is_null())
            && (burst_val.is_none() || burst_val.unwrap().is_null())
        {
            return Ok(None);
        }

        let config = if let Some(v) = obs_val.filter(|v| !v.is_null()) {
            let subject_selector = v
                .get("subjectSelector")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let probe_url = v
                .get("probeURL")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_OBSERVATORY_PROBE_URL)
                .to_owned();
            let probe_interval = v
                .get("probeInterval")
                .and_then(Value::as_str)
                .and_then(parse_xray_duration)
                .unwrap_or(DEFAULT_PROBE_INTERVAL);
            let enable_concurrency = v
                .get("enableConcurrency")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(ObservatoryConfig {
                subject_selector,
                probe_url,
                probe_interval,
                enable_concurrency,
            })
        } else {
            None
        };

        let burst_config = if let Some(v) = burst_val.filter(|v| !v.is_null()) {
            let ping_config = v.get("pingConfig").ok_or_else(|| {
                "failed to build burst observatory configuration: BurstObservatory requires a valid pingConfig".to_string()
            })?;
            if ping_config.is_null() {
                return Err("failed to build burst observatory configuration: BurstObservatory requires a valid pingConfig".into());
            }

            let subject_selector = v
                .get("subjectSelector")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();

            let destination = ping_config
                .get("destination")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_BURST_DESTINATION)
                .to_owned();
            let connectivity = ping_config
                .get("connectivity")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let mut interval = ping_config
                .get("interval")
                .and_then(Value::as_str)
                .and_then(parse_xray_duration)
                .unwrap_or(DEFAULT_BURST_INTERVAL);
            if interval < MIN_BURST_INTERVAL {
                log::warn("health check interval is too small, 10s is applied");
                interval = MIN_BURST_INTERVAL;
            }
            let sampling_count = match ping_config.get("sampling").and_then(Value::as_u64) {
                Some(n) if n > i32::MAX as u64 => {
                    return Err("burst observatory: sampling is out of range".into())
                }
                Some(n) if n > 0 => n as usize,
                _ => DEFAULT_SAMPLING_COUNT,
            };
            let timeout = ping_config
                .get("timeout")
                .and_then(Value::as_str)
                .and_then(parse_xray_duration)
                .unwrap_or(DEFAULT_PROBE_TIMEOUT);
            let http_method = ping_config
                .get("httpMethod")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("HEAD")
                .to_owned();

            Some(BurstObservatoryConfig {
                subject_selector,
                destination,
                connectivity,
                interval,
                sampling_count,
                timeout,
                http_method,
            })
        } else {
            None
        };

        Ok(Some(Arc::new(Self {
            config,
            burst_config,
            status: RwLock::new(HashMap::new()),
            burst_results: RwLock::new(HashMap::new()),
        })))
    }

    pub fn get_observation(&self) -> Vec<OutboundStatus> {
        let map = self.status.read().unwrap();
        let mut list: Vec<OutboundStatus> = map.values().cloned().collect();
        list.sort_by(|a, b| a.outbound_tag.cmp(&b.outbound_tag));
        list
    }

    pub fn get_status_for(&self, tag: &str) -> Option<OutboundStatus> {
        let map = self.status.read().unwrap();
        map.get(tag).cloned()
    }

    pub fn update_status_for_probe(&self, tag: &str, result: Result<Duration, String>) {
        let now_sec = current_unix_time();
        let mut map = self.status.write().unwrap();
        let entry = map.entry(tag.to_owned()).or_insert_with(|| OutboundStatus {
            alive: false,
            delay: 99999999,
            last_error_reason: String::new(),
            outbound_tag: tag.to_owned(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        });
        entry.last_try_time = now_sec;
        match result {
            Ok(delay) => {
                entry.alive = true;
                entry.delay = delay.as_millis() as i64;
                entry.last_seen_time = now_sec;
                entry.last_error_reason.clear();
            }
            Err(e) => {
                entry.alive = false;
                entry.delay = 99999999;
                entry.last_error_reason = format!(
                    "the outbound {tag} is dead: GET request failed: {e} with outbound handler report underlying connection failed"
                );
            }
        }
    }

    pub fn update_status_for_burst(&self, tag: &str, result: Result<Duration, String>) {
        let now_sec = current_unix_time();
        let stats = {
            let mut results = self.burst_results.write().unwrap();
            let sampling_count = self
                .burst_config
                .as_ref()
                .map(|c| c.sampling_count)
                .unwrap_or(DEFAULT_SAMPLING_COUNT);
            let validity = self
                .burst_config
                .as_ref()
                .map(|c| c.interval * sampling_count as u32 * 2)
                .unwrap_or(Duration::from_secs(1200));
            let r = results
                .entry(tag.to_owned())
                .or_insert_with(|| HealthPingRTTS::new(sampling_count, validity));
            match result {
                Ok(d) => r.put(d.as_nanos() as i64),
                Err(_) => r.put(RTT_FAILED),
            }
            r.get_statistics()
        };

        let mut map = self.status.write().unwrap();
        let entry = map.entry(tag.to_owned()).or_insert_with(|| OutboundStatus {
            alive: false,
            delay: 99999999,
            last_error_reason: String::new(),
            outbound_tag: tag.to_owned(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        });
        entry.alive = stats.all != stats.fail;
        entry.delay = stats.average / 1_000_000;
        entry.last_try_time = now_sec;
        if entry.alive {
            entry.last_seen_time = now_sec;
            entry.last_error_reason.clear();
        }
        entry.health_ping = Some(stats);
    }

    pub fn start(self: Arc<Self>, router: Arc<Router>) {
        if let Some(config) = self.config.clone() {
            let obs = self.clone();
            let r = router.clone();
            tokio::spawn(async move {
                obs.run_observatory_loop(config, r).await;
            });
        }
        if let Some(burst) = self.burst_config.clone() {
            let obs = self.clone();
            let r = router.clone();
            tokio::spawn(async move {
                obs.run_burst_loop(burst, r).await;
            });
        }
    }

    async fn run_observatory_loop(&self, config: ObservatoryConfig, router: Arc<Router>) {
        if config.subject_selector.is_empty() {
            return;
        }
        let probe_interval = if config.probe_interval.is_zero() {
            DEFAULT_PROBE_INTERVAL
        } else {
            config.probe_interval
        };

        loop {
            let outbounds: Vec<String> = {
                let map = router.outbounds.read().unwrap();
                map.keys()
                    .filter(|tag| config.subject_selector.iter().any(|p| tag.starts_with(p)))
                    .cloned()
                    .collect()
            };

            {
                let mut map = self.status.write().unwrap();
                // The burst loop owns the tags matching its own selector.
                map.retain(|tag, _| {
                    outbounds.contains(tag)
                        || !config.subject_selector.iter().any(|p| tag.starts_with(p))
                });
            }

            if outbounds.is_empty() {
                tokio::time::sleep(probe_interval).await;
                continue;
            }

            if !config.enable_concurrency {
                let mut sorted = outbounds;
                sorted.sort();
                for tag in sorted {
                    let res = probe_outbound(
                        &router,
                        &tag,
                        &config.probe_url,
                        "GET",
                        DEFAULT_PROBE_TIMEOUT,
                    )
                    .await;
                    self.update_status_for_probe(&tag, res);
                    tokio::time::sleep(probe_interval).await;
                }
            } else {
                let mut tasks = Vec::new();
                for tag in outbounds {
                    let r = router.clone();
                    let url = config.probe_url.clone();
                    tasks.push(async move {
                        let res =
                            probe_outbound(&r, &tag, &url, "GET", DEFAULT_PROBE_TIMEOUT).await;
                        (tag, res)
                    });
                }
                let results = futures_util::future::join_all(tasks).await;
                for (tag, res) in results {
                    self.update_status_for_probe(&tag, res);
                }
                tokio::time::sleep(probe_interval).await;
            }
        }
    }

    async fn run_burst_loop(&self, burst: BurstObservatoryConfig, router: Arc<Router>) {
        if burst.subject_selector.is_empty() {
            return;
        }
        let interval = if burst.interval < MIN_BURST_INTERVAL {
            MIN_BURST_INTERVAL
        } else {
            burst.interval
        };

        // Initial immediate check
        let outbounds: Vec<String> = {
            let map = router.outbounds.read().unwrap();
            map.keys()
                .filter(|tag| burst.subject_selector.iter().any(|p| tag.starts_with(p)))
                .cloned()
                .collect()
        };
        for tag in &outbounds {
            let res = probe_outbound(
                &router,
                tag,
                &burst.destination,
                &burst.http_method,
                burst.timeout,
            )
            .await;
            self.update_status_for_burst(tag, res);
        }

        let loop_interval = interval * (burst.sampling_count as u32);
        let mut ticker = tokio::time::interval(loop_interval);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let outbounds: Vec<String> = {
                let map = router.outbounds.read().unwrap();
                map.keys()
                    .filter(|tag| burst.subject_selector.iter().any(|p| tag.starts_with(p)))
                    .cloned()
                    .collect()
            };
            if outbounds.is_empty() {
                continue;
            }

            {
                let mut res = self.burst_results.write().unwrap();
                res.retain(|tag, _| outbounds.contains(tag));
                let mut map = self.status.write().unwrap();
                map.retain(|tag, _| {
                    outbounds.contains(tag)
                        || !burst.subject_selector.iter().any(|p| tag.starts_with(p))
                });
            }

            for tag in &outbounds {
                let res = probe_outbound(
                    &router,
                    tag,
                    &burst.destination,
                    &burst.http_method,
                    burst.timeout,
                )
                .await;
                self.update_status_for_burst(tag, res);
            }
        }
    }
}

pub async fn probe_outbound(
    router: &Router,
    outbound_tag: &str,
    target_url: &str,
    http_method: &str,
    probe_timeout: Duration,
) -> Result<Duration, String> {
    timeout(
        probe_timeout,
        probe_outbound_inner(router, outbound_tag, target_url, http_method),
    )
    .await
    .map_err(|_| "probe timed out".to_string())?
}

async fn probe_outbound_inner(
    router: &Router,
    outbound_tag: &str,
    target_url: &str,
    http_method: &str,
) -> Result<Duration, String> {
    let uri: http::Uri = target_url
        .parse()
        .map_err(|e| format!("invalid URL {target_url:?}: {e}"))?;
    let is_https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        other => return Err(format!("unsupported scheme {other:?}")),
    };
    let host = uri
        .host()
        .ok_or_else(|| "missing host in URL".to_string())?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
    let host_authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let decision = router.decision_for_tag(outbound_tag);
    let host_enum = match host.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(host.clone()),
    };

    let start = Instant::now();
    let stream = outbound::connect(router, &decision, &host_enum, port)
        .await
        .map_err(|e| format!("connect error: {e}"))?;

    let mut stream: Box<dyn Stream> = if is_https {
        let tls_connector = xray_transport::TlsConnector::system()
            .map_err(|e| format!("tls connector error: {e}"))?;
        let is_loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
        let tls_config = xray_transport::TlsClientConfig {
            server_name: host.clone(),
            allow_insecure: is_loopback,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: vec!["http/1.1".to_string()],
            fingerprint: None,
        };
        let client_config = tls_connector
            .client_config_for(&tls_config)
            .map_err(|e| format!("tls config error: {e}"))?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
            .map_err(|e| format!("invalid server name {host:?}: {e}"))?;
        let tokio_tls = tokio_rustls::TlsConnector::from(client_config);
        let tls_stream = tokio_tls
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("tls handshake error: {e}"))?;
        Box::new(tls_stream)
    } else {
        stream
    };

    let mut headers = xray_transport::stream::HeaderMap::new();
    xray_transport::stream::apply_masquerade(&mut headers, "nav");
    let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
        host_authority.clone()
    } else {
        format!("{host_authority}:{port}")
    };
    let mut req_bytes = xray_transport::stream::serialize_request(
        http_method,
        path_and_query,
        &host_header,
        &headers,
    );
    req_bytes.truncate(req_bytes.len() - 2);
    req_bytes.extend_from_slice(b"Accept-Encoding: gzip\r\n\r\n");

    stream
        .write_all(&req_bytes)
        .await
        .map_err(|e| format!("write error: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush error: {e}"))?;

    let mut line_buf = [0u8; 1024];
    let mut n_read = 0;
    while n_read < line_buf.len() {
        let n = stream
            .read(&mut line_buf[n_read..n_read + 1])
            .await
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
        n_read += 1;
        if n_read >= 2 && &line_buf[n_read - 2..n_read] == b"\r\n" {
            break;
        }
        if n_read >= 1 && line_buf[n_read - 1] == b'\n' {
            break;
        }
    }
    if n_read == 0 {
        return Err("empty response".to_string());
    }
    let status_line =
        std::str::from_utf8(&line_buf[..n_read]).map_err(|e| format!("utf8 error: {e}"))?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 || parts[1].parse::<u16>().is_err() {
        return Err(format!("malformed status line: {status_line:?}"));
    }

    Ok(start.elapsed())
}
