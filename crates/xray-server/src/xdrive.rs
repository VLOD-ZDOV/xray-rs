//! The xdrive transport (transport/internet/xdrive in official Xray-core).
//!
//! A stream transport backed by storage (local filesystem, Google Drive, S3, template).
//! Non-slot stores (such as local storage) use a Write-Ahead Log (WAL) of segments:
//! - Sessions announced in `sessions/<unix_nano>-<session_id>`.
//! - Streams carried in `streams/<session_id>/c2s/` (uplink) and `streams/<session_id>/s2c/` (downlink).
//! - Segments named `%09d.seg` (e.g. `000000000.seg`, `000000001.seg`).
//! - End of stream marked by `%09d.end` on clean close.
//! - Error marked by `%09d.err`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};

use xray_proxy::vless::VisionStreamIo;

#[derive(Clone)]
pub struct CancellationToken {
    notify: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub const DEFAULT_SEGMENT_BYTES: usize = 512 * 1024;
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(20);
pub const DEFAULT_MIN_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const DEFAULT_MAX_POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const DEFAULT_EAGER_WINDOW: Duration = Duration::from_millis(2000);
pub const DEFAULT_HOLE_TIMEOUT: Duration = Duration::from_millis(30000);
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);
pub const DEFAULT_CONCURRENCY: usize = 8;

pub const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CONCURRENCY: usize = 64;
pub const MAX_COALESCED_TICKS: usize = 8;

pub const SESSIONS_DIR: &str = "sessions";
pub const STREAMS_DIR: &str = "streams";
pub const UPLINK_DIR: &str = "c2s";
pub const DOWNLINK_DIR: &str = "s2c";

pub const SEG_SUFFIX: &str = ".seg";
pub const END_SUFFIX: &str = ".end";
pub const ERR_SUFFIX: &str = ".err";

const TEMP_PREFIX: &str = ".xdrive-tmp-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdriveParams {
    pub segment_bytes: usize,
    pub flush_interval: Duration,
    pub min_poll_interval: Duration,
    pub max_poll_interval: Duration,
    pub eager_window: Duration,
    pub hole_timeout: Duration,
    pub session_ttl: Duration,
    pub concurrency: usize,
}

impl Default for XdriveParams {
    fn default() -> Self {
        Self {
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            min_poll_interval: DEFAULT_MIN_POLL_INTERVAL,
            max_poll_interval: DEFAULT_MAX_POLL_INTERVAL,
            eager_window: DEFAULT_EAGER_WINDOW,
            hole_timeout: DEFAULT_HOLE_TIMEOUT,
            session_ttl: DEFAULT_SESSION_TTL,
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdriveConfig {
    pub remote_folder: String,
    pub service: String,
    pub secrets: Vec<String>,
    pub params: XdriveParams,
}

pub fn parse_xdrive_settings(settings: &Value) -> Result<XdriveConfig, String> {
    let service = settings
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let remote_folder = settings
        .get("remoteFolder")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let secrets: Vec<String> = settings
        .get("secrets")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let service = match service.as_str() {
        "local" => "local".to_string(),
        "Google Drive" => "google-drive".to_string(),
        "google-drive" => "google-drive".to_string(),
        "template" => "template".to_string(),
        "s3" => "s3".to_string(),
        _ => {
            return Err(format!(
                r#"unknown "service": "{service}", use "google-drive", "template", "s3" or "local""#
            ));
        }
    };

    match service.as_str() {
        "local" => {
            if remote_folder.is_empty() {
                return Err(r#"empty "remoteFolder""#.into());
            }
        }
        "google-drive" => {
            if remote_folder.is_empty() {
                return Err(r#"empty "remoteFolder", it must be a Google Drive folder id"#.into());
            }
            if secrets.len() != 3 {
                return Err(
                    "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken"
                        .into(),
                );
            }
            for (i, s) in secrets.iter().enumerate() {
                if s.is_empty() {
                    return Err(format!("Google Drive secret {i} is empty"));
                }
            }
        }
        "template"
            if settings.get("template").is_none()
                || settings.get("template") == Some(&Value::Null) =>
        {
            return Err(r#"service "template" needs a "template" object"#.into());
        }
        "s3" if settings.get("s3").is_none() || settings.get("s3") == Some(&Value::Null) => {
            return Err(r#"service "s3" needs an "s3" object"#.into());
        }
        _ => {}
    }
    // Only local storage is implemented; the others would quietly fall back to it.
    if service != "local" {
        return Err(format!(
            r#"xdrive "service": "{service}" is not supported yet, only "local""#
        ));
    }

    let segment_bytes = settings
        .get("segmentBytes")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).min(MAX_SEGMENT_BYTES))
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_SEGMENT_BYTES);

    let flush_interval = settings
        .get("flushIntervalMs")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_FLUSH_INTERVAL);

    let min_poll_interval = settings
        .get("pollIntervalMs")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_MIN_POLL_INTERVAL);

    let mut max_poll_interval = settings
        .get("maxPollIntervalMs")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_MAX_POLL_INTERVAL);
    if max_poll_interval < min_poll_interval {
        max_poll_interval = min_poll_interval;
    }

    let eager_window = settings
        .get("eagerWindowMs")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_EAGER_WINDOW);

    let hole_timeout = settings
        .get("holeTimeoutMs")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_HOLE_TIMEOUT);

    let session_ttl = settings
        .get("sessionTtlSeconds")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_SESSION_TTL);

    let concurrency = settings
        .get("concurrency")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).min(MAX_CONCURRENCY))
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_CONCURRENCY);

    Ok(XdriveConfig {
        remote_folder,
        service,
        secrets,
        params: XdriveParams {
            segment_bytes,
            flush_interval,
            min_poll_interval,
            max_poll_interval,
            eager_window,
            hole_timeout,
            session_ttl,
            concurrency,
        },
    })
}

// ---------------------------------------------------------------------------
// LocalStorage: POSIX filesystem operations with atomic temp-rename
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let clean = name.trim_matches('/');
        if clean.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid object name: {name}"),
            ));
        }
        for part in clean.split('/') {
            if part == ".." || part == "." || part.starts_with(TEMP_PREFIX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("reserved or invalid object name: {name}"),
                ));
            }
        }
        Ok(self.root.join(clean))
    }

    pub async fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let full = self.resolve(name)?;
        let dir = full.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing parent directory")
        })?;
        tokio::fs::create_dir_all(dir).await?;

        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let tmp_name = format!("{TEMP_PREFIX}{}-{id}-{nanos:x}", std::process::id());
        let tmp_path = dir.join(tmp_name);

        let res = async {
            // create_new (O_EXCL) never follows a symlink planted at the temp name.
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .await?;
            file.write_all(data).await?;
            file.flush().await?;
            file.sync_all().await?;
            Ok::<(), io::Error>(())
        }
        .await;

        if let Err(e) = res {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }

        if let Err(e) = tokio::fs::rename(&tmp_path, &full).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
        Ok(())
    }

    pub async fn get(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let full = self.resolve(name)?;
        use tokio::io::AsyncReadExt;
        // The folder is shared with the peer: O_NONBLOCK keeps a FIFO from
        // blocking the open, and the type is checked on the opened file itself.
        let file = match tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&full)
            .await
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if !file.metadata().await?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xdrive entry is not a regular file",
            ));
        }
        // The folder is shared with the peer, so the file size is untrusted.
        let mut data = Vec::new();
        file.take(MAX_SEGMENT_BYTES as u64 + 1)
            .read_to_end(&mut data)
            .await?;
        if data.len() > MAX_SEGMENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xdrive segment is too large",
            ));
        }
        Ok(Some(data))
    }

    pub async fn delete(&self, name: &str) -> io::Result<()> {
        let full = self.resolve(name)?;
        match tokio::fs::metadata(&full).await {
            Ok(meta) => {
                if meta.is_dir() {
                    let _ = tokio::fs::remove_dir_all(&full).await;
                } else {
                    let _ = tokio::fs::remove_file(&full).await;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let full = self.resolve(prefix)?;
        let mut read_dir = match tokio::fs::read_dir(&full).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut entries = Vec::new();
        while let Some(entry) = read_dir.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            entries.push(name);
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Helpers: object naming, parsing
// ---------------------------------------------------------------------------

pub fn object_name(prefix: &str, seq: i64, suffix: &str) -> String {
    format!("{prefix}/{seq:09}{suffix}")
}

pub fn parse_entry(name: &str) -> Option<(i64, &'static str)> {
    let dot = name.rfind('.')?;
    let suffix = match &name[dot..] {
        SEG_SUFFIX => SEG_SUFFIX,
        END_SUFFIX => END_SUFFIX,
        ERR_SUFFIX => ERR_SUFFIX,
        _ => return None,
    };
    let seq = name[..dot].parse::<i64>().ok()?;
    if seq < 0 {
        return None;
    }
    Some((seq, suffix))
}

pub fn announce_name(session: &str, at: SystemTime) -> String {
    let nanos = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{SESSIONS_DIR}/{nanos}-{session}")
}

pub fn parse_announce(entry: &str) -> Option<(String, u64)> {
    let (nanos_str, session) = entry.split_once('-')?;
    if nanos_str.is_empty() || session.is_empty() {
        return None;
    }
    let nanos = nanos_str.parse::<u64>().ok()?;
    Some((session.to_string(), nanos))
}

// ---------------------------------------------------------------------------
// WalWriter
// ---------------------------------------------------------------------------

struct WalWriterState {
    buf: Vec<u8>,
    seq: i64,
    last_size: usize,
    held: usize,
    closed: bool,
    err: Option<io::Error>,
}

pub struct WalWriter {
    storage: Arc<LocalStorage>,
    prefix: String,
    params: XdriveParams,
    state: Arc<Mutex<WalWriterState>>,
    sem: Arc<Semaphore>,
    active_uploads: Arc<AtomicUsize>,
    upload_done: Arc<Notify>,
    cancel_token: CancellationToken,
}

impl WalWriter {
    pub fn new(
        storage: Arc<LocalStorage>,
        prefix: String,
        params: XdriveParams,
        cancel_token: CancellationToken,
    ) -> Self {
        let state = Arc::new(Mutex::new(WalWriterState {
            buf: Vec::new(),
            seq: 0,
            last_size: 0,
            held: 0,
            closed: false,
            err: None,
        }));
        let sem = Arc::new(Semaphore::new(params.concurrency));
        let active_uploads = Arc::new(AtomicUsize::new(0));
        let upload_done = Arc::new(Notify::new());

        let writer = Self {
            storage,
            prefix,
            params,
            state,
            sem,
            active_uploads,
            upload_done,
            cancel_token,
        };

        writer.start_flush_loop();
        writer
    }

    fn start_flush_loop(&self) {
        let state = Arc::clone(&self.state);
        let storage = Arc::clone(&self.storage);
        let prefix = self.prefix.clone();
        let sem = Arc::clone(&self.sem);
        let active_uploads = Arc::clone(&self.active_uploads);
        let upload_done = Arc::clone(&self.upload_done);
        let params = self.params.clone();
        let cancel_token = self.cancel_token.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(params.flush_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => return,
                    _ = interval.tick() => {
                        let to_upload = {
                            let mut st = state.lock().await;
                            if st.closed || st.err.is_some() || st.buf.is_empty() {
                                if st.closed || st.err.is_some() {
                                    return;
                                }
                                None
                            } else {
                                let grew = st.buf.len() > st.last_size;
                                st.last_size = st.buf.len();
                                if grew && st.held < MAX_COALESCED_TICKS {
                                    st.held += 1;
                                    None
                                } else {
                                    st.held = 0;
                                    Self::take_segment_locked(&mut st, params.segment_bytes)
                                }
                            }
                        };

                        if let Some((seq, chunk)) = to_upload {
                            Self::spawn_upload(
                                storage.clone(),
                                prefix.clone(),
                                seq,
                                chunk,
                                sem.clone(),
                                active_uploads.clone(),
                                upload_done.clone(),
                                state.clone(),
                                cancel_token.clone(),
                            );
                        }
                    }
                }
            }
        });
    }

    fn take_segment_locked(
        st: &mut WalWriterState,
        segment_bytes: usize,
    ) -> Option<(i64, Vec<u8>)> {
        if st.buf.is_empty() || st.err.is_some() {
            return None;
        }
        let n = st.buf.len().min(segment_bytes);
        let chunk = st.buf.drain(..n).collect();
        let seq = st.seq;
        st.seq += 1;
        st.last_size = st.buf.len();
        st.held = 0;
        Some((seq, chunk))
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_upload(
        storage: Arc<LocalStorage>,
        prefix: String,
        seq: i64,
        chunk: Vec<u8>,
        sem: Arc<Semaphore>,
        active_uploads: Arc<AtomicUsize>,
        upload_done: Arc<Notify>,
        state: Arc<Mutex<WalWriterState>>,
        cancel_token: CancellationToken,
    ) {
        active_uploads.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let _permit = tokio::select! {
                p = sem.acquire() => match p {
                    Ok(permit) => permit,
                    Err(_) => {
                        active_uploads.fetch_sub(1, Ordering::SeqCst);
                        upload_done.notify_waiters();
                        return;
                    }
                },
                _ = cancel_token.cancelled() => {
                    active_uploads.fetch_sub(1, Ordering::SeqCst);
                    upload_done.notify_waiters();
                    return;
                }
            };

            let obj = object_name(&prefix, seq, SEG_SUFFIX);
            if let Err(e) = storage.put(&obj, &chunk).await {
                {
                    let mut st = state.lock().await;
                    if st.err.is_none() {
                        st.err = Some(io::Error::other(format!("failed to store segment: {e}")));
                    }
                }
                let err_obj = object_name(&prefix, seq, ERR_SUFFIX);
                let _ = storage.put(&err_obj, &[]).await;
            }

            active_uploads.fetch_sub(1, Ordering::SeqCst);
            upload_done.notify_waiters();
        });
    }

    pub async fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut segments = Vec::new();
        {
            let mut st = self.state.lock().await;
            if let Some(ref e) = st.err {
                return Err(io::Error::new(e.kind(), e.to_string()));
            }
            if st.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed writer"));
            }
            st.buf.extend_from_slice(data);
            while st.buf.len() >= self.params.segment_bytes {
                if let Some(item) = Self::take_segment_locked(&mut st, self.params.segment_bytes) {
                    segments.push(item);
                }
            }
        }

        for (seq, chunk) in segments {
            Self::spawn_upload(
                self.storage.clone(),
                self.prefix.clone(),
                seq,
                chunk,
                self.sem.clone(),
                self.active_uploads.clone(),
                self.upload_done.clone(),
                self.state.clone(),
                self.cancel_token.clone(),
            );
        }

        Ok(data.len())
    }

    pub async fn shutdown(&self) -> io::Result<()> {
        let mut segments = Vec::new();
        let final_seq = {
            let mut st = self.state.lock().await;
            if st.closed {
                return Ok(());
            }
            st.closed = true;
            while !st.buf.is_empty() && st.err.is_none() {
                if let Some(item) = Self::take_segment_locked(&mut st, self.params.segment_bytes) {
                    segments.push(item);
                }
            }
            st.seq
        };

        for (seq, chunk) in segments {
            Self::spawn_upload(
                self.storage.clone(),
                self.prefix.clone(),
                seq,
                chunk,
                self.sem.clone(),
                self.active_uploads.clone(),
                self.upload_done.clone(),
                self.state.clone(),
                self.cancel_token.clone(),
            );
        }

        // Wait for all in-flight uploads to complete
        loop {
            let notified = self.upload_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active_uploads.load(Ordering::SeqCst) == 0 {
                break;
            }
            notified.await;
        }

        {
            let st = self.state.lock().await;
            if let Some(ref e) = st.err {
                return Err(io::Error::new(e.kind(), e.to_string()));
            }
        }

        // Write end marker
        let end_obj = object_name(&self.prefix, final_seq, END_SUFFIX);
        self.storage.put(&end_obj, &[]).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WalReader
// ---------------------------------------------------------------------------

pub struct WalReader {
    chunk_rx: mpsc::Receiver<io::Result<Bytes>>,
    wake_tx: Arc<Notify>,
}

impl WalReader {
    pub fn new(
        storage: Arc<LocalStorage>,
        prefix: String,
        params: XdriveParams,
        cancel_token: CancellationToken,
    ) -> Self {
        let (chunk_tx, chunk_rx) = mpsc::channel(params.concurrency.max(1));
        let wake_tx = Arc::new(Notify::new());

        let wake_rx = Arc::clone(&wake_tx);
        tokio::spawn(async move {
            Self::run_poll_loop(storage, prefix, params, chunk_tx, wake_rx, cancel_token).await;
        });

        Self { chunk_rx, wake_tx }
    }

    pub fn wake(&self) {
        self.wake_tx.notify_one();
    }

    async fn run_poll_loop(
        storage: Arc<LocalStorage>,
        prefix: String,
        params: XdriveParams,
        chunk_tx: mpsc::Sender<io::Result<Bytes>>,
        wake_rx: Arc<Notify>,
        cancel_token: CancellationToken,
    ) {
        let mut seq: i64 = 0;
        let mut delay = params.min_poll_interval;
        let mut active = Instant::now();
        let mut hole_since: Option<Instant> = None;

        loop {
            let polled = Instant::now();
            let poll_res = Self::poll_once(
                &storage,
                &prefix,
                &params,
                &mut seq,
                &mut hole_since,
                &chunk_tx,
                &cancel_token,
            )
            .await;

            match poll_res {
                Err(e) => {
                    let _ = chunk_tx.send(Err(e)).await;
                    return;
                }
                Ok((_advanced, true)) => {
                    // Clean EOF
                    return;
                }
                Ok((advanced, false)) => {
                    if advanced {
                        active = Instant::now();
                        delay = params.min_poll_interval;
                    } else if active.elapsed() < params.eager_window {
                        delay = params.min_poll_interval;
                    } else {
                        delay = (delay * 2).min(params.max_poll_interval);
                    }
                }
            }

            tokio::select! {
                _ = cancel_token.cancelled() => return,
                _ = tokio::time::sleep(delay) => {},
                _ = wake_rx.notified() => {
                    active = Instant::now();
                    delay = params.min_poll_interval;
                    let elapsed = polled.elapsed();
                    if elapsed < params.min_poll_interval {
                        let rest = params.min_poll_interval - elapsed;
                        tokio::select! {
                            _ = cancel_token.cancelled() => return,
                            _ = tokio::time::sleep(rest) => {}
                        }
                    }
                }
            }
        }
    }

    async fn poll_once(
        storage: &Arc<LocalStorage>,
        prefix: &str,
        params: &XdriveParams,
        seq: &mut i64,
        hole_since: &mut Option<Instant>,
        chunk_tx: &mpsc::Sender<io::Result<Bytes>>,
        cancel_token: &CancellationToken,
    ) -> io::Result<(bool, bool)> {
        let listed = storage.list(prefix).await?;
        if listed.is_empty() {
            return Ok((false, false));
        }

        let mut pending = HashMap::with_capacity(listed.len());
        let mut ahead = false;
        for entry in &listed {
            if let Some((s, suffix)) = parse_entry(entry) {
                pending.insert(s, (entry.clone(), suffix));
                if s > *seq {
                    ahead = true;
                }
            }
        }

        if !pending.contains_key(seq) && ahead {
            match *hole_since {
                None => *hole_since = Some(Instant::now()),
                Some(since) if since.elapsed() >= params.hole_timeout => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!(
                            "segment {seq} never arrived while later ones did, the peer lost it"
                        ),
                    ));
                }
                _ => {}
            }
        } else {
            *hole_since = None;
        }

        let mut advanced = false;
        loop {
            if let Some((name, suffix)) = pending.get(seq) {
                if *suffix == ERR_SUFFIX {
                    let _ = storage.delete(&format!("{prefix}/{name}")).await;
                    return Err(io::Error::other(format!(
                        "the peer could not store segment {seq}"
                    )));
                }
            }

            // Find batch of contiguous segments starting from *seq
            let mut batch = Vec::new();
            let mut done = false;
            for i in 0..params.concurrency {
                let target_seq = *seq + i as i64;
                match pending.get(&target_seq) {
                    Some((name, suffix)) if *suffix == SEG_SUFFIX => {
                        batch.push((target_seq, name.clone()));
                    }
                    Some((name, suffix)) if *suffix == END_SUFFIX && i == 0 => {
                        let _ = storage.delete(&format!("{prefix}/{name}")).await;
                        done = true;
                        break;
                    }
                    _ => break,
                }
            }

            if done {
                return Ok((advanced, true));
            }
            if batch.is_empty() {
                return Ok((advanced, false));
            }

            // Fetch segments
            for (curr_seq, name) in batch {
                let full_name = format!("{prefix}/{name}");
                match storage.get(&full_name).await? {
                    Some(data) => {
                        tokio::select! {
                            _ = cancel_token.cancelled() => return Ok((advanced, true)),
                            res = chunk_tx.send(Ok(Bytes::from(data))) => {
                                if res.is_err() {
                                    return Ok((advanced, true));
                                }
                            }
                        }
                        *seq = curr_seq + 1;
                        advanced = true;
                        let st = storage.clone();
                        tokio::spawn(async move {
                            let _ = st.delete(&full_name).await;
                        });
                    }
                    None => {
                        // File not found (e.g. peer deleted or in-flight), retry next tick
                        return Ok((advanced, false));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// XdriveStream: AsyncRead + AsyncWrite + VisionStreamIo
// ---------------------------------------------------------------------------

pub struct XdriveStream {
    writer: Arc<WalWriter>,
    reader: WalReader,
    current_chunk: Option<Bytes>,
    chunk_offset: usize,
    cancel_token: CancellationToken,
    write_fut: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
    shutdown_fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}

impl XdriveStream {
    pub fn new(
        storage: Arc<LocalStorage>,
        write_prefix: String,
        read_prefix: String,
        params: XdriveParams,
    ) -> Self {
        let cancel_token = CancellationToken::new();
        let writer = Arc::new(WalWriter::new(
            storage.clone(),
            write_prefix,
            params.clone(),
            cancel_token.clone(),
        ));
        let reader = WalReader::new(storage, read_prefix, params, cancel_token.clone());

        Self {
            writer,
            reader,
            current_chunk: None,
            chunk_offset: 0,
            cancel_token,
            write_fut: None,
            shutdown_fut: None,
        }
    }
}

impl Drop for XdriveStream {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl AsyncRead for XdriveStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref chunk) = self.current_chunk {
                let chunk_len = chunk.len();
                let avail = chunk_len - self.chunk_offset;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&chunk[self.chunk_offset..self.chunk_offset + to_copy]);
                self.chunk_offset += to_copy;
                if self.chunk_offset >= chunk_len {
                    self.current_chunk = None;
                    self.chunk_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.reader.chunk_rx).poll_recv(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    self.current_chunk = Some(bytes);
                    self.chunk_offset = 0;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for XdriveStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_none() {
            let writer = Arc::clone(&self.writer);
            let bytes = data.to_vec();
            self.write_fut = Some(Box::pin(async move { writer.write(&bytes).await }));
        }

        let fut = self.write_fut.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(res) => {
                self.write_fut = None;
                if res.is_ok() {
                    self.reader.wake();
                }
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_fut.is_none() {
            let writer = Arc::clone(&self.writer);
            self.shutdown_fut = Some(Box::pin(async move { writer.shutdown().await }));
        }

        let fut = self.shutdown_fut.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(res) => {
                self.shutdown_fut = None;
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl VisionStreamIo for XdriveStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

// ---------------------------------------------------------------------------
// Dialer (Client Outbound side)
// ---------------------------------------------------------------------------

pub async fn dial(config: &XdriveConfig) -> io::Result<XdriveStream> {
    let storage = Arc::new(LocalStorage::new(&config.remote_folder)?);
    let session_id = hex_encode(&rand::random::<[u8; 16]>());
    let announce = announce_name(&session_id, SystemTime::now());

    storage.put(&announce, &[]).await?;

    let write_prefix = format!("{STREAMS_DIR}/{session_id}/{UPLINK_DIR}");
    let read_prefix = format!("{STREAMS_DIR}/{session_id}/{DOWNLINK_DIR}");

    Ok(XdriveStream::new(
        storage,
        write_prefix,
        read_prefix,
        config.params.clone(),
    ))
}

// ---------------------------------------------------------------------------
// Listener (Server Inbound side)
// ---------------------------------------------------------------------------

pub struct XdriveListener {
    storage: Arc<LocalStorage>,
    params: XdriveParams,
    active: Arc<Mutex<HashSet<String>>>,
    handled: Arc<Mutex<HashMap<String, Instant>>>,
    idle_since: Arc<Mutex<HashMap<String, Instant>>>,
    cancel_token: CancellationToken,
}

impl XdriveListener {
    pub fn new(
        storage: Arc<LocalStorage>,
        params: XdriveParams,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            storage,
            params,
            active: Arc::new(Mutex::new(HashSet::new())),
            handled: Arc::new(Mutex::new(HashMap::new())),
            idle_since: Arc::new(Mutex::new(HashMap::new())),
            cancel_token,
        }
    }

    pub fn start_cleanup_loop(&self) {
        let storage = Arc::clone(&self.storage);
        let active = Arc::clone(&self.active);
        let handled = Arc::clone(&self.handled);
        let idle_since = Arc::clone(&self.idle_since);
        let session_ttl = self.params.session_ttl;
        let cancel_token = self.cancel_token.clone();

        tokio::spawn(async move {
            let interval = (session_ttl / 2).max(Duration::from_millis(500));
            let mut timer = tokio::time::interval(interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => return,
                    _ = timer.tick() => {
                        let sessions = match storage.list(STREAMS_DIR).await {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                        let now = Instant::now();
                        let mut expired = Vec::new();
                        {
                            let act = active.lock().await;
                            let mut idle = idle_since.lock().await;
                            let mut hand = handled.lock().await;

                            let present: HashSet<String> = sessions.into_iter().collect();
                            for session in &present {
                                if act.contains(session) {
                                    idle.remove(session);
                                    continue;
                                }
                                match idle.get(session) {
                                    None => {
                                        idle.insert(session.clone(), now);
                                    }
                                    Some(&since) => {
                                        if now.duration_since(since) >= session_ttl {
                                            expired.push(session.clone());
                                            idle.remove(session);
                                        }
                                    }
                                }
                            }
                            idle.retain(|k, _| present.contains(k));
                            hand.retain(|k, &mut at| act.contains(k) || now.duration_since(at) < session_ttl);
                        }

                        for session in expired {
                            let _ = storage.delete(&format!("{STREAMS_DIR}/{session}")).await;
                        }
                    }
                }
            }
        });
    }

    pub async fn accept_pending(&self) -> io::Result<(bool, Vec<String>)> {
        let sessions = self.storage.list(SESSIONS_DIR).await?;
        let mut accepted = Vec::new();

        for entry in sessions {
            let full = format!("{SESSIONS_DIR}/{entry}");
            let (session, nanos) = match parse_announce(&entry) {
                Some(res) => res,
                None => {
                    let st = self.storage.clone();
                    tokio::spawn(async move {
                        let _ = st.delete(&full).await;
                    });
                    continue;
                }
            };

            let now_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            if now_nanos > nanos
                && (now_nanos - nanos) / 1_000_000_000 > self.params.session_ttl.as_secs()
            {
                let st = self.storage.clone();
                let sess = session.clone();
                tokio::spawn(async move {
                    let _ = st.delete(&full).await;
                    let _ = st.delete(&format!("{STREAMS_DIR}/{sess}")).await;
                });
                continue;
            }

            let claimed = {
                let mut act = self.active.lock().await;
                let mut hand = self.handled.lock().await;
                if act.contains(&session) || hand.contains_key(&session) {
                    false
                } else {
                    act.insert(session.clone());
                    hand.insert(session.clone(), Instant::now());
                    true
                }
            };

            if claimed {
                let st = self.storage.clone();
                tokio::spawn(async move {
                    let _ = st.delete(&full).await;
                });
                accepted.push(session);
            }
        }

        let is_any = !accepted.is_empty();
        Ok((is_any, accepted))
    }
}

pub async fn start_inbound(
    _inbound: &crate::config::Inbound,
    ctx: Arc<crate::vless::Context>,
    settings: Arc<XdriveConfig>,
) -> Result<tokio::task::AbortHandle, String> {
    let storage = Arc::new(LocalStorage::new(&settings.remote_folder).map_err(|e| e.to_string())?);
    let cancel_token = CancellationToken::new();
    let listener = XdriveListener::new(
        storage.clone(),
        settings.params.clone(),
        cancel_token.clone(),
    );
    listener.start_cleanup_loop();

    let task = tokio::spawn(async move {
        // Aborting the task (RemoveInbound) must also stop the cleanup loop.
        let _stop_cleanup = CancelOnDrop(cancel_token.clone());
        let mut delay = settings.params.min_poll_interval;
        let mut active = Instant::now();

        loop {
            let (accepted, sessions) = match listener.accept_pending().await {
                Ok(res) => res,
                Err(e) => {
                    crate::log::warn(format!("xdrive listener: failed to list sessions: {e}"));
                    (false, Vec::new())
                }
            };

            for session_id in sessions {
                let vless_ctx = Arc::clone(&ctx);
                let storage = Arc::clone(&storage);
                let params = settings.params.clone();
                let active_set = Arc::clone(&listener.active);
                let sess = session_id.clone();

                tokio::spawn(async move {
                    let write_prefix = format!("{STREAMS_DIR}/{sess}/{DOWNLINK_DIR}");
                    let read_prefix = format!("{STREAMS_DIR}/{sess}/{UPLINK_DIR}");
                    let stream = XdriveStream::new(storage, write_prefix, read_prefix, params);
                    let peer = "127.0.0.1:0".parse().unwrap();
                    let tls = crate::fallback::TlsInfo::default();

                    let res = crate::vless::serve_stream(stream, &vless_ctx, peer, &tls).await;
                    if let Err(e) = res {
                        crate::log::debug(format!("xdrive session {sess} closed: {e}"));
                    }
                    active_set.lock().await.remove(&sess);
                });
            }

            if accepted {
                active = Instant::now();
                delay = settings.params.min_poll_interval;
            } else if active.elapsed() < settings.params.eager_window {
                delay = settings.params.min_poll_interval;
            } else {
                delay = (delay * 2).min(settings.params.max_poll_interval);
            }

            tokio::select! {
                _ = cancel_token.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
            }
        }
    });

    Ok(task.abort_handle())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_storage_get_rejects_oversized_files() {
        let dir = std::env::temp_dir().join(format!("xdrive-test-{}", rand::random::<u64>()));
        let storage = LocalStorage::new(&dir).unwrap();
        let f = std::fs::File::create(dir.join("big.seg")).unwrap();
        f.set_len(MAX_SEGMENT_BYTES as u64 + 1).unwrap();
        assert!(storage.get("big.seg").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_local_storage_crud() {
        let temp_dir = std::env::temp_dir().join(format!("xdrive-test-{}", rand::random::<u64>()));
        let storage = LocalStorage::new(&temp_dir).unwrap();

        storage
            .put("foo/bar/baz.txt", b"hello world")
            .await
            .unwrap();
        let read = storage.get("foo/bar/baz.txt").await.unwrap();
        assert_eq!(read.as_deref(), Some(&b"hello world"[..]));

        let list = storage.list("foo/bar").await.unwrap();
        assert_eq!(list, vec!["baz.txt".to_string()]);

        storage.delete("foo/bar/baz.txt").await.unwrap();
        assert_eq!(storage.get("foo/bar/baz.txt").await.unwrap(), None);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_xdrive_stream_transfer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let temp_dir =
            std::env::temp_dir().join(format!("xdrive-stream-test-{}", rand::random::<u64>()));
        let storage = Arc::new(LocalStorage::new(&temp_dir).unwrap());

        let params = XdriveParams {
            segment_bytes: 4096,
            flush_interval: Duration::from_millis(5),
            min_poll_interval: Duration::from_millis(5),
            max_poll_interval: Duration::from_millis(20),
            ..Default::default()
        };

        let mut client = XdriveStream::new(
            storage.clone(),
            "streams/test/c2s".into(),
            "streams/test/s2c".into(),
            params.clone(),
        );

        let mut server = XdriveStream::new(
            storage.clone(),
            "streams/test/s2c".into(),
            "streams/test/c2s".into(),
            params.clone(),
        );

        let payload = vec![0x42u8; 16384];
        let p_clone = payload.clone();

        let client_task = tokio::spawn(async move {
            client.write_all(&p_clone).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = server.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        client_task.await.unwrap();
        assert_eq!(received, payload);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
