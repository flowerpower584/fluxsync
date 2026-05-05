//! FluxSync Kotlin/Android FFI.
//!
//! Surface designed to dodge UniFFI 0.27 codegen bugs:
//!
//!   * **No callback interfaces.** Earlier versions used a Kotlin
//!     `StateObserver` callback for state updates; UniFFI 0.27 emits
//!     broken `uniffiCallbackInterface*` glue for that pattern. Instead,
//!     a background task on the Rust side keeps the latest state JSON in
//!     a `Mutex<Option<String>>`, and Kotlin **polls** via `poll_state`.
//!   * **No `Option<String>`.** UniFFI 0.27 fails to generate the
//!     `FfiConverterOptionalString` for some surfaces; we use the empty
//!     string as a sentinel for "absent" everywhere instead.
//!   * **Flat error enum.** `#[uniffi(flat_error)]` collapses the
//!     variants into a single Kotlin `FluxException` class — variant-
//!     fielded enums confuse 0.27's exception generator. The variant
//!     `Display` impl carries the user-facing message.
//!
//! These constraints will relax once we move to UniFFI 0.28+, but the
//! shapes here are clean enough to keep even after that — the Kotlin
//! side is straightforward to write against.

uniffi::setup_scaffolding!();

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fluxsync_crypto::Identity;
use fluxsyncd::{run, DaemonConfig};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use tokio::sync::Notify;

const LOG_BUFFER_CAP: usize = 200;

/// All FFI errors funnel here. `flat_error` flattens the variants into
/// a single Kotlin `FluxException` class — UniFFI 0.27's per-variant
/// codegen is buggy when variants carry field data. Kotlin still gets
/// the message via `Throwable::getLocalizedMessage`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FluxError {
    #[error("identity: {0}")]
    Identity(String),
    #[error("daemon: {0}")]
    Daemon(String),
    #[error("ipc: {0}")]
    Ipc(String),
    #[error("invalid argument: {0}")]
    Invalid(String),
}

/// One row of the Logs screen — synthesized at FFI receipt from the
/// daemon's `LogEntry` plus a monotonic `seq` cursor so the Kotlin side
/// can ask for "everything since seq N" without re-sending the whole
/// buffer. `time` is UTC HH:MM:SS, formatted client-side; `raw` is the
/// untouched JSON line for the LogsScreen "RAW" toggle.
#[derive(Clone, uniffi::Record)]
pub struct FfiLogEntry {
    pub seq: u64,
    pub time: String,
    pub level: String,
    pub msg: String,
    pub raw: String,
}

/// Opaque handle returned by `start`. Holds the runtime, the shutdown
/// signal, the IPC socket path, and a continuously-updated snapshot of
/// the daemon's last state JSON. Drop = no-op (Kotlin must call `stop`
/// explicitly so the daemon thread joins deterministically).
#[derive(uniffi::Object)]
pub struct FluxsyncHandle {
    runtime: Arc<Runtime>,
    shutdown: Arc<Notify>,
    ipc_path: PathBuf,
    daemon_thread: Mutex<Option<JoinHandle<()>>>,
    /// Latest state JSON line as published by the daemon. The
    /// background subscriber writes here; Kotlin reads via
    /// `poll_state`. `None` until the first snapshot arrives.
    last_state: Arc<Mutex<Option<String>>>,
    /// Ring buffer of recent log lines, capped at [`LOG_BUFFER_CAP`].
    /// Background subscriber appends; Kotlin reads via `poll_logs`.
    last_logs: Arc<Mutex<VecDeque<FfiLogEntry>>>,
    /// Monotonic seq counter so callers can pass a `since` cursor to
    /// `poll_logs` and only receive new entries.
    log_seq: Arc<AtomicU64>,
}

#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires specific types for code generation
impl FluxsyncHandle {
    /// Boot the daemon. Returns once the IPC socket is reachable and a
    /// state-subscriber task is running. `identity_secret_b64 = ""`
    /// regenerates a fresh keypair on every start.
    #[uniffi::constructor]
    pub fn start(
        peer_name: String,
        ipc_path: String,
        keystore_dir: String,
        udp_port: u16,
        identity_secret_b64: String,
    ) -> Result<Arc<Self>, FluxError> {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("fluxsyncd")
                .with_max_level(log::LevelFilter::Debug),
        );

        let identity = if identity_secret_b64.is_empty() {
            if keystore_dir.is_empty() {
                Identity::generate()
            } else {
                fluxsyncd::keystore::load_or_create_identity(std::path::Path::new(&keystore_dir))
                    .map_err(|e| FluxError::Identity(format!("keystore: {e}")))?
            }
        } else {
            let bytes = B64
                .decode(identity_secret_b64.as_bytes())
                .map_err(|e| FluxError::Identity(format!("base64: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| FluxError::Identity("expected 32 bytes".into()))?;
            Identity::from_secret_bytes(arr)
        };

        let ipc_path = PathBuf::from(ipc_path);
        let mut cfg = DaemonConfig::new(identity, udp_port, ipc_path.clone());
        cfg.peer_name_self = peer_name;
        if !keystore_dir.is_empty() {
            cfg.keystore_dir = Some(PathBuf::from(keystore_dir));
            cfg.start_on = true; // Auto-start sync if we have a keystore
        }

        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("fluxsync-mobile-rt")
                .build()
                .map_err(|e| FluxError::Daemon(format!("runtime: {e}")))?,
        );
        let shutdown = Arc::new(Notify::new());

        // Spawn the daemon on a dedicated OS thread so dropping the
        // runtime there is straightforward.
        let rt_clone = runtime.clone();
        let shutdown_clone = shutdown.clone();
        let thread = std::thread::Builder::new()
            .name("fluxsync-mobile-daemon".into())
            .spawn(move || {
                rt_clone.block_on(async move {
                    if let Err(e) = run(cfg, shutdown_clone).await {
                        tracing::error!(error = %e, "daemon exited with error");
                    }
                });
            })
            .map_err(|e| FluxError::Daemon(format!("spawn thread: {e}")))?;

        // Wait for the IPC socket to appear (cap at ~1.5s). Done from
        // the SAME runtime that owns the daemon, so we don't spin up a
        // throwaway one.
        runtime
            .block_on(wait_for_socket(
                &ipc_path,
                std::time::Duration::from_millis(1500),
            ))
            .map_err(|e| FluxError::Ipc(format!("not ready: {e}")))?;

        // Background subscriber: keeps `last_state` fresh.
        let last_state: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let last_state_clone = last_state.clone();
        let path_for_sub = ipc_path.clone();
        let shutdown_for_sub = shutdown.clone();
        runtime.spawn(async move {
            if let Err(e) =
                state_subscriber_loop(path_for_sub, last_state_clone, shutdown_for_sub).await
            {
                tracing::warn!(error = %e, "state subscriber loop exited");
            }
        });

        // Logs subscriber: same idea as state, but on the daemon's
        // `logs` IPC channel. Pushed entries land in a capped ring; the
        // Kotlin `LogsScreen` polls via `poll_logs(since)`.
        let last_logs: Arc<Mutex<VecDeque<FfiLogEntry>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(LOG_BUFFER_CAP)));
        let log_seq: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let logs_clone = last_logs.clone();
        let seq_clone = log_seq.clone();
        let path_for_logs = ipc_path.clone();
        let shutdown_for_logs = shutdown.clone();
        runtime.spawn(async move {
            if let Err(e) = logs_subscriber_loop(
                path_for_logs,
                logs_clone,
                seq_clone,
                shutdown_for_logs,
            )
            .await
            {
                tracing::warn!(error = %e, "logs subscriber loop exited");
            }
        });

        Ok(Arc::new(Self {
            runtime,
            shutdown,
            ipc_path,
            daemon_thread: Mutex::new(Some(thread)),
            last_state,
            last_logs,
            log_seq,
        }))
    }

    /// Fire the shutdown notify and join the daemon thread. Returns
    /// once the daemon has exited (≤ 500ms in practice).
    pub fn stop(&self) {
        self.shutdown.notify_waiters();
        if let Some(handle) = self.daemon_thread.lock().ok().and_then(|mut g| g.take()) {
            let _ = handle.join();
        }
    }
}

impl Drop for FluxsyncHandle {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
    }
}

#[uniffi::export]
impl FluxsyncHandle {
    /// Latest state JSON, or `""` before the daemon has published its
    /// first snapshot. Pollable from any Kotlin coroutine — the read is
    /// O(1) and lock-cheap.
    pub fn poll_state(&self) -> String {
        self.last_state
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns log entries with `seq > since`. Pass `0` to fetch the
    /// whole buffer at startup; pass the highest seq seen so far on
    /// subsequent polls so the Kotlin side only walks new entries.
    pub fn poll_logs(&self, since: u64) -> Vec<FfiLogEntry> {
        let g = match self.last_logs.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        g.iter()
            .filter(|e| e.seq > since)
            .cloned()
            .collect()
    }

    /// Highest log seq observed so far. Useful for Kotlin's first poll
    /// when it wants only new entries (subscribe-after-attach pattern).
    pub fn log_cursor(&self) -> u64 {
        self.log_seq.load(Ordering::Relaxed)
    }

    /// Inject a clipboard item. Same code path as `fluxctl push`.
    pub fn push_text(&self, text: String) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "push", "text": text}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Pause-below-X% battery threshold (5..=50).
    pub fn set_battery_threshold(&self, value: u8) -> Result<(), FluxError> {
        if !(5..=50).contains(&value) {
            return Err(FluxError::Invalid(format!(
                "threshold {value} out of range 5..=50"
            )));
        }
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "set_threshold", "value": value}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Wake / sleep the FSM. `true` = `Idle → Discovering`.
    pub fn toggle(&self, on: bool) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "toggle", "on": on}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// "Resume while charging" override.
    pub fn set_charge_override(&self, value: bool) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "set_charge_override", "value": value}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Push host-OS battery telemetry into the daemon. Called from the
    /// Android `MainActivity` whenever the system fires
    /// `ACTION_BATTERY_CHANGED`. Without this, the daemon reports a
    /// hardcoded value to the peer.
    pub fn set_self_battery(&self, level: u8, charging: bool) -> Result<(), FluxError> {
        if level > 100 {
            return Err(FluxError::Invalid(format!("level {level} > 100")));
        }
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({
                    "id": 1,
                    "op": "set_self_battery",
                    "level": level,
                    "charging": charging,
                }),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// This device's pair info as JSON (matches `CmdData::PairInfo`).
    pub fn pair_show(&self) -> Result<String, FluxError> {
        let resp = self
            .runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "pair_show"}),
            ))
            .map_err(|e| FluxError::Ipc(e.to_string()))?;
        let data = resp
            .get("data")
            .ok_or_else(|| FluxError::Ipc("pair_show missing `data`".into()))?;
        Ok(data.to_string())
    }

    /// Trust a peer described by a `fluxsync://pair/...` URI (typically
    /// from a scanned QR). `name` is the nickname for the peer.
    pub fn pair_from_uri(&self, uri: String, name: String) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({
                    "id": 1,
                    "op": "pair_from_uri",
                    "uri": uri,
                    "name": name,
                }),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Manually unpair from the current peer and reset the FSM state.
    /// The Android UI calls this when the user taps "Unpair" on the
    /// Reconnecting screen, or when the system detects a stale ghost.
    pub fn unpair(&self) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "unpair"}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Manual pair fallback. Pass `addr = ""` to skip the immediate
    /// handshake (mDNS will pick the peer up later); pass `IP:PORT` to
    /// kick the handshake right away.
    pub fn pair_accept(
        &self,
        pubkey_b32: String,
        name: String,
        addr: String,
    ) -> Result<(), FluxError> {
        let path = self.ipc_path.clone();
        self.runtime
            .block_on(async move {
                let mut req = serde_json::json!({
                    "id": 1,
                    "op": "pair_accept",
                    "pubkey_b32": pubkey_b32,
                    "name": name,
                });
                if !addr.is_empty() {
                    req["addr"] = serde_json::json!(addr);
                }
                send_cmd(&path, req).await
            })
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }
}

// ── Internal helpers ───────────────────────────────────────────────────

async fn wait_for_socket(path: &PathBuf, deadline: std::time::Duration) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if path.exists() && UnixStream::connect(path).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Err(anyhow::anyhow!(
        "ipc socket {} not reachable within {:?}",
        path.display(),
        deadline
    ))
}

async fn send_cmd(path: &PathBuf, request: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let stream = UnixStream::connect(path).await?;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"subscribe\":\"cmd\"}\n").await?;
    let line = format!("{request}\n");
    write.write_all(line.as_bytes()).await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    let v: serde_json::Value = serde_json::from_str(buf.trim())?;
    if !v.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false) {
        let err = v
            .get("err")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        anyhow::bail!("daemon refused: {err}");
    }
    Ok(v)
}

/// Long-lived state-channel subscriber. Keeps `last_state` updated with
/// each new snapshot the daemon publishes. Reconnects after transient
/// errors so a brief socket hiccup doesn't break polling.
async fn state_subscriber_loop(
    path: PathBuf,
    last_state: Arc<Mutex<Option<String>>>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    loop {
        if let Err(e) = state_subscribe_once(&path, &last_state, &shutdown).await {
            tracing::warn!(error = %e, "state subscribe loop error; reconnecting in 500ms");
        }
        tokio::select! {
            () = shutdown.notified() => return Ok(()),
            () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
        }
    }
}

async fn state_subscribe_once(
    path: &PathBuf,
    last_state: &Arc<Mutex<Option<String>>>,
    shutdown: &Arc<Notify>,
) -> anyhow::Result<()> {
    let stream = UnixStream::connect(path).await?;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"subscribe\":\"state\"}\n").await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    loop {
        buf.clear();
        tokio::select! {
            () = shutdown.notified() => return Ok(()),
            res = reader.read_line(&mut buf) => {
                let n = res?;
                if n == 0 { return Ok(()); }
                if let Ok(mut g) = last_state.lock() {
                    *g = Some(buf.trim().to_string());
                }
            }
        }
    }
}

/// Symmetric to `state_subscriber_loop`, but reads the daemon's `logs`
/// channel. Each NDJSON line decodes to `{level, msg}`; we synthesize a
/// UTC timestamp + monotonic seq at receipt and append to the bounded
/// ring buffer.
async fn logs_subscriber_loop(
    path: PathBuf,
    last_logs: Arc<Mutex<VecDeque<FfiLogEntry>>>,
    log_seq: Arc<AtomicU64>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    loop {
        if let Err(e) =
            logs_subscribe_once(&path, &last_logs, &log_seq, &shutdown).await
        {
            tracing::warn!(error = %e, "logs subscribe loop error; reconnecting in 500ms");
        }
        tokio::select! {
            () = shutdown.notified() => return Ok(()),
            () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
        }
    }
}

async fn logs_subscribe_once(
    path: &PathBuf,
    last_logs: &Arc<Mutex<VecDeque<FfiLogEntry>>>,
    log_seq: &Arc<AtomicU64>,
    shutdown: &Arc<Notify>,
) -> anyhow::Result<()> {
    let stream = UnixStream::connect(path).await?;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"subscribe\":\"logs\"}\n").await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    loop {
        buf.clear();
        tokio::select! {
            () = shutdown.notified() => return Ok(()),
            res = reader.read_line(&mut buf) => {
                let n = res?;
                if n == 0 { return Ok(()); }
                let raw = buf.trim().to_string();
                if raw.is_empty() { continue; }
                let parsed: serde_json::Value = match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let level = parsed
                    .get("level")
                    .and_then(|x| x.as_str())
                    .unwrap_or("INFO")
                    .to_string();
                let msg = parsed
                    .get("msg")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let seq = log_seq.fetch_add(1, Ordering::Relaxed) + 1;
                let entry = FfiLogEntry {
                    seq,
                    time: format_utc_hms(),
                    level,
                    msg,
                    raw,
                };
                if let Ok(mut g) = last_logs.lock() {
                    if g.len() >= LOG_BUFFER_CAP { g.pop_front(); }
                    g.push_back(entry);
                }
            }
        }
    }
}

/// UTC HH:MM:SS without pulling in `chrono`. Lossy at midnight UTC but
/// fine for a log timestamp; the user-perceptible drift between this
/// and "log entry actually emitted by the daemon" is sub-second.
fn format_utc_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
