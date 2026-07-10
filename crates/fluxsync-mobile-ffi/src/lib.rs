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
use tokio_util::sync::CancellationToken;

const LOG_BUFFER_CAP: usize = 200;

/// FS-015: reconnect backoff bounds for the state/logs subscriber loops.
/// First retry waits `RECONNECT_MIN_MS`; each further failure doubles the
/// delay up to `RECONNECT_MAX_MS` so an unreachable daemon settles at one
/// attempt per minute instead of 7200 per hour.
const RECONNECT_MIN_MS: u64 = 500;
const RECONNECT_MAX_MS: u64 = 60_000;

/// Next backoff delay: double the current one, capped at `RECONNECT_MAX_MS`.
fn next_reconnect_delay(current_ms: u64) -> u64 {
    current_ms.saturating_mul(2).min(RECONNECT_MAX_MS)
}

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

/// SE-05: source of the long-term identity, replacing the older trio of
/// `keystore_dir` / `identity_secret_b64` empty-string sentinels.
/// The empty-string overloads silently destroyed pairings when a caller
/// passed `""` by mistake — a typed enum makes that misuse impossible.
#[derive(uniffi::Enum)]
pub enum IdentitySource {
    /// Generate a fresh keypair on every start.
    /// **Destroys any existing pairing** — pick this only for first-run
    /// or "reset device" flows.
    Generate,
    /// Load the persisted identity from `dir`, or create+persist a new
    /// one if none exists. Historically "the normal mobile path"; Android
    /// now prefers `Provided` (DIR-P2-02) and only falls back to this one
    /// if the on-device AndroidKeyStore itself is broken (rare OEM bugs).
    /// Still the normal desktop path via `FLUXSYNC_NO_KEYCHAIN=1`.
    Keystore { dir: String },
    /// Decode a base64-encoded 32-byte secret. Testing / migration only —
    /// production callers should use `Keystore` or `Provided`.
    SecretBase64 { secret: String },
    /// DIR-P2-02: a 32-byte secret the caller already decrypted from its
    /// own secure store — on Android, a `KeystoreIdentityStore`-managed
    /// AES-256-GCM key held in `AndroidKeyStore` (the `keyring` crate the
    /// desktop `Keystore` path relies on has no Android backend, which is
    /// why identity used to sit in a plaintext file there). `dir` is
    /// still the app-private data directory: it wires up `peers.json` /
    /// `firewall.json` persistence and `start_on` auto-sync exactly like
    /// `Keystore` does — only the identity secret itself skips Rust-side
    /// file I/O.
    Provided { secret: Vec<u8>, dir: String },
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
    shutdown: CancellationToken,
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
    /// state-subscriber task is running. Pass `IdentitySource::Keystore`
    /// for the normal "remember pairing across reboots" path on desktop;
    /// Android passes `IdentitySource::Provided` with a secret it already
    /// decrypted from `AndroidKeyStore` (DIR-P2-02).
    #[uniffi::constructor]
    #[allow(clippy::too_many_lines)]
    pub fn start(
        peer_name: String,
        ipc_path: String,
        udp_port: u16,
        identity: IdentitySource,
    ) -> Result<Arc<Self>, FluxError> {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("fluxsyncd")
                .with_max_level(log::LevelFilter::Debug),
        );
        init_trace_bridge();

        // SE-05: reject empty peer_name so the daemon never broadcasts
        // a blank advertisement name (the old API silently accepted it).
        if peer_name.trim().is_empty() {
            return Err(FluxError::Invalid("peer_name must not be empty".into()));
        }

        let (identity_obj, keystore_dir) = match identity {
            IdentitySource::Generate => (Identity::generate(), None),
            IdentitySource::Keystore { dir } => {
                if dir.is_empty() {
                    return Err(FluxError::Invalid(
                        "IdentitySource::Keystore.dir must not be empty".into(),
                    ));
                }
                let id = fluxsyncd::keystore::load_or_create_identity(std::path::Path::new(&dir))
                    .map_err(|e| FluxError::Identity(format!("keystore: {e}")))?;
                (id, Some(PathBuf::from(dir)))
            }
            IdentitySource::SecretBase64 { secret } => {
                if secret.is_empty() {
                    return Err(FluxError::Invalid(
                        "IdentitySource::SecretBase64.secret must not be empty".into(),
                    ));
                }
                let bytes = B64
                    .decode(secret.as_bytes())
                    .map_err(|e| FluxError::Identity(format!("base64: {e}")))?;
                // Wrap the decoded Vec in `Zeroizing` so the heap
                // allocation is scrubbed once we've copied the bytes
                // into the fixed array.
                let bytes = zeroize::Zeroizing::new(bytes);
                if bytes.len() != 32 {
                    return Err(FluxError::Identity("expected 32 bytes".into()));
                }
                let mut arr = zeroize::Zeroizing::new([0u8; 32]);
                arr.copy_from_slice(&bytes);
                let id = Identity::from_secret_bytes(arr)
                    .map_err(|e| FluxError::Identity(format!("identity: {e}")))?;
                (id, None)
            }
            IdentitySource::Provided { secret, dir } => {
                if dir.is_empty() {
                    return Err(FluxError::Invalid(
                        "IdentitySource::Provided.dir must not be empty".into(),
                    ));
                }
                // Wrap the incoming Vec in `Zeroizing` so the heap
                // allocation is scrubbed once we've copied the bytes
                // into the fixed array — same treatment as `SecretBase64`.
                let secret = zeroize::Zeroizing::new(secret);
                if secret.len() != 32 {
                    return Err(FluxError::Identity(format!(
                        "IdentitySource::Provided: expected 32 bytes, got {}",
                        secret.len()
                    )));
                }
                let mut arr = zeroize::Zeroizing::new([0u8; 32]);
                arr.copy_from_slice(&secret);
                let id = Identity::from_secret_bytes(arr)
                    .map_err(|e| FluxError::Identity(format!("identity: {e}")))?;
                (id, Some(PathBuf::from(dir)))
            }
        };

        let ipc_path = PathBuf::from(ipc_path);
        let mut cfg = DaemonConfig::new(identity_obj, udp_port, ipc_path.clone());
        cfg.peer_name_self = peer_name;
        if let Some(dir) = keystore_dir {
            cfg.keystore_dir = Some(dir);
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
        let shutdown = CancellationToken::new();

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
            if let Err(e) =
                logs_subscriber_loop(path_for_logs, logs_clone, seq_clone, shutdown_for_logs).await
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
        self.shutdown.cancel();
        if let Some(handle) = self.daemon_thread.lock().ok().and_then(|mut g| g.take()) {
            let _ = handle.join();
        }
    }
}

impl Drop for FluxsyncHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
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
        let Ok(g) = self.last_logs.lock() else {
            return Vec::new();
        };
        g.iter().filter(|e| e.seq > since).cloned().collect()
    }

    /// Highest log seq observed so far. Useful for Kotlin's first poll
    /// when it wants only new entries (subscribe-after-attach pattern).
    pub fn log_cursor(&self) -> u64 {
        self.log_seq.load(Ordering::Relaxed)
    }

    /// Inject a clipboard item. Same code path as `fluxctl push`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn push_text(&self, text: String) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "push", "text": text}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Inject a typed clipboard item. `kind` is `"text"` or `"image"`;
    /// `bytes` is the raw payload (UTF-8 for text, PNG for image). Image
    /// bytes ride to the daemon as base64 since the IPC channel is NDJSON.
    ///
    /// DIR-P2-05: `sensitive` marks an `"image"` push as sensitive — same
    /// treatment as a detected-secret text item (still syncs to the peer,
    /// excluded from history/vault/outbox on both ends). There is no
    /// image-content classifier, so this flag is the only way an image
    /// gets marked. Ignored for `"text"`, which already runs the real
    /// classifier server-side. Defaults to `false` so existing Kotlin call
    /// sites that predate this parameter keep compiling unchanged.
    #[allow(clippy::needless_pass_by_value)]
    #[uniffi::method(default(sensitive = false))]
    pub fn push_item(
        &self,
        kind: String,
        bytes: Vec<u8>,
        sensitive: bool,
    ) -> Result<(), FluxError> {
        let request = match kind.as_str() {
            "image" => {
                serde_json::json!({
                    "id": 1,
                    "op": "push_image",
                    "data": B64.encode(&bytes),
                    "sensitive": sensitive,
                })
            }
            "text" => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                serde_json::json!({"id": 1, "op": "push", "text": text})
            }
            other => return Err(FluxError::Invalid(format!("unknown kind {other}"))),
        };
        self.runtime
            .block_on(send_cmd(&self.ipc_path, request))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Fetch a clipboard item's raw bytes by its hex content hash. Used by
    /// the Android client to pull an inbound image's PNG on demand — the
    /// state JSON only carries the hash + a label, never the bytes.
    #[allow(clippy::needless_pass_by_value)]
    pub fn fetch_item(&self, hash: String) -> Result<Vec<u8>, FluxError> {
        let resp = self
            .runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "fetch_item", "hash": hash}),
            ))
            .map_err(|e| FluxError::Ipc(e.to_string()))?;
        let b64 = resp
            .get("data")
            .and_then(|d| d.get("bytes"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FluxError::Ipc("fetch_item missing `data.bytes`".into()))?;
        B64.decode(b64)
            .map_err(|e| FluxError::Ipc(format!("fetch_item base64: {e}")))
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

    /// DIR-P3-01: rename this device. Validation (non-empty, wire-length
    /// bound, printable) happens daemon-side in `App::set_device_name`; a
    /// rejected name comes back as `FluxError::Ipc` with the daemon's
    /// message. An already-linked peer sees the new name on the next
    /// session establishment, not immediately.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_device_name(&self, name: String) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "set_device_name", "name": name}),
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
    ///
    /// Returns `true` when the daemon reports `already_paired`: the
    /// scanned peer was already trusted and it took the silent-reconnect
    /// path (no fresh pending pair, no SAS re-verify). The Kotlin caller
    /// uses this to skip straight to the linked screen instead of routing
    /// to the verify-words screen, whose `pair_pending` poll would come up
    /// empty and strand the pairing flow. Missing/older-daemon responses
    /// (no `data`, or `data` without `already_paired`) default to `false`
    /// so a legacy daemon always falls through to the normal SAS flow.
    #[allow(clippy::needless_pass_by_value)]
    pub fn pair_from_uri(&self, uri: String, name: String) -> Result<bool, FluxError> {
        let resp = self
            .runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({
                    "id": 1,
                    "op": "pair_from_uri",
                    "uri": uri,
                    "name": name,
                }),
            ))
            .map_err(|e| FluxError::Ipc(e.to_string()))?;
        Ok(resp
            .get("data")
            .and_then(|d| d.get("already_paired"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
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

    /// FluxMesh: revoke one specific peer by hex peer-id (drops its
    /// session + removes it from the trust store), leaving every other
    /// paired device linked. Drives the per-secondary "Unpair" button in
    /// the mesh peer list. `unpair` (above) tears down only the active
    /// primary; this is the surgical single-peer version.
    #[allow(clippy::needless_pass_by_value)]
    pub fn revoke(&self, peer_id: String) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "revoke", "peer_id": peer_id}),
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

    /// FS-052: list TOFU pairs awaiting verbal SAS confirmation. Returns the
    /// raw `data` JSON array (`[{peer_id, name, sas_words, ...}]`) so the UI
    /// can render the 6-word compare after a scan. Empty array once the user
    /// has confirmed (or if nothing is pending).
    pub fn pair_pending(&self) -> Result<String, FluxError> {
        let resp = self
            .runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "pair_pending"}),
            ))
            .map_err(|e| FluxError::Ipc(e.to_string()))?;
        // `data` is omitted when the list is empty (skip_serializing_if).
        Ok(resp
            .get("data")
            .map_or_else(|| "[]".to_string(), std::string::ToString::to_string))
    }

    /// FS-052: accept or reject a pending pair after the user has compared the
    /// 6 SAS words on both devices. `accept = true` clears the gate so
    /// clipboard can flow; `accept = false` revokes the peer entirely.
    #[allow(clippy::needless_pass_by_value)]
    pub fn pair_confirm(&self, peer_id: String, accept: bool) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({
                    "id": 1,
                    "op": "pair_confirm",
                    "peer_id": peer_id,
                    "accept": accept,
                }),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// FluxFirewall: replace the whole clipboard firewall policy. `policy_json`
    /// is the serialized `FirewallPolicy` object (`enabled` + the per-kind
    /// rules); the daemon swaps it in and re-emits state so the Android
    /// toggles reflect the new rules immediately. Parsing here keeps a
    /// malformed object from reaching the daemon as an opaque IPC error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_firewall(&self, policy_json: String) -> Result<(), FluxError> {
        let policy: serde_json::Value = serde_json::from_str(&policy_json)
            .map_err(|e| FluxError::Invalid(format!("firewall policy json: {e}")))?;
        if !policy.is_object() {
            return Err(FluxError::Invalid(
                "firewall policy must be a JSON object".into(),
            ));
        }
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "set_firewall", "policy": policy}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// FluxFirewall: approve (`allow = true`) or reject an item parked under an
    /// Ask rule, keyed by its hex content hash from `State.pending`. Approval
    /// sends/writes the held item; rejection drops it silently.
    #[allow(clippy::needless_pass_by_value)]
    pub fn resolve_pending(&self, hash: String, allow: bool) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "resolve_pending", "hash": hash, "allow": allow}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// FluxVault: pin (`favorite = true`) or unpin a history item by its hex
    /// content hash. Pinned items survive the vault's TTL + disk cap.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_favorite(&self, hash: String, favorite: bool) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "set_favorite", "hash": hash, "favorite": favorite}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// "Clear clipboard history" (owner-requested, local-only — never
    /// propagated to the peer). `include_favorites = false` keeps favorited
    /// items; `true` drops everything, favorites included. Defaults to
    /// `false` so existing Kotlin call sites keep compiling unchanged —
    /// mirrors `push_item`'s `sensitive` default.
    #[uniffi::method(default(include_favorites = false))]
    pub fn clear_history(&self, include_favorites: bool) -> Result<(), FluxError> {
        self.runtime
            .block_on(send_cmd(
                &self.ipc_path,
                serde_json::json!({"id": 1, "op": "clear_history", "include_favorites": include_favorites}),
            ))
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }
}

// ── Internal helpers ───────────────────────────────────────────────────

/// Bridges the daemon's `tracing` events into the `log` crate (and thus
/// `android_logger` → logcat). The desktop daemon installs a
/// `tracing_subscriber` in `main.rs`, but the FFI path calls
/// `fluxsyncd::run` directly with no subscriber, so every `tracing::*`
/// event from the daemon is silently dropped on Android. This bridge
/// makes the daemon internals visible in `adb logcat` (tag `fluxsyncd`).
fn init_trace_bridge() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_writer(LogBridgeWriter)
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_target(true)
            .without_time()
            .try_init();
    });
}

/// `MakeWriter` that forwards each formatted `tracing` line to
/// `log::info!`, which `android_logger` routes to logcat.
#[derive(Clone, Copy)]
struct LogBridgeWriter;

impl std::io::Write for LogBridgeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        for line in text.lines() {
            if !line.is_empty() {
                log::info!(target: "trace", "{line}");
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBridgeWriter {
    type Writer = LogBridgeWriter;
    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

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

/// M-FFI-01: hard deadline on a single IPC round-trip. Every FFI command runs
/// via `block_on(send_cmd(...))` on the calling JNI thread; without a timeout a
/// wedged daemon (busy event loop, an `fsync` storm, a oneshot reply that never
/// fires) would block the Android UI thread indefinitely → ANR.
const IPC_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The daemon caps inbound IPC lines at 64 MiB (`fluxsyncd`'s `MAX_IPC_LINE`
/// in `driver.rs`). Mirror that cap on the client side so a wedged or
/// hostile daemon response can't grow our read buffer unbounded — this
/// matters most for `state`/`logs` subscriber loops, which stay connected
/// and read continuously.
const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

/// Capped line read, mirroring `fluxsyncd`'s own `read_line_capped`: reads
/// up to `MAX_IPC_LINE` bytes looking for a newline, erroring out instead of
/// growing `out` forever if the peer never sends one.
async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut String,
) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            break; // EOF
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if bytes.len() + take > MAX_IPC_LINE {
            reader.consume(take);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC response line exceeds max length",
            ));
        }
        bytes.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if done {
            break;
        }
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    Ok(bytes.len())
}

async fn send_cmd(path: &PathBuf, request: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let round_trip = async {
        let stream = UnixStream::connect(path).await?;
        let (read, mut write) = stream.into_split();
        write.write_all(b"{\"subscribe\":\"cmd\"}\n").await?;
        let line = format!("{request}\n");
        write.write_all(line.as_bytes()).await?;
        write.flush().await?;
        let mut reader = BufReader::new(read);
        let mut buf = String::new();
        read_line_capped(&mut reader, &mut buf).await?;
        let v: serde_json::Value = serde_json::from_str(buf.trim())?;
        if !v
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            let err = v
                .get("err")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            anyhow::bail!("daemon refused: {err}");
        }
        Ok(v)
    };
    match tokio::time::timeout(IPC_CMD_TIMEOUT, round_trip).await {
        Ok(res) => res,
        Err(_) => anyhow::bail!("ipc command timed out after {IPC_CMD_TIMEOUT:?}"),
    }
}

/// Long-lived state-channel subscriber. Keeps `last_state` updated with
/// each new snapshot the daemon publishes. Reconnects after transient
/// errors so a brief socket hiccup doesn't break polling.
async fn state_subscriber_loop(
    path: PathBuf,
    last_state: Arc<Mutex<Option<String>>>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut delay_ms = RECONNECT_MIN_MS;
    loop {
        match state_subscribe_once(&path, &last_state, &shutdown).await {
            Ok(()) => delay_ms = RECONNECT_MIN_MS,
            Err(e) => {
                tracing::warn!(error = %e, delay_ms, "state subscribe loop error; reconnecting");
            }
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(std::time::Duration::from_millis(delay_ms)) => {}
        }
        delay_ms = next_reconnect_delay(delay_ms);
    }
}

async fn state_subscribe_once(
    path: &PathBuf,
    last_state: &Arc<Mutex<Option<String>>>,
    shutdown: &CancellationToken,
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
            () = shutdown.cancelled() => return Ok(()),
            res = read_line_capped(&mut reader, &mut buf) => {
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
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut delay_ms = RECONNECT_MIN_MS;
    loop {
        match logs_subscribe_once(&path, &last_logs, &log_seq, &shutdown).await {
            Ok(()) => delay_ms = RECONNECT_MIN_MS,
            Err(e) => {
                tracing::warn!(error = %e, delay_ms, "logs subscribe loop error; reconnecting");
            }
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(std::time::Duration::from_millis(delay_ms)) => {}
        }
        delay_ms = next_reconnect_delay(delay_ms);
    }
}

async fn logs_subscribe_once(
    path: &PathBuf,
    last_logs: &Arc<Mutex<VecDeque<FfiLogEntry>>>,
    log_seq: &Arc<AtomicU64>,
    shutdown: &CancellationToken,
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
            () = shutdown.cancelled() => return Ok(()),
            res = read_line_capped(&mut reader, &mut buf) => {
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

/// `HH:MM:SS UTC` for a Unix epoch, without pulling in `chrono`. The
/// explicit "UTC" suffix tells users outside GMT+0 why the log clock
/// differs from their wall clock (local time would need a tz database).
fn hms_utc_label(epoch_secs: u64) -> String {
    let h = (epoch_secs % 86400) / 3600;
    let m = (epoch_secs % 3600) / 60;
    let s = epoch_secs % 60;
    format!("{h:02}:{m:02}:{s:02} UTC")
}

/// Current time as `HH:MM:SS UTC` for a log entry.
fn format_utc_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    hms_utc_label(secs)
}

#[cfg(test)]
mod tests {
    use super::{hms_utc_label, next_reconnect_delay, RECONNECT_MAX_MS, RECONNECT_MIN_MS};

    /// FS-015: the reconnect delay must double each step until it caps,
    /// instead of staying at a flat 500ms forever.
    #[test]
    fn backoff_doubles_then_caps() {
        let mut d = RECONNECT_MIN_MS;
        let curve: Vec<u64> = (0..10)
            .map(|_| {
                d = next_reconnect_delay(d);
                d
            })
            .collect();
        assert_eq!(
            curve,
            vec![1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000, 60_000],
        );
    }

    #[test]
    fn backoff_never_overflows() {
        assert_eq!(next_reconnect_delay(u64::MAX), RECONNECT_MAX_MS);
    }

    /// FS-021: the log timestamp must carry an explicit "UTC" label so
    /// users outside GMT+0 know why it differs from their wall clock.
    #[test]
    fn hms_utc_label_formats_with_zone_suffix() {
        assert_eq!(hms_utc_label(0), "00:00:00 UTC");
        assert_eq!(hms_utc_label(3_661), "01:01:01 UTC");
        assert_eq!(hms_utc_label(86_399), "23:59:59 UTC");
    }
}
