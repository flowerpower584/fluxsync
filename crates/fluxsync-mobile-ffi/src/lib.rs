//! FluxSync Kotlin/Android FFI.
//!
//! Surface (six entry points, deliberately minimal — see CHECKPOINT 6
//! reminder #1):
//!   * `start(peer_name, ipc_path, udp_port, identity_secret_b64)` — boot the
//!     daemon thread, return a handle.
//!   * `stop()` — fire the shutdown notify; the daemon thread joins inside.
//!   * `observe_state(observer)` — install a Kotlin callback that gets one
//!     JSON `String` per state change. **Verbatim** state JSON, *never* a
//!     UniFFI struct, so adding a field to `State` does not break the ABI.
//!   * `push_text(text)` — inject a clipboard item. Uses the same path as
//!     `fluxctl push` (the daemon's IPC), so the exact same classifier and
//!     dedup logic applies.
//!   * `set_battery_threshold(value)` — `5..=50`, validated.
//!   * `set_charge_override(value)` — bool.
//!
//! Threading: UniFFI calls cross over JNI synchronously. The daemon's
//! tokio runtime lives in a single dedicated Rust thread spawned by
//! `start`. The state observer callback is invoked from a Rust task —
//! the Kotlin side must hop to `Dispatchers.Main` itself before
//! touching Compose state.
//!
//! Identity:
//!   * `identity_secret_b64 = None` → daemon generates a fresh keypair on
//!     every start. v0.1.1 will persist via the Android Keystore (`keyring`
//!     crate, android-native backend).
//!   * `identity_secret_b64 = Some(b64)` → caller (Kotlin app) manages the
//!     Android Keystore itself and supplies a 32-byte secret base64-encoded.

uniffi::setup_scaffolding!();

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fluxsync_crypto::Identity;
use fluxsyncd::{run, DaemonConfig};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use tokio::sync::Notify;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FluxError {
    #[error("invalid threshold: {0}")]
    InvalidThreshold(u8),
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),
    #[error("daemon error: {0}")]
    Daemon(String),
    #[error("ipc error: {0}")]
    Ipc(String),
}

/// Kotlin-implemented callback. Each call passes one JSON line that
/// matches the design system's state shape exactly.
#[uniffi::export(callback_interface)]
pub trait StateObserver: Send + Sync + std::fmt::Debug {
    fn on_state(&self, json: String);
}

/// Opaque handle returned by `start`. Holds the runtime, the shutdown
/// signal, and the IPC socket path. Drop = no-op (Kotlin must call
/// `stop` explicitly so the daemon thread joins deterministically).
#[derive(uniffi::Object)]
pub struct FluxsyncHandle {
    runtime: Arc<Runtime>,
    shutdown: Arc<Notify>,
    ipc_path: PathBuf,
    daemon_thread: Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl FluxsyncHandle {
    /// Boot the daemon. Returns once the IPC socket is reachable.
    #[uniffi::constructor]
    pub fn start(
        peer_name: String,
        ipc_path: String,
        udp_port: u16,
        identity_secret_b64: Option<String>,
    ) -> Result<Arc<Self>, FluxError> {
        // Build identity.
        let identity = match identity_secret_b64 {
            None => Identity::generate(),
            Some(b64) => {
                let bytes = B64
                    .decode(b64.as_bytes())
                    .map_err(|e| FluxError::InvalidIdentity(format!("base64: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| FluxError::InvalidIdentity("expected 32 bytes".into()))?;
                Identity::from_secret_bytes(arr)
            }
        };

        let ipc_path = PathBuf::from(ipc_path);
        let mut cfg = DaemonConfig::new(identity, udp_port, ipc_path.clone());
        cfg.peer_name_self = peer_name;

        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("fluxsync-mobile-rt")
                .build()
                .map_err(|e| FluxError::Daemon(format!("runtime: {e}")))?,
        );
        let shutdown = Arc::new(Notify::new());

        // Spawn the daemon on a dedicated OS thread. The thread owns
        // the runtime so dropping the runtime there is straightforward.
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

        // Wait for the IPC socket to appear (cap at ~1.5s).
        let path_for_wait = ipc_path.clone();
        let runtime_for_wait = runtime.clone();
        runtime_for_wait
            .block_on(wait_for_socket(
                &path_for_wait,
                std::time::Duration::from_millis(1500),
            ))
            .map_err(|e| FluxError::Ipc(format!("ipc not ready: {e}")))?;

        Ok(Arc::new(Self {
            runtime,
            shutdown,
            ipc_path,
            daemon_thread: Mutex::new(Some(thread)),
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

    /// Install a Kotlin callback for state updates. The callback is
    /// invoked once with the current snapshot, then once per change.
    /// Calling more than once installs additional observers (each gets
    /// every update).
    pub fn observe_state(&self, observer: Box<dyn StateObserver>) {
        let path = self.ipc_path.clone();
        let shutdown = self.shutdown.clone();
        self.runtime.spawn(async move {
            if let Err(e) = state_subscriber_loop(path, observer, shutdown).await {
                tracing::warn!(error = %e, "observe_state loop exited");
            }
        });
    }

    /// Inject a clipboard item. Same code path as `fluxctl push`.
    pub fn push_text(&self, text: String) -> Result<(), FluxError> {
        let path = self.ipc_path.clone();
        self.runtime
            .block_on(async move {
                send_cmd(
                    &path,
                    serde_json::json!({"id": 1, "op": "push", "text": text}),
                )
                .await
            })
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Set the pause-below-X% battery threshold (5..=50).
    pub fn set_battery_threshold(&self, value: u8) -> Result<(), FluxError> {
        if !(5..=50).contains(&value) {
            return Err(FluxError::InvalidThreshold(value));
        }
        let path = self.ipc_path.clone();
        self.runtime
            .block_on(async move {
                send_cmd(
                    &path,
                    serde_json::json!({"id": 1, "op": "set_threshold", "value": value}),
                )
                .await
            })
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }

    /// Toggle the "resume while charging" override.
    pub fn set_charge_override(&self, value: bool) -> Result<(), FluxError> {
        let path = self.ipc_path.clone();
        self.runtime
            .block_on(async move {
                send_cmd(
                    &path,
                    serde_json::json!({"id": 1, "op": "set_charge_override", "value": value}),
                )
                .await
            })
            .map(|_| ())
            .map_err(|e| FluxError::Ipc(e.to_string()))
    }
}

// ── Internal helpers ───────────────────────────────────────────────────

async fn wait_for_socket(path: &PathBuf, deadline: std::time::Duration) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if path.exists() {
            // Try a real connection too — file might exist before listen.
            if UnixStream::connect(path).await.is_ok() {
                return Ok(());
            }
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
    if !v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
        let err = v
            .get("err")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        anyhow::bail!("daemon refused: {err}");
    }
    Ok(v)
}

async fn state_subscriber_loop(
    path: PathBuf,
    observer: Box<dyn StateObserver>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    let stream = UnixStream::connect(&path).await?;
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
                observer.on_state(buf.trim().to_string());
            }
        }
    }
}
