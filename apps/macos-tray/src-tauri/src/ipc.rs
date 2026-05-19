//! UNIX-socket client for `fluxsyncd`'s NDJSON IPC. One request per
//! socket — same shape as `fluxctl`'s `one_shot`. Reuses tokio so the
//! Tauri command handlers stay async and the UI thread never blocks.
//!
//! Also owns daemon-lifecycle helpers used at app boot: probe the
//! socket, spawn `fluxsyncd` detached if absent, wait for the socket to
//! appear. Lets the tray be the only thing the user has to launch.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Default IPC socket path. Honors `FLUXSYNC_IPC_PATH` so contributors
/// can point the tray at a non-default daemon during development.
fn ipc_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("FLUXSYNC_IPC_PATH") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not find home directory"))?;
    Ok(home.join(".fluxsync").join("sock"))
}

/// Best-effort: ensure `fluxsyncd` is reachable on its UNIX socket.
/// Called once during Tauri `setup()`. Steps:
///   1. If the socket already accepts a connection, return immediately.
///   2. Otherwise locate the daemon binary and spawn it detached, with
///      stdout/stderr redirected to `~/.fluxsync/daemon.log`.
///   3. Poll the socket for up to `boot_budget` so subsequent IPC calls
///      from the tray see a live daemon.
///
/// Failures are logged but never fatal — the tray must still open even
/// if the daemon is missing, so the user can see an actionable error in
/// the popup ("daemon not reachable").
pub fn ensure_daemon_running() {
    if is_daemon_alive() {
        // Socket answers — but is it the daemon build this tray expects?
        // A daemon left over from a previous (older) checkout would
        // otherwise be used silently. See the version-guard helpers.
        match daemon_build_id() {
            Ok(Some(id)) if id == env!("FLUXSYNC_TRAY_BUILD_ID") => return,
            Ok(found) => {
                let shown = found.as_deref().unwrap_or("<none>");
                eprintln!(
                    "[fluxsync-tray] stale daemon (build {shown} != tray {}); restarting",
                    env!("FLUXSYNC_TRAY_BUILD_ID")
                );
                if !restart_stale_daemon() {
                    // Couldn't confirm the old daemon exited — don't pile
                    // a second daemon on top of it.
                    return;
                }
                // Old daemon gone; fall through to spawn a fresh one.
            }
            Err(e) => {
                // Probe itself failed (socket race / parse error). Leave
                // the running daemon alone rather than risk a thrash loop.
                eprintln!("[fluxsync-tray] daemon build-id probe failed: {e:#}; leaving it");
                return;
            }
        }
    }
    match spawn_daemon_detached() {
        Ok(bin) => eprintln!("[fluxsync-tray] spawned daemon: {}", bin.display()),
        Err(e) => {
            eprintln!("[fluxsync-tray] daemon spawn failed: {e:#}");
            return;
        }
    }
    // Daemon usually creates the socket within ~200ms. Cap the wait at
    // 3s so a wedged daemon doesn't freeze the menu-bar icon forever.
    let boot_budget = Duration::from_secs(3);
    let started = Instant::now();
    while started.elapsed() < boot_budget {
        if is_daemon_alive() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("[fluxsync-tray] daemon spawned but socket never appeared within {boot_budget:?}");
}

fn is_daemon_alive() -> bool {
    let Ok(p) = ipc_path() else {
        return false;
    };
    std::os::unix::net::UnixStream::connect(&p).is_ok()
}

/// Blocking one-shot `cmd` request on the daemon's UNIX socket. Used by
/// the boot-time version guard, which runs on a sync thread before the
/// tokio runtime is wired up — so it can't reuse the async `one_shot`.
fn ipc_cmd_blocking(op: &str) -> Result<Value> {
    use std::io::{BufRead, Write};

    let path = ipc_path()?;
    let mut stream = std::os::unix::net::UnixStream::connect(&path)
        .with_context(|| format!("connect {}", path.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .context("set socket read timeout")?;
    stream.write_all(b"{\"subscribe\":\"cmd\"}\n")?;
    stream.write_all(format!("{{\"id\":1,\"op\":\"{op}\"}}\n").as_bytes())?;
    stream.flush()?;

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim())
        .with_context(|| format!("parse daemon response: {line:?}"))
}

/// Ask the running daemon for its compiled-in `build_id`.
///   * `Ok(Some(id))` — daemon reported an id.
///   * `Ok(None)` — daemon answered but carries no `build_id` (a build
///     predating the field) → treat as stale.
///   * `Err(_)` — the probe itself failed; caller should not act on it.
fn daemon_build_id() -> Result<Option<String>> {
    let v = ipc_cmd_blocking("status")?;
    if !v.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(anyhow!("daemon refused `status`: {v}"));
    }
    // `CmdData` is `#[serde(untagged)]`, so the `State` object sits
    // directly under `data`.
    Ok(v.get("data")
        .and_then(|d| d.get("build_id"))
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Tell a stale daemon to shut down, then wait for it to release its
/// socket. Returns `true` once the socket stops answering.
fn restart_stale_daemon() -> bool {
    // Fire-and-forget: a clean shutdown often drops the connection
    // before any response is flushed, so the reply isn't worth reading.
    if let Ok(path) = ipc_path() {
        if let Ok(mut s) = std::os::unix::net::UnixStream::connect(&path) {
            use std::io::Write;
            let _ = s.write_all(b"{\"subscribe\":\"cmd\"}\n{\"id\":1,\"op\":\"shutdown\"}\n");
            let _ = s.flush();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !is_daemon_alive() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("[fluxsync-tray] stale daemon did not exit within 3s");
    false
}

fn spawn_daemon_detached() -> Result<PathBuf> {
    let bin = locate_daemon()?;
    let log = open_daemon_log()?;
    let log_err = log.try_clone().context("clone log fd for stderr")?;

    let mut cmd = std::process::Command::new(&bin);
    cmd.stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(log_err);

    // Detach from the tray's process group so the daemon survives a
    // tray crash / restart and isn't killed when the user quits the
    // menu-bar app. `setsid(2)` is the standard Unix call for this.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(detach_session);
        }
    }

    cmd.spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    Ok(bin)
}

/// Run `setsid(2)` in the post-fork child so the daemon is its own
/// session leader and won't get killed when the tray's process group
/// goes away. Inlined `extern "C"` link rather than pulling the `libc`
/// crate for a single symbol.
#[cfg(unix)]
fn detach_session() -> std::io::Result<()> {
    extern "C" {
        fn setsid() -> i32;
    }
    if unsafe { setsid() } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_daemon_log() -> Result<std::fs::File> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME unset; cannot derive log path"))?;
    let dir = PathBuf::from(home).join(".fluxsync");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("daemon.log");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))
}

/// Search order for the daemon binary:
///   1. `FLUXSYNC_DAEMON_BIN` env var (dev override).
///   2. Sibling to the running tray binary (`.app` bundle layout).
///   3. System bin prefixes (`/opt/homebrew/bin`, `/usr/local/bin`).
///   4. `~/.cargo/bin/fluxsyncd` (developer `cargo install`).
///   5. The repo's `target/{release,debug}/fluxsyncd` when running from
///      a workspace checkout (`cargo run` / `tauri dev`).
fn locate_daemon() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("FLUXSYNC_DAEMON_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
    }

    // Dev: prefer the build.rs-managed sidecar. `build.rs` rebuilds it
    // fresh on every tray compile, so it is guaranteed current — unlike
    // the `target/debug/fluxsyncd` sibling below, which can be a stale
    // orphan from a manual copy. `CARGO_MANIFEST_DIR` is a build-machine
    // path, so in a shipped `.app` this simply doesn't exist and we fall
    // through to the bundle layout.
    let managed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("fluxsyncd-aarch64-apple-darwin");
    if managed.is_file() {
        return Ok(managed);
    }

    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let cand = dir.join("fluxsyncd");
            if cand.is_file() {
                return Ok(cand);
            }
            // Sidecar location in macOS bundle: ../Resources/binaries/fluxsyncd-<target>
            if let Some(contents) = dir.parent() {
                let sidecar = contents.join("Resources").join("binaries").join("fluxsyncd-aarch64-apple-darwin");
                if sidecar.is_file() {
                    return Ok(sidecar);
                }
            }
        }
    }

    for p in [
        "/opt/homebrew/bin/fluxsyncd",
        "/usr/local/bin/fluxsyncd",
    ] {
        let p = Path::new(p);
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        let cargo_bin = PathBuf::from(&home).join(".cargo/bin/fluxsyncd");
        if cargo_bin.is_file() {
            return Ok(cargo_bin);
        }
    }

    if let Ok(self_exe) = std::env::current_exe() {
        // `tauri dev` puts the tray binary at
        // apps/macos-tray/src-tauri/target/debug/<bin>; the workspace
        // daemon lives at <repo>/target/{release,debug}/fluxsyncd. Walk
        // up the tray's path until one of the ancestor dirs contains a
        // matching workspace `target/` subtree.
        let mut cur = self_exe.as_path();
        while let Some(parent) = cur.parent() {
            for profile in ["release", "debug"] {
                let cand = parent.join("target").join(profile).join("fluxsyncd");
                if cand.is_file() {
                    return Ok(cand);
                }
            }
            cur = parent;
        }
    }

    Err(anyhow!(
        "fluxsyncd binary not found. Build it with `cargo build --release -p fluxsyncd`, \
         `cargo install --path crates/fluxsyncd`, or set `FLUXSYNC_DAEMON_BIN` to an explicit path."
    ))
}

/// Connect, send one cmd, read one response, drop the connection.
/// Returns the `String → String` map error so Tauri can serialize it
/// across the JS boundary without an extra `Display` impl.
pub async fn one_shot(request: Value) -> Result<Value, String> {
    one_shot_inner(request).await.map_err(|e| e.to_string())
}

async fn one_shot_inner(request: Value) -> Result<Value> {
    let path = ipc_path()?;
    let stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("connect {}", path.display()))?;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"subscribe\":\"cmd\"}\n").await?;
    write
        .write_all(format!("{request}\n").as_bytes())
        .await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    let v: Value = serde_json::from_str(buf.trim())
        .with_context(|| format!("parse daemon response: {buf:?}"))?;
    if !v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
        let err = v
            .get("err")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown error");
        return Err(anyhow!("daemon refused: {err}"));
    }
    Ok(v)
}

/// Subscribe to the daemon's `state` channel. Each NDJSON line the
/// daemon pushes is a full `State` snapshot; forward it through
/// `on_update`. Runs until the daemon closes the connection.
pub async fn subscribe_state<F>(mut on_update: F) -> Result<()>
where
    F: FnMut(Value) + Send + 'static,
{
    let path = ipc_path()?;
    let stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("connect {}", path.display()))?;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"subscribe\":\"state\"}\n").await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
            on_update(v);
        }
    }
}
