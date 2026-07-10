//! Minimal StatusNotifierItem tray for FluxSync on KDE/freedesktop.
//!
//! Talks to the daemon over its NDJSON IPC socket (`~/.fluxsync/sock`),
//! exactly like `fluxctl` — no webkit, no GTK, no embedded UI. The
//! daemon does all the work; this is a panel icon + control menu.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ksni::menu::StandardItem;
use ksni::{MenuItem, ToolTip, Tray, TrayService};
use serde_json::Value;

fn ipc_path() -> PathBuf {
    if let Ok(p) = std::env::var("FLUXSYNC_SOCK") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".fluxsync/sock")
}

/// The daemon caps inbound IPC lines at 64 MiB (`fluxsyncd`'s `MAX_IPC_LINE`
/// in `driver.rs`). Mirror that cap here so a wedged or hostile daemon
/// response can't grow our read buffer unbounded.
const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

/// Capped line read, mirroring `fluxsyncd`'s own `read_line_capped`: reads
/// up to `MAX_IPC_LINE` bytes looking for a newline, erroring out instead of
/// growing `out` forever if the peer never sends one.
fn read_line_capped<R: BufRead>(reader: &mut R, out: &mut String) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
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

/// One NDJSON request → one NDJSON reply. Returns `None` if the daemon
/// is unreachable or the reply does not parse.
fn ipc(path: &Path, req: &str) -> Option<Value> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    // The daemon IPC expects a channel subscription line before the
    // request, mirroring `fluxctl`'s one-shot client.
    stream.write_all(b"{\"subscribe\":\"cmd\"}\n").ok()?;
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    read_line_capped(&mut reader, &mut line).ok()?;
    serde_json::from_str(line.trim()).ok()
}

/// Appends a friendly OS suffix to the peer name, e.g. `mac-mini (macOS)`.
/// `peer_platform` arrives via `Msg::Hello`; empty until then.
fn with_platform(peer: &str, platform: Option<&str>) -> String {
    match platform {
        Some("macos") => format!("{peer} (macOS)"),
        Some("windows") => format!("{peer} (Windows)"),
        Some("linux") => format!("{peer} (Linux)"),
        Some("android") => format!("{peer} (Android)"),
        Some("ios") => format!("{peer} (iOS)"),
        _ => peer.to_string(),
    }
}

#[derive(Default, Clone)]
struct Snapshot {
    online: bool,
    on: bool,
    status: String,
    phase: String,
    peer: Option<String>,
    platform: Option<String>,
    peer_battery: u8,
    peer_charging: bool,
    battery: u8,
    charging: bool,
    history: usize,
    version: String,
}

impl Snapshot {
    /// The peer link is genuinely up (not merely "name remembered for a
    /// reconnect"). Battery / "linked" must gate on this, never on peer-name
    /// presence — the daemon keeps the name across a drop for reconnect UX.
    fn connected(&self) -> bool {
        matches!(self.phase.as_str(), "linked" | "paused" | "halted")
    }
}

/// Renders a battery reading: "—" for the 255 sentinel (not read / no
/// battery), else "63%" with a ⚡ when on external power.
fn fmt_batt(level: u8, charging: bool) -> String {
    if level > 100 {
        "—".to_string()
    } else if charging {
        format!("{level}% ⚡")
    } else {
        format!("{level}%")
    }
}

fn query() -> Snapshot {
    match ipc(&ipc_path(), r#"{"id":1,"op":"status"}"#) {
        Some(v) if v.get("ok").and_then(Value::as_bool).unwrap_or(false) => {
            let d = &v["data"];
            Snapshot {
                online: true,
                on: d["on"].as_bool().unwrap_or(false),
                status: d["status"].as_str().unwrap_or("").to_string(),
                phase: d["phase"].as_str().unwrap_or("").to_string(),
                peer: d["peer_name"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                platform: d["peer_platform"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                peer_battery: d["peer_battery"].as_u64().unwrap_or(255) as u8,
                peer_charging: d["peer_charging"].as_bool().unwrap_or(false),
                battery: d["battery_level"].as_u64().unwrap_or(255) as u8,
                charging: d["charging"].as_bool().unwrap_or(false),
                history: d["history"].as_array().map_or(0, Vec::len),
                version: d["version"].as_str().unwrap_or("").to_string(),
            }
        }
        _ => Snapshot::default(),
    }
}

fn send(req: &'static str) {
    let _ = ipc(&ipc_path(), req);
}

/// DIR-P3-11: "Pair device…" entry for this minimal tray. It has no
/// QR/PIN/verify-words screens of its own (deliberately — "no webkit, no
/// GTK, no embedded UI", per the module doc comment), so it:
///   1. Prefers handing off to the full Tauri GUI build if one is
///      installed — it has the real pairing flow this tray doesn't
///      reimplement. Best-effort PATH probe only; there is no install
///      registry to consult, so this covers the common case (a Tauri
///      `.deb`/AppImage on PATH) and silently falls through otherwise.
///   2. Otherwise asks the daemon directly for pair info — the exact same
///      `pair_show` op `fluxctl pair show` and the macOS/Windows tray use
///      (see `fluxsyncd::cmd::CmdOp::PairShow`) — reusing this file's own
///      `ipc()` helper rather than shelling out to `fluxctl`, so this
///      doesn't gain a new "is fluxctl installed?" failure mode.
///   3. Surfaces the PIN + verification words + URI via a desktop
///      notification (`notify-send`, present on virtually every
///      freedesktop desktop) AND stdout — zenity may not be installed,
///      and stdout is a guaranteed fallback for a tray started from a
///      terminal with no notification daemon running.
fn pair_device() {
    if let Some(gui) = locate_full_gui() {
        if std::process::Command::new(&gui).spawn().is_ok() {
            return;
        }
    }
    match ipc(&ipc_path(), r#"{"id":1,"op":"pair_show"}"#) {
        Some(v) if v.get("ok").and_then(Value::as_bool).unwrap_or(false) => {
            let d = &v["data"];
            let pin = d["pin"].as_str().unwrap_or("");
            let uri = d["uri"].as_str().unwrap_or("");
            let words: Vec<&str> = d["fingerprint_words"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut body = String::new();
            if !pin.is_empty() {
                body.push_str(&format!("PIN: {pin}\n"));
            }
            if !words.is_empty() {
                body.push_str(&format!("Words: {}\n", words.join(" ")));
            }
            body.push_str(uri);
            notify("FluxSync — pair this device", &body);
        }
        Some(v) => {
            let err = v["err"].as_str().unwrap_or("unknown error");
            notify("FluxSync — pairing unavailable", err);
        }
        None => notify("FluxSync — pairing unavailable", "daemon unreachable"),
    }
}

/// Best-effort lookup of a full FluxSync GUI build on PATH. There is no
/// registry of Linux install locations for the Tauri build today, so this
/// only checks a couple of plausible binary names (the Cargo package name
/// used by a `cargo build`/dev checkout, and a product-name-derived name a
/// packaged `.deb`/AppImage might install as) — never a hard requirement,
/// `pair_device` falls back to the daemon-direct path if nothing matches.
fn locate_full_gui() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for name in ["fluxsync", "fluxsync-macos-tray"] {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// Show a desktop notification via `notify-send`, plus an unconditional
/// stdout `println!` — the tray must never block its event loop on this,
/// and a headless/no-notification-daemon session still needs a way to see
/// the PIN.
fn notify(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .arg(title)
        .arg(body)
        .spawn();
    println!("{title}\n{body}");
}

struct FluxTray {
    snap: Snapshot,
}

impl Tray for FluxTray {
    fn id(&self) -> String {
        "sn.kaolack.fluxsync".into()
    }

    fn title(&self) -> String {
        "FluxSync".into()
    }

    // Themed clipboard icon — present on every KDE Plasma install.
    fn icon_name(&self) -> String {
        "klipper".into()
    }

    fn tool_tip(&self) -> ToolTip {
        let description = if !self.snap.online {
            "Daemon unreachable".into()
        } else if self.snap.connected() {
            match &self.snap.peer {
                Some(p) => format!(
                    "Linked · {} {} · {} items",
                    with_platform(p, self.snap.platform.as_deref()),
                    fmt_batt(self.snap.peer_battery, self.snap.peer_charging),
                    self.snap.history,
                ),
                None => format!("Linked · {} items", self.snap.history),
            }
        } else if self.snap.on {
            match &self.snap.peer {
                Some(p) => format!(
                    "Reconnecting — {}",
                    with_platform(p, self.snap.platform.as_deref())
                ),
                None => "Searching — no peer".into(),
            }
        } else {
            "Paused".into()
        };
        ToolTip {
            icon_name: "klipper".into(),
            icon_pixmap: Vec::new(),
            title: format!("FluxSync {}", self.snap.version),
            description,
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let statusline = if !self.snap.online {
            "● daemon unreachable".to_string()
        } else if self.snap.connected() {
            match &self.snap.peer {
                Some(p) => format!(
                    "● linked — {} · {}",
                    with_platform(p, self.snap.platform.as_deref()),
                    fmt_batt(self.snap.peer_battery, self.snap.peer_charging),
                ),
                None => "● linked".to_string(),
            }
        } else if self.snap.on {
            match &self.snap.peer {
                Some(p) => format!(
                    "○ reconnecting — {}",
                    with_platform(p, self.snap.platform.as_deref())
                ),
                None => "○ searching".to_string(),
            }
        } else {
            "○ paused".to_string()
        };

        let on_now = self.snap.online && self.snap.on;
        let toggle_label = if on_now { "Pause sync" } else { "Resume sync" };

        vec![
            StandardItem {
                label: statusline,
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: toggle_label.into(),
                activate: Box::new(move |_: &mut FluxTray| {
                    send(if on_now {
                        r#"{"id":1,"op":"toggle","on":false}"#
                    } else {
                        r#"{"id":1,"op":"toggle","on":true}"#
                    });
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Reconnect".into(),
                activate: Box::new(|_: &mut FluxTray| send(r#"{"id":1,"op":"reconnect"}"#)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Pair device…".into(),
                activate: Box::new(|_: &mut FluxTray| pair_device()),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit tray".into(),
                activate: Box::new(|_: &mut FluxTray| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn main() {
    let service = TrayService::new(FluxTray { snap: query() });
    let handle = service.handle();
    service.spawn();

    loop {
        // 1s poll: a local status IPC is cheap, and a tray that lags the
        // real state by up to 3s reads as broken when a peer plugs in or
        // drops. Pairs with the daemon's ~9s disconnect detection.
        std::thread::sleep(Duration::from_secs(1));
        let snap = query();
        handle.update(move |t: &mut FluxTray| t.snap = snap.clone());
    }
}
