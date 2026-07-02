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
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
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
