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

#[derive(Default, Clone)]
struct Snapshot {
    online: bool,
    on: bool,
    status: String,
    peer: Option<String>,
    history: usize,
    version: String,
}

fn query() -> Snapshot {
    match ipc(&ipc_path(), r#"{"id":1,"op":"status"}"#) {
        Some(v) if v.get("ok").and_then(Value::as_bool).unwrap_or(false) => {
            let d = &v["data"];
            Snapshot {
                online: true,
                on: d["on"].as_bool().unwrap_or(false),
                status: d["status"].as_str().unwrap_or("").to_string(),
                peer: d["peer_name"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
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
        } else if let Some(p) = &self.snap.peer {
            format!("{} · {} · {} items", self.snap.status, p, self.snap.history)
        } else if self.snap.on {
            "Discovering — no peer".into()
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
        } else if let Some(p) = &self.snap.peer {
            format!("● linked — {p}")
        } else if self.snap.on {
            "○ discovering".to_string()
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
        std::thread::sleep(Duration::from_secs(3));
        let snap = query();
        handle.update(move |t: &mut FluxTray| t.snap = snap.clone());
    }
}
