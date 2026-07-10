//! `fluxctl doctor` — one-shot diagnostic: why isn't sync working?
//!
//! Every verdict below is a pure function over already-fetched inputs (the
//! daemon's `status` response, an optional trusted-peer count, and a few
//! local filesystem facts), so the whole checklist is unit-testable without
//! a running daemon. [`run`] is the only impure part: it makes the IPC
//! calls, reads the data dir, then prints.

use anyhow::Result;
use owo_colors::OwoColorize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    fn word(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }

    fn colored_tag(self) -> String {
        let tag = format!("{:<4}", self.word().to_uppercase());
        match self {
            Level::Ok => tag.green().to_string(),
            Level::Info => tag.bright_black().to_string(),
            Level::Warn => tag.yellow().bold().to_string(),
            Level::Fail => tag.red().bold().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub message: String,
}

impl Check {
    fn new(name: &'static str, level: Level, message: impl Into<String>) -> Self {
        Self {
            name,
            level,
            message: message.into(),
        }
    }
}

fn u64_field(data: &Value, key: &str, default: u64) -> u64 {
    data.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn bool_field(data: &Value, key: &str, default: bool) -> bool {
    data.get(key).and_then(Value::as_bool).unwrap_or(default)
}

// ── 1. daemon reachable ────────────────────────────────────────────────

fn daemon_launch_hint(platform: &str) -> &'static str {
    match platform {
        "macos" => {
            "start the FluxSync app (Dock) — it manages fluxsyncd for you — \
             or run `fluxsyncd` directly"
        }
        "windows" => {
            "start the FluxSync tray app — it manages fluxsyncd for you — \
             or run `fluxsyncd.exe` directly"
        }
        "linux" => {
            "run `fluxsyncd` in the foreground, or enable the systemd user unit: \
             `systemctl --user enable --now fluxsync.service` (see README's Linux section)"
        }
        _ => "start `fluxsyncd` — see the README Quickstart",
    }
}

fn check_daemon(reachable: bool, err: Option<&str>, hint: &str) -> Check {
    if reachable {
        Check::new(
            "daemon",
            Level::Ok,
            "IPC socket reachable, status query answered",
        )
    } else {
        let detail = err.unwrap_or("connection failed");
        Check::new(
            "daemon",
            Level::Fail,
            format!("cannot reach the daemon ({detail}) — {hint}"),
        )
    }
}

// ── 2. sync enabled ────────────────────────────────────────────────────

fn check_sync(data: Option<&Value>) -> Check {
    let Some(data) = data else {
        return Check::new("sync", Level::Info, "skipped: no status data available");
    };
    if bool_field(data, "on", false) {
        Check::new("sync", Level::Ok, "daemon is ON")
    } else {
        Check::new(
            "sync",
            Level::Warn,
            "daemon is OFF — `fluxctl on` to enable syncing",
        )
    }
}

// ── 3. phase ───────────────────────────────────────────────────────────

/// Mirrors `fluxsync_core::policy::status_for`'s battery gate. Duplicated
/// here (fluxctl has no dependency on fluxsync-core) — if that policy ever
/// changes, this explanation must be updated to match.
fn paused_cause(data: &Value) -> String {
    let battery_level = u64_field(data, "battery_level", 255);
    let threshold = u64_field(data, "battery_threshold", 20);
    let charging = bool_field(data, "charging", false);
    let peer_battery = u64_field(data, "peer_battery", 255);
    let peer_charging = bool_field(data, "peer_charging", false);
    let charge_override = bool_field(data, "charge_override", true);

    let self_below = battery_level <= threshold && !(charge_override && charging);
    let peer_below = peer_battery <= threshold && !(charge_override && peer_charging);

    match (self_below, peer_below) {
        (true, true) => format!(
            "paused — this device ({battery_level}%) and the peer ({peer_battery}%) are \
             both <= the {threshold}% threshold and neither is charging"
        ),
        (true, false) => format!(
            "paused — this device's battery is {battery_level}%, at or below the \
             {threshold}% threshold, and it is not charging"
        ),
        (false, true) => format!(
            "paused — the peer's battery is {peer_battery}%, at or below the \
             {threshold}% threshold, and it is not charging"
        ),
        (false, false) => format!(
            "paused — battery {battery_level}% / peer {peer_battery}% vs threshold \
             {threshold}%; cause unclear (check charge_override)"
        ),
    }
}

fn check_phase(data: Option<&Value>) -> Check {
    let Some(data) = data else {
        return Check::new("phase", Level::Info, "skipped: no status data available");
    };
    let phase = data.get("phase").and_then(Value::as_str).unwrap_or("");
    match phase {
        "linked" => Check::new("phase", Level::Ok, "linked to a peer"),
        "idle" => Check::new("phase", Level::Ok, "idle (sync off)"),
        "discovering" => Check::new(
            "phase",
            Level::Warn,
            "discovering — no peer found yet (mDNS / redial in progress)",
        ),
        "handshaking" => Check::new("phase", Level::Info, "handshake in progress"),
        "paused" => Check::new("phase", Level::Warn, paused_cause(data)),
        "halted" => Check::new(
            "phase",
            Level::Warn,
            "halted — battery critical (<= 5%); the link resumes once charged",
        ),
        other => Check::new("phase", Level::Warn, format!("unrecognized phase {other:?}")),
    }
}

// ── 4. peers (trust-store count) ──────────────────────────────────────

fn check_peers(trust_count: Option<usize>) -> Check {
    match trust_count {
        None => Check::new(
            "peers",
            Level::Info,
            "skipped: could not query the trust store",
        ),
        Some(0) => Check::new(
            "peers",
            Level::Warn,
            "0 paired — pair a device with `fluxctl pair show-qr` or `fluxctl pair accept`",
        ),
        Some(n) => Check::new("peers", Level::Ok, format!("{n} paired")),
    }
}

// ── 5. peer liveness ───────────────────────────────────────────────────

fn check_peer_liveness(data: Option<&Value>, trust_count: Option<usize>) -> Check {
    let Some(data) = data else {
        return Check::new(
            "peer_liveness",
            Level::Info,
            "skipped: no status data available",
        );
    };
    let phase = data.get("phase").and_then(Value::as_str).unwrap_or("");
    if matches!(phase, "linked" | "paused" | "halted") {
        return Check::new("peer_liveness", Level::Ok, "a peer is currently connected");
    }
    match trust_count {
        None => Check::new(
            "peer_liveness",
            Level::Info,
            "no peer connected (trust store unknown)",
        ),
        Some(0) => Check::new(
            "peer_liveness",
            Level::Info,
            "no peer connected (no trusted peers yet)",
        ),
        Some(n) => {
            let mdns_enabled = bool_field(data, "mdns_enabled", true);
            let mdns_note = if mdns_enabled {
                String::new()
            } else {
                " (mDNS discovery is disabled on this daemon — reconnection relies solely \
                 on the persisted last address)"
                    .to_string()
            };
            Check::new(
                "peer_liveness",
                Level::Warn,
                format!(
                    "no peer connected, {n} trusted peer(s) on file — the daemon will redial \
                     the last known address and retry mDNS discovery{mdns_note}"
                ),
            )
        }
    }
}

// ── 6. reliability counters ────────────────────────────────────────────

fn check_counters(metrics: Option<&Value>) -> Check {
    let Some(m) = metrics.filter(|v| !v.is_null()) else {
        return Check::new(
            "counters",
            Level::Info,
            "no metrics yet (daemon just started / never linked)",
        );
    };
    let sent = u64_field(m, "items_sent", 0);
    let received = u64_field(m, "items_received", 0);
    let dedup = u64_field(m, "dedup_drops", 0);
    let resynced = u64_field(m, "items_resynced", 0);
    let reconnects = u64_field(m, "reconnects", 0);
    let hs_failed = u64_field(m, "handshakes_failed", 0);
    // NOTE: `items_sent > 0 && items_received == 0` is deliberately NOT used
    // as a "no acks" heuristic — `items_received` counts items applied from
    // the peer's own copies, which is independent of whether the peer
    // received what we sent. That signal isn't derivable from the current
    // counters without a false-alarm risk, so the only WARN trigger here is
    // the one counter that unambiguously means "something failed".
    if hs_failed > 0 {
        Check::new(
            "counters",
            Level::Warn,
            format!(
                "handshakes_failed={hs_failed} this session — check peer reachability, \
                 clock skew, or a stale trusted pubkey"
            ),
        )
    } else {
        Check::new(
            "counters",
            Level::Ok,
            format!(
                "sent {sent} · recv {received} · dedup {dedup} · resynced {resynced} · \
                 reconnects {reconnects} · no failed handshakes"
            ),
        )
    }
}

// ── 7. data dir ─────────────────────────────────────────────────────────

struct DataDirFacts {
    exists: bool,
    writable: bool,
    history_enc_size: Option<u64>,
    event_seq_present: bool,
}

fn check_data_dir(dir: &Path, facts: &DataDirFacts) -> Check {
    if !facts.exists {
        return Check::new(
            "data_dir",
            Level::Warn,
            format!(
                "{} does not exist yet — run fluxsyncd once to create it",
                dir.display()
            ),
        );
    }
    if !facts.writable {
        return Check::new(
            "data_dir",
            Level::Warn,
            format!("{} exists but is not writable — fix permissions", dir.display()),
        );
    }
    let hist = match facts.history_enc_size {
        Some(n) => format!("history.enc {n} bytes"),
        None => "history.enc absent (no persisted history yet)".to_string(),
    };
    let seq = if facts.event_seq_present {
        "event_seq.json present"
    } else {
        "event_seq.json absent (fresh install)"
    };
    Check::new(
        "data_dir",
        Level::Ok,
        format!("{} — {hist}; {seq}", dir.display()),
    )
}

fn probe_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".fluxctl-doctor-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

// ── 7b. identity source (never touches the real keychain) ─────────────

fn identity_source_message(no_keychain: bool, strict: bool, platform: &str) -> String {
    if no_keychain {
        return "plaintext file (identity.bin) — FLUXSYNC_NO_KEYCHAIN=1".to_string();
    }
    let backend = match platform {
        "macos" => "macOS Keychain",
        "windows" => "Windows Credential Manager",
        "linux" => "Secret Service (dbus)",
        other => other,
    };
    if strict && platform == "macos" {
        format!("OS keychain ({backend}, strict self-only ACL — FLUXSYNC_STRICT_KEYCHAIN=1)")
    } else {
        format!("OS keychain ({backend})")
    }
}

/// `no_keychain`/`strict` are read from *this* process's environment, which
/// may differ from the daemon's if the two were launched in different
/// shells/services — `identity_file_on_disk` is ground truth from the data
/// dir and corrects for that mismatch when it disagrees.
fn check_identity(no_keychain: bool, strict: bool, platform: &str, identity_file_on_disk: bool) -> Check {
    let mut msg = identity_source_message(no_keychain, strict, platform);
    if identity_file_on_disk && !no_keychain {
        msg.push_str(
            " — note: identity.bin also exists on disk; either FLUXSYNC_NO_KEYCHAIN=1 is set \
             in the daemon's own environment (this shell may not share it), or it's a leftover \
             from a failed keychain-wipe after migration",
        );
    }
    // DIR-P2-06: surface the same advisory the daemon logs at startup —
    // the identity secret sits unencrypted on disk in this mode. `Warn`,
    // not `Fail`: it's an intentional, opt-in escape hatch for headless/
    // dark-wake boots where the OS keychain is unavailable, not a bug.
    let level = if no_keychain {
        msg.push_str(
            " — unencrypted on disk; intended for headless/dark-wake boots only",
        );
        Level::Warn
    } else {
        Level::Info
    };
    Check::new("identity", level, msg)
}

// ── 8. version ──────────────────────────────────────────────────────────

fn check_version(fluxctl_version: &str, daemon_version: Option<&Value>) -> Check {
    let Some(dv) = daemon_version.and_then(Value::as_str) else {
        return Check::new(
            "version",
            Level::Info,
            "skipped: daemon unreachable or version not reported",
        );
    };
    if dv == fluxctl_version {
        Check::new(
            "version",
            Level::Ok,
            format!("fluxctl {fluxctl_version} matches daemon {dv}"),
        )
    } else {
        Check::new(
            "version",
            Level::Warn,
            format!("fluxctl {fluxctl_version} != daemon {dv} — rebuild/reinstall matching binaries"),
        )
    }
}

// ── orchestration (impure: IPC + filesystem) ───────────────────────────

/// Runs the full checklist, prints it (plain text or `--json`), and
/// returns `true` when every check is below [`Level::Fail`] (the caller
/// maps this to the process exit code).
pub async fn run(ipc_path: &Path, json: bool) -> Result<bool> {
    let status_result = crate::one_shot(ipc_path, json!({"id": 1, "op": "status"})).await;
    let (reachable, connect_err, data) = match status_result {
        Ok(v) => (true, None, v.get("data").cloned()),
        Err(e) => (false, Some(e.to_string()), None),
    };

    let trust_count = if reachable {
        crate::one_shot(ipc_path, json!({"id": 1, "op": "trust_list"}))
            .await
            .ok()
            .and_then(|v| v.get("data").and_then(Value::as_array).map(Vec::len))
    } else {
        None
    };

    // The IPC socket lives inside the daemon's data dir by convention
    // (`~/.fluxsync/{sock,identity.bin,peers.json,...}`), including under a
    // custom `--ipc-path` — best-effort assumption, not enforced.
    let data_dir = ipc_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let dir_exists = data_dir.is_dir();
    let dir_writable = dir_exists && probe_writable(&data_dir);
    let history_enc_size = std::fs::metadata(data_dir.join("history.enc"))
        .ok()
        .map(|m| m.len());
    let event_seq_present = data_dir.join("event_seq.json").is_file();
    let identity_file_on_disk = data_dir.join("identity.bin").is_file();

    let no_keychain = std::env::var("FLUXSYNC_NO_KEYCHAIN").as_deref() == Ok("1");
    let strict_keychain = std::env::var("FLUXSYNC_STRICT_KEYCHAIN").as_deref() == Ok("1");
    let platform = std::env::consts::OS;

    let checks = vec![
        check_daemon(reachable, connect_err.as_deref(), daemon_launch_hint(platform)),
        check_sync(data.as_ref()),
        check_phase(data.as_ref()),
        check_peers(trust_count),
        check_peer_liveness(data.as_ref(), trust_count),
        check_counters(data.as_ref().and_then(|d| d.get("metrics"))),
        check_data_dir(
            &data_dir,
            &DataDirFacts {
                exists: dir_exists,
                writable: dir_writable,
                history_enc_size,
                event_seq_present,
            },
        ),
        check_identity(no_keychain, strict_keychain, platform, identity_file_on_disk),
        check_version(
            env!("CARGO_PKG_VERSION"),
            data.as_ref().and_then(|d| d.get("version")),
        ),
    ];

    let all_ok = !checks.iter().any(|c| c.level == Level::Fail);

    if json {
        let arr: Vec<Value> = checks
            .iter()
            .map(|c| {
                json!({
                    "check": c.name,
                    "level": c.level.word(),
                    "message": c.message,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&Value::Array(arr))?);
    } else {
        for c in &checks {
            println!("{}  {:<14} {}", c.level.colored_tag(), c.name, c.message);
        }
    }

    Ok(all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> Value {
        json!({
            "phase": "linked",
            "on": true,
            "battery_level": 80,
            "battery_threshold": 20,
            "charging": false,
            "peer_battery": 55,
            "peer_charging": true,
            "charge_override": true,
            "mdns_enabled": true,
            "version": "0.6.2",
            "metrics": {
                "items_sent": 7,
                "items_received": 5,
                "dedup_drops": 2,
                "items_resynced": 1,
                "reconnects": 1,
                "handshakes_failed": 0,
            },
        })
    }

    #[test]
    fn daemon_reachable_ok() {
        let c = check_daemon(true, None, "hint");
        assert_eq!(c.level, Level::Ok);
    }

    #[test]
    fn daemon_unreachable_fails_with_hint() {
        let c = check_daemon(false, Some("connect ipc /x: No such file"), "start fluxsyncd");
        assert_eq!(c.level, Level::Fail);
        assert!(c.message.contains("start fluxsyncd"));
        assert!(c.message.contains("No such file"));
    }

    #[test]
    fn sync_off_warns() {
        let d = json!({"on": false});
        assert_eq!(check_sync(Some(&d)).level, Level::Warn);
        assert_eq!(check_sync(Some(&json!({"on": true}))).level, Level::Ok);
        assert_eq!(check_sync(None).level, Level::Info);
    }

    #[test]
    fn phase_linked_is_ok() {
        assert_eq!(check_phase(Some(&sample_data())).level, Level::Ok);
    }

    #[test]
    fn phase_discovering_warns() {
        let d = json!({"phase": "discovering"});
        assert_eq!(check_phase(Some(&d)).level, Level::Warn);
    }

    #[test]
    fn phase_handshaking_is_info_not_warn() {
        let d = json!({"phase": "handshaking"});
        assert_eq!(check_phase(Some(&d)).level, Level::Info);
    }

    #[test]
    fn phase_paused_reports_self_battery_cause_with_numbers() {
        let d = json!({
            "phase": "paused",
            "battery_level": 12,
            "battery_threshold": 20,
            "charging": false,
            "peer_battery": 90,
            "peer_charging": true,
            "charge_override": true,
        });
        let c = check_phase(Some(&d));
        assert_eq!(c.level, Level::Warn);
        assert!(c.message.contains("12%"));
        assert!(c.message.contains("20%"));
        assert!(c.message.contains("this device"));
    }

    #[test]
    fn phase_paused_reports_peer_battery_cause() {
        let d = json!({
            "phase": "paused",
            "battery_level": 90,
            "battery_threshold": 20,
            "charging": true,
            "peer_battery": 5,
            "peer_charging": false,
            "charge_override": true,
        });
        let c = check_phase(Some(&d));
        assert!(c.message.contains("peer"));
        assert!(c.message.contains("5%"));
    }

    #[test]
    fn phase_paused_charge_override_off_ignores_charging() {
        // charge_override=false: a below-threshold + charging device must
        // still count as "below", matching policy::status_for exactly.
        let d = json!({
            "phase": "paused",
            "battery_level": 10,
            "battery_threshold": 20,
            "charging": true,
            "peer_battery": 90,
            "peer_charging": true,
            "charge_override": false,
        });
        let c = check_phase(Some(&d));
        assert!(c.message.contains("this device"));
    }

    #[test]
    fn phase_halted_warns_with_critical_battery_cause() {
        let d = json!({"phase": "halted"});
        let c = check_phase(Some(&d));
        assert_eq!(c.level, Level::Warn);
        assert!(c.message.contains("critical"));
    }

    #[test]
    fn peers_zero_warns_with_pair_hint() {
        let c = check_peers(Some(0));
        assert_eq!(c.level, Level::Warn);
        assert!(c.message.contains("pair show-qr"));
    }

    #[test]
    fn peers_nonzero_ok() {
        assert_eq!(check_peers(Some(3)).level, Level::Ok);
    }

    #[test]
    fn peers_unknown_is_info() {
        assert_eq!(check_peers(None).level, Level::Info);
    }

    #[test]
    fn liveness_connected_ok() {
        let d = json!({"phase": "linked"});
        assert_eq!(check_peer_liveness(Some(&d), Some(1)).level, Level::Ok);
    }

    #[test]
    fn liveness_no_peer_but_trusted_peers_warns_with_redial_story() {
        let d = json!({"phase": "discovering", "mdns_enabled": true});
        let c = check_peer_liveness(Some(&d), Some(2));
        assert_eq!(c.level, Level::Warn);
        assert!(c.message.contains("redial"));
        assert!(!c.message.contains("disabled"));
    }

    #[test]
    fn liveness_mentions_disabled_mdns_only_when_reported_off() {
        let d = json!({"phase": "discovering", "mdns_enabled": false});
        let c = check_peer_liveness(Some(&d), Some(2));
        assert!(c.message.contains("mDNS discovery is disabled"));
    }

    #[test]
    fn liveness_no_trusted_peers_is_info_not_warn() {
        let d = json!({"phase": "discovering"});
        let c = check_peer_liveness(Some(&d), Some(0));
        assert_eq!(c.level, Level::Info);
    }

    #[test]
    fn counters_handshake_failures_warn() {
        let m = json!({"handshakes_failed": 2});
        assert_eq!(check_counters(Some(&m)).level, Level::Warn);
    }

    #[test]
    fn counters_healthy_session_is_ok_not_a_false_alarm() {
        // items_sent > 0 && items_received == 0 must NOT warn — it's a
        // completely normal one-directional-copying session.
        let m = json!({
            "items_sent": 5,
            "items_received": 0,
            "handshakes_failed": 0,
        });
        assert_eq!(check_counters(Some(&m)).level, Level::Ok);
    }

    #[test]
    fn counters_absent_metrics_is_info() {
        assert_eq!(check_counters(None).level, Level::Info);
        assert_eq!(check_counters(Some(&Value::Null)).level, Level::Info);
    }

    #[test]
    fn data_dir_missing_warns() {
        let facts = DataDirFacts {
            exists: false,
            writable: false,
            history_enc_size: None,
            event_seq_present: false,
        };
        assert_eq!(check_data_dir(Path::new("/nope"), &facts).level, Level::Warn);
    }

    #[test]
    fn data_dir_present_and_writable_is_ok() {
        let facts = DataDirFacts {
            exists: true,
            writable: true,
            history_enc_size: Some(4096),
            event_seq_present: true,
        };
        let c = check_data_dir(Path::new("/tmp/x"), &facts);
        assert_eq!(c.level, Level::Ok);
        assert!(c.message.contains("4096 bytes"));
    }

    #[test]
    fn identity_reports_no_keychain_env_verbatim() {
        let msg = identity_source_message(true, false, "macos");
        assert!(msg.contains("FLUXSYNC_NO_KEYCHAIN=1"));
        assert!(msg.contains("identity.bin"));
    }

    #[test]
    fn identity_reports_platform_backend() {
        assert!(identity_source_message(false, false, "macos").contains("macOS Keychain"));
        assert!(identity_source_message(false, false, "windows")
            .contains("Windows Credential Manager"));
        assert!(identity_source_message(false, false, "linux").contains("Secret Service"));
    }

    #[test]
    fn identity_reports_strict_acl_only_on_macos() {
        assert!(identity_source_message(false, true, "macos").contains("strict"));
        assert!(!identity_source_message(false, true, "linux").contains("strict"));
    }

    #[test]
    fn identity_check_is_always_info_never_fail_or_warn() {
        let c = check_identity(false, false, "linux", false);
        assert_eq!(c.level, Level::Info);
    }

    #[test]
    fn identity_notes_stray_file_when_env_says_keychain() {
        let c = check_identity(false, false, "linux", true);
        assert!(c.message.contains("also exists on disk"));
    }

    #[test]
    fn identity_no_stray_note_when_no_keychain_env_set() {
        let c = check_identity(true, false, "linux", true);
        assert!(!c.message.contains("also exists on disk"));
    }

    /// DIR-P2-06: `fluxctl doctor` must flag `FLUXSYNC_NO_KEYCHAIN=1` as a
    /// `Warn`, not silently `Info` — the identity secret sits unencrypted
    /// on disk in this mode.
    #[test]
    fn identity_check_warns_when_no_keychain_env_set() {
        let c = check_identity(true, false, "linux", false);
        assert_eq!(c.level, Level::Warn);
        assert!(c.message.contains("unencrypted"));
        assert!(c.message.contains("headless"));
    }

    #[test]
    fn version_match_ok() {
        let v = json!("0.6.2");
        assert_eq!(check_version("0.6.2", Some(&v)).level, Level::Ok);
    }

    #[test]
    fn version_mismatch_warns() {
        let v = json!("0.6.1");
        let c = check_version("0.6.2", Some(&v));
        assert_eq!(c.level, Level::Warn);
        assert!(c.message.contains("0.6.1"));
        assert!(c.message.contains("0.6.2"));
    }

    #[test]
    fn version_unknown_is_info() {
        assert_eq!(check_version("0.6.2", None).level, Level::Info);
    }

    /// End-to-end over one synthetic "everything healthy" snapshot: every
    /// data-dependent check should come back OK.
    #[test]
    fn happy_path_snapshot_is_all_ok() {
        let data = sample_data();
        assert_eq!(check_sync(Some(&data)).level, Level::Ok);
        assert_eq!(check_phase(Some(&data)).level, Level::Ok);
        assert_eq!(check_peer_liveness(Some(&data), Some(1)).level, Level::Ok);
        assert_eq!(
            check_counters(data.get("metrics")).level,
            Level::Ok
        );
        assert_eq!(check_version("0.6.2", data.get("version")).level, Level::Ok);
    }
}
