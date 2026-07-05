use crate::error::CoreError;
use crate::policy::{Direction, FirewallPolicy};
use fluxsync_proto::Kind;
use serde::{Deserialize, Serialize};

/// JSON shape served over the IPC `state` channel.
///
/// Field names use snake_case so they match what every consumer of the
/// daemon already expects: the macOS tray reads `s.battery_level` /
/// `s.peer_name` (`apps/macos-tray/src/app.js`), and the Android
/// `DaemonState.kt` parser keys off the same shape. The original v0.1
/// React mock used camelCase, but it was the only thing left expecting
/// that shape — every current client now reads snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::struct_excessive_bools)] // Wire DTO: field shape is fixed by the macOS/Android IPC consumers.
pub struct State {
    pub phase: String,
    pub on: bool,
    pub battery_level: u8,
    pub battery_threshold: u8,
    pub charging: bool,
    pub peer_id: [u8; 32],
    pub peer_name: String,
    pub trusted_peer_name: Option<String>,
    /// DIR-P3-01: this device's own friendly name, as sent in `Msg::Hello`
    /// on the next session establishment. Mirrors `Config.peer_name_self` so
    /// clients (fluxctl, tray, Android settings) can render + edit it via
    /// `CmdOp::SetDeviceName` without a separate read path. `#[serde(
    /// default)]` keeps older snapshots (pre-rename) deserializing.
    #[serde(default)]
    pub device_name: String,
    /// Peer's OS family (`macos`/`windows`/`linux`/`android`/`ios`), learned
    /// from `Msg::Hello`. Empty until the peer's Hello arrives. Frontends key
    /// the device icon off this instead of hardcoding one.
    pub peer_platform: String,
    /// Negotiated capability set from the peer's `Msg::Hello.caps`
    /// (DIR-P1-01) — the intersection with what this build supports. Empty
    /// until the peer's Hello arrives, or if it and this build share no
    /// caps.
    pub peer_caps: Vec<String>,
    pub peer_battery: u8,
    pub peer_charging: bool,
    /// FluxMesh Phase 3: every peer with a live mesh session, including the
    /// primary. The legacy `peer_*` fields above remain the primary's
    /// projection so single-peer clients keep working; clients that render a
    /// device list read this instead. Empty until at least one peer links;
    /// the daemon rebuilds it at every `EmitState` from the live session set
    /// (so a dead session never lingers as a ghost entry).
    pub peers: Vec<PeerInfo>,
    pub history: Vec<HistoryItem>,
    pub status: Status,
    pub version: String,
    /// Short build identifier (git short hash, `-dirty` suffixed for an
    /// uncommitted tree). Lets a launcher detect that it spawned — or is
    /// talking to — a stale daemon binary and refresh it. Empty/`unknown`
    /// when the build wasn't stamped.
    pub build_id: String,
    pub link_latency_ms: u32,
    pub cipher: String,
    pub metrics: Option<ConnectionMetrics>,
    pub charge_override: bool,
    /// Clipboard firewall policy (chantier A). Mirrors `Config.firewall` so
    /// clients can render + drive the per-content-type toggles. `#[serde(
    /// default)]` keeps older snapshots (pre-firewall) deserializing.
    #[serde(default)]
    pub firewall: FirewallPolicy,
    /// Items the firewall held under an `Ask` rule, awaiting the user's
    /// approve/deny. The UI lists these; a `resolve` IPC clears one by its
    /// `hash`. Binary payloads are NOT carried here (only a hash + preview) —
    /// the daemon keeps the bytes out of the wire, same as `history`.
    #[serde(default)]
    pub pending: Vec<PendingItem>,
    /// Monotonic counter bumped on every *security* history wipe
    /// (untrusted-peer-seen, ghost-timeout, FS-046 peer-swap). The daemon's
    /// vault persister watches it: a change means "also wipe the on-disk
    /// vault and forget cached favorites" so a favorited secret cannot be
    /// re-appended and the encrypted file cannot outlive the in-memory wipe.
    /// `#[serde(skip)]` keeps it out of the IPC JSON — it is an in-process
    /// signal only, so the macOS/Android wire shape is unchanged.
    #[serde(skip)]
    pub vault_wipe_gen: u64,
    /// DIR-P3-10 (`fluxctl doctor`): mirrors `DaemonConfig::disable_mdns`
    /// (negated), so a client can tell "no live peer, mDNS is off" apart
    /// from "no live peer, still searching" without a new IPC round trip.
    /// `#[serde(default = "default_mdns_enabled")]` keeps older snapshots
    /// (pre-doctor) deserializing as the common case (mDNS on).
    #[serde(default = "default_mdns_enabled")]
    pub mdns_enabled: bool,
    /// Wire-level mutual SAS confirmation (`sas-confirm` capability):
    /// `"idle"` | `"showing"` | `"peer_confirmed"` | `"local_confirmed"` |
    /// `"confirmed"` | `"peer_rejected"`. Driven by `Event::SasPairingStarted`
    /// / `SasLocalConfirmed` / `SasPeerConfirmed` / `SasPeerRejected` /
    /// `SasReset` (see `App::handle`). `#[serde(default = ...)]` keeps older
    /// state snapshots (pre-sas-confirm) deserializing as `"idle"`.
    #[serde(default = "default_sas_phase")]
    pub sas_phase: String,
}

fn default_mdns_enabled() -> bool {
    true
}

fn default_sas_phase() -> String {
    String::from("idle")
}

/// One clipboard item parked by the firewall's `Ask` rule, surfaced to the UI
/// so the user can approve or deny it. Mirrors a `HistoryItem`'s display fields
/// but adds the flow `direction` and omits the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PendingItem {
    /// Hex of the 32-byte content hash. The resolve key.
    pub hash: String,
    pub kind: Kind,
    pub preview: String,
    pub sensitive: bool,
    /// Inbound (awaiting apply) or Outbound (awaiting send).
    pub direction: Direction,
    /// FIX1 (P0 parked-payload leak): hex-encoded id of the peer this item
    /// is tied to — the sender, for an Inbound item. `None` for an Outbound
    /// item (locally copied; not tied to a specific peer in today's
    /// single-primary-peer model) or for an older daemon build that hadn't
    /// stamped one yet. Lets `App::drop_pending_for` selectively clear one
    /// revoked peer's parked items without wiping every other peer's.
    /// `#[serde(default)]` keeps older State JSON (pre-this-field)
    /// deserializing; clients that don't recognize the key ignore it
    /// (verified tolerant: macOS/linux tray JS, Android's `org.json`-based
    /// `parsePending`).
    #[serde(default)]
    pub peer_id: Option<String>,
}

/// One mesh peer in the `State.peers` list (FluxMesh Phase 3). A flat
/// projection of what the UI needs to draw a device row — identity, name,
/// OS icon, battery — for each peer that currently holds a live session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub name: String,
    /// OS family (`macos`/`windows`/`linux`/`android`/`ios`), from `Hello`.
    /// Empty until the peer's Hello arrives.
    pub platform: String,
    pub battery: u8,
    pub charging: bool,
    /// True for the peer the legacy single-peer `State.peer_*` fields project
    /// (the FSM-driven primary link). Exactly one entry is primary when any
    /// peer is linked.
    pub primary: bool,
    /// Negotiated capability set from this peer's `Msg::Hello.caps`
    /// (DIR-P1-01). Empty until its Hello arrives.
    pub caps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionMetrics {
    pub handshakes_total: u64,
    pub handshakes_failed: u64,
    pub heartbeats_sent: u64,
    pub heartbeats_received: u64,
    pub heartbeats_missed_consecutive: u8,
    pub last_rtt_ms: u32,
    pub rtt_p99_ms: u32,
    pub network_changes: u64,
    pub reconnects: u64,
    pub decrypt_failures: u64,
    /// DIR-P1-09: content-hash dedup drops (an echo of our own local copy,
    /// or a peer retransmit already applied). Counted at `App::handle`'s
    /// `suppress_action` sites via `Action::DuplicateDropped`.
    pub dedup_drops: u64,
    pub last_disconnect_reason: Option<DisconnectReason>,
    pub uptime_session_secs: u64,
    /// DIR-P1-09: clipboard items successfully handed to the transport for
    /// sending (`Action::SendItem`, fanned out to at least one linked peer).
    /// Counts logical items, not wire frames — a chunked image is one.
    #[serde(default)]
    pub items_sent: u64,
    /// DIR-P1-09: clipboard items applied to the local OS clipboard
    /// (`Action::WriteClipboard`) after arriving from a peer.
    #[serde(default)]
    pub items_received: u64,
    /// resync-1: items actually re-sent while serving a peer's
    /// `Msg::ResyncPull` (one per item found in our outbox and re-sent, not
    /// per requested hash — a hash we don't hold is silently skipped).
    #[serde(default)]
    pub items_resynced: u64,
    /// resync-1 apply-suppression fix (DEFECT 1): items that arrived in
    /// response to OUR OWN `ResyncPull` and so were deliberately NOT applied
    /// to the OS clipboard (`Action::WriteClipboard` stripped) — still
    /// entered history/vault/relay and were still acked. Test-visible proof
    /// that a resync delivery didn't silently overwrite the user's current
    /// clipboard; see `Action::ResyncApplySuppressed`.
    #[serde(default)]
    pub resync_applies_suppressed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    HeartbeatTimeout, // 3 missed = peer offline
    NetworkChanged,   // if-watch detected a network change
    DecryptFailure,   // tag invalide → session destroyed
    PeerSentBye,
    IpcShutdown,
    UnknownTransportError,
}

/// One row of the UI's history list. The daemon builds `preview` from the
/// underlying `ClipboardItem.payload` (truncated, sanitized) and sets
/// `time` from the wall clock at insertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HistoryItem {
    pub kind: Kind,
    pub preview: String,
    pub time: String, // "HH:MM"
    pub source: HistorySource,
    pub sensitive: bool,
    pub lamport: u64,
    /// Hex of the 32-byte content hash. Lets the Android client fetch an
    /// image's raw bytes on demand (`fetch_item`) — the daemon never puts
    /// binary payloads in the state JSON, only this hash + a label.
    pub hash: String,
    /// FluxVault: pinned by the user. Favorites survive the vault's TTL and
    /// disk cap. `#[serde(default)]` so older state/vault JSON (pre-favorites)
    /// and clients that don't send the field still deserialize to `false`.
    #[serde(default)]
    pub favorite: bool,
    /// resync-1: true when this item was delivered as a catch-up response to
    /// OUR OWN `ResyncPull` (not a live/fresh copy). Local IPC/state/vault
    /// projection only — never part of the wire protocol. `#[serde(default)]`
    /// so older state/vault JSON (pre-resync-marker) still deserializes to
    /// `false`. Lets clients (e.g. Android) tell history-only catch-up items
    /// apart from items that should be applied to the OS clipboard.
    #[serde(default)]
    pub resync: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistorySource {
    Local,
    Remote,
}

/// Derived status reported to UIs. The daemon never sets this directly;
/// `policy::status_for` is the single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Inactive,
    Syncing,
    Paused,
    Critical,
}

/// Static configuration baked into the running daemon. None of these change
/// during normal operation; threshold mutates via a CLI command, peer name
/// is set at install time.
#[derive(Debug, Clone)]
pub struct Config {
    pub peer_name_self: String,
    pub charge_override: bool,
    pub version: String,
    pub build_id: String,
    pub cipher: String,
    /// Clipboard firewall (chantier A). Disabled by default, so a daemon
    /// built without firewall config syncs everything exactly as before.
    pub firewall: FirewallPolicy,
    /// DIR-P3-10: mirrors `DaemonConfig::disable_mdns` (negated). Projected
    /// into `State.mdns_enabled` for `fluxctl doctor`.
    pub mdns_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            peer_name_self: String::from("this device"),
            charge_override: true,
            version: String::from(env!("CARGO_PKG_VERSION")),
            build_id: String::from("unknown"),
            cipher: String::from("chacha20-poly1305"),
            firewall: FirewallPolicy::default(),
            mdns_enabled: true,
        }
    }
}

impl State {
    /// Initial state at process boot. Threshold defaults to 20% (matches
    /// the macOS slider and Android UI default position).
    #[must_use]
    pub fn initial(config: &Config) -> Self {
        Self {
            phase: String::from("idle"),
            on: false,
            // 255 = "not read yet" sentinel → UI renders "—" instead of a
            // fake 100%. Safe for policy: every `<= threshold` / `<= CRITICAL`
            // check is false at 255, so an unread battery never forces a pause.
            // The watcher (desktop) or set_self_battery (Android) overwrites it
            // with a real 0-100 within a few seconds; a battery-less desktop
            // keeps 255 and shows "—".
            battery_level: 255,
            battery_threshold: 20,
            charging: false,
            peer_id: [0u8; 32],
            peer_name: String::new(),
            trusted_peer_name: None,
            device_name: config.peer_name_self.clone(),
            peer_platform: String::new(),
            peer_caps: Vec::new(),
            peer_battery: 255, // sentinel: unknown until first BatteryStatus → UI shows "—"
            peer_charging: false,
            peers: Vec::new(),
            history: Vec::new(),
            status: Status::Inactive,
            version: config.version.clone(),
            build_id: config.build_id.clone(),
            link_latency_ms: 0,
            cipher: config.cipher.clone(),
            metrics: None,
            charge_override: config.charge_override,
            firewall: config.firewall.clone(),
            pending: Vec::new(),
            vault_wipe_gen: 0,
            mdns_enabled: config.mdns_enabled,
            sas_phase: default_sas_phase(),
        }
    }

    /// Sets a new threshold, validating it lies in `5..=50` (matches the
    /// frontend slider range).
    pub fn set_threshold(&mut self, value: u8) -> Result<(), CoreError> {
        if !(5..=50).contains(&value) {
            return Err(CoreError::ThresholdOutOfRange(value));
        }
        self.battery_threshold = value;
        Ok(())
    }

    /// Sets a battery level, validating it is `<= 100`.
    pub fn set_self_battery(&mut self, level: u8, charging: bool) -> Result<(), CoreError> {
        if level > 100 {
            return Err(CoreError::BatteryLevel(level));
        }
        self.battery_level = level;
        self.charging = charging;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_inactive_with_baked_config() {
        let cfg = Config::default();
        let s = State::initial(&cfg);
        assert!(!s.on);
        assert_eq!(s.battery_threshold, 20);
        assert_eq!(s.status, Status::Inactive);
        assert_eq!(s.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(s.cipher, "chacha20-poly1305");
    }

    #[test]
    fn set_threshold_accepts_inclusive_range() {
        let mut s = State::initial(&Config::default());
        assert!(s.set_threshold(5).is_ok());
        assert!(s.set_threshold(50).is_ok());
        assert!(s.set_threshold(20).is_ok());
    }

    #[test]
    fn set_threshold_rejects_out_of_range() {
        let mut s = State::initial(&Config::default());
        assert!(matches!(
            s.set_threshold(4),
            Err(CoreError::ThresholdOutOfRange(4))
        ));
        assert!(matches!(
            s.set_threshold(51),
            Err(CoreError::ThresholdOutOfRange(51))
        ));
        assert!(matches!(
            s.set_threshold(0),
            Err(CoreError::ThresholdOutOfRange(0))
        ));
    }

    #[test]
    fn initial_state_sas_phase_is_idle() {
        let s = State::initial(&Config::default());
        assert_eq!(s.sas_phase, "idle");
    }

    #[test]
    fn sas_phase_defaults_to_idle_on_old_json() {
        // Pre-sas-confirm snapshot: no `sas_phase` key at all.
        let mut v = serde_json::to_value(State::initial(&Config::default())).unwrap();
        v.as_object_mut().unwrap().remove("sas_phase");
        let s: State = serde_json::from_value(v).unwrap();
        assert_eq!(s.sas_phase, "idle");
    }

    #[test]
    fn set_self_battery_rejects_over_100() {
        let mut s = State::initial(&Config::default());
        assert!(s.set_self_battery(0, false).is_ok());
        assert!(s.set_self_battery(100, true).is_ok());
        assert!(matches!(
            s.set_self_battery(101, false),
            Err(CoreError::BatteryLevel(101))
        ));
    }

    #[test]
    fn json_field_names_match_snake_case_wire() {
        let cfg = Config::default();
        let s = State::initial(&cfg);
        let j = serde_json::to_value(&s).unwrap();
        for k in [
            "phase",
            "on",
            "battery_level",
            "battery_threshold",
            "charging",
            "peer_id",
            "peer_name",
            "trusted_peer_name",
            "device_name",
            "peer_battery",
            "peer_charging",
            "peers",
            "history",
            "status",
            "version",
            "build_id",
            "link_latency_ms",
            "cipher",
            "charge_override",
            "firewall",
            "pending",
            "mdns_enabled",
            "sas_phase",
        ] {
            assert!(j.get(k).is_some(), "missing key {k} in JSON shape");
        }
    }
}
