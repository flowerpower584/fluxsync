use crate::error::CoreError;
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
pub struct State {
    pub phase: String,
    pub on: bool,
    pub battery_level: u8,
    pub battery_threshold: u8,
    pub charging: bool,
    pub peer_id: [u8; 32],
    pub peer_name: String,
    pub trusted_peer_name: Option<String>,
    pub peer_battery: u8,
    pub peer_charging: bool,
    pub history: Vec<HistoryItem>,
    pub status: Status,
    pub version: String,
    pub link_latency_ms: u32,
    pub cipher: String,
    pub metrics: Option<ConnectionMetrics>,
    pub charge_override: bool,
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
    pub dedup_drops: u64,
    pub last_disconnect_reason: Option<DisconnectReason>,
    pub uptime_session_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    HeartbeatTimeout,        // 3 missed = peer offline
    NetworkChanged,          // if-watch a détecté un changement
    DecryptFailure,          // tag invalide → session destroyed
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
    pub cipher: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            peer_name_self: String::from("this device"),
            charge_override: true,
            version: String::from("0.4.2"),
            cipher: String::from("chacha20-poly1305"),
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
            battery_level: 100,
            battery_threshold: 20,
            charging: false,
            peer_id: [0u8; 32],
            peer_name: String::new(),
            trusted_peer_name: None,
            peer_battery: 100, // Default to 100 so it doesn't trigger Critical threshold before the first update
            peer_charging: false,
            history: Vec::new(),
            status: Status::Inactive,
            version: config.version.clone(),
            link_latency_ms: 0,
            cipher: config.cipher.clone(),
            metrics: None,
            charge_override: config.charge_override,
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
        assert_eq!(s.version, "0.4.2");
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
            "peer_battery",
            "peer_charging",
            "history",
            "status",
            "version",
            "link_latency_ms",
            "cipher",
            "charge_override",
        ] {
            assert!(j.get(k).is_some(), "missing key {k} in JSON shape");
        }
    }
}
