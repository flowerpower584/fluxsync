use crate::error::CoreError;
use fluxsync_proto::Kind;
use serde::{Deserialize, Serialize};

/// JSON shape served over the IPC `state` channel. Matches the frontend
/// design 1:1 — see `docs/ARCHITECTURE.md` §4.
///
/// Field names use camelCase via `serde(rename_all)` so the wire stays the
/// same as the React state object the UI already consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub on: bool,
    pub battery_level: u8,
    pub battery_threshold: u8,
    pub charging: bool,
    pub peer_name: String,
    pub peer_battery: u8,
    pub peer_charging: bool,
    pub history: Vec<HistoryItem>,
    pub status: Status,
    pub version: String,
    pub link_latency_ms: u32,
    pub cipher: String,
}

/// One row of the UI's history list. The daemon builds `preview` from the
/// underlying `ClipboardItem.payload` (truncated, sanitized) and sets
/// `time` from the wall clock at insertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItem {
    pub kind: Kind,
    pub preview: String,
    pub time: String, // "HH:MM"
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
    /// Initial state at process boot. Threshold defaults to 15% (matches
    /// the design system's default slider position).
    #[must_use]
    pub fn initial(config: &Config) -> Self {
        Self {
            on: false,
            battery_level: 100,
            battery_threshold: 15,
            charging: false,
            peer_name: String::new(),
            peer_battery: 0,
            peer_charging: false,
            history: Vec::new(),
            status: Status::Inactive,
            version: config.version.clone(),
            link_latency_ms: 0,
            cipher: config.cipher.clone(),
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
        assert_eq!(s.battery_threshold, 15);
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
    fn json_field_names_match_frontend_camel_case() {
        let cfg = Config::default();
        let s = State::initial(&cfg);
        let j = serde_json::to_value(&s).unwrap();
        for k in [
            "on",
            "batteryLevel",
            "batteryThreshold",
            "charging",
            "peerName",
            "peerBattery",
            "peerCharging",
            "history",
            "status",
            "version",
            "linkLatencyMs",
            "cipher",
        ] {
            assert!(j.get(k).is_some(), "missing key {k} in JSON shape");
        }
    }
}
