use fluxsync_proto::Kind;
use serde::{Deserialize, Serialize};

/// Things the daemon tells the FSM about.
///
/// All non-pure inputs come in here. The FSM's response is a list of
/// [`Action`]s the daemon then executes (send a frame, write the
/// clipboard, emit a log line, push a new state to subscribers, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ToggleOn,
    ToggleOff,
    PeerSeen {
        peer_id: [u8; 32],
        name: String,
    },
    PeerLost,
    HandshakeOk,
    HandshakeTimeout,
    SetTrustedPeer { name: String },
    UntrustedPeerSeen {
        name: String,
    },
    GhostTimeout,
    ManualUnpair,
    NetworkChanged,
    BatteryChangedSelf {
        level: u8,
        charging: bool,
    },
    BatteryChangedPeer {
        level: u8,
        charging: bool,
    },
    LocalClipboardChange {
        hash: [u8; 32],
        kind: Kind,
        preview: String,
        sensitive: bool,
        lamport: u64,
    },
    FrameReceivedClipboard {
        hash: [u8; 32],
        kind: Kind,
        preview: String,
        sensitive: bool,
        lamport: u64,
    },
    Reconnect,
}

/// Side-effect commands the daemon must execute. The FSM never performs
/// I/O; it only describes what should happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    StartDiscovery,
    StopDiscovery,
    SendHandshake {
        peer_id: [u8; 32],
    },
    DropPeer,
    OpenSession,
    CloseSession,
    SendItem {
        hash: [u8; 32],
        kind: Kind,
        preview: String,
        sensitive: bool,
    },
    AckItem {
        hash: [u8; 32],
    },
    WriteClipboard {
        preview: String,
    },
    EmitState,
    EmitLog(LogEntry),
    BurstReplay,
    SendBattery {
        level: u8,
        charging: bool,
    },
}

/// A friendly log entry. Routed both to `tracing` (structured) and to the
/// IPC `logs` channel (plain English).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub msg: String,
}

/// Five-level log severity. Names match the frontend's filter buttons
/// exactly (`OK`, `INFO`, `SYNC`, `WARN`, `ERR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Ok,
    Info,
    Sync,
    Warn,
    Err,
}

impl LogEntry {
    #[must_use]
    pub fn ok(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Ok,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn info(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Info,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn sync(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Sync,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn warn(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Warn,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Err,
            msg: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_serializes_uppercase() {
        let v = serde_json::to_value(LogLevel::Sync).unwrap();
        assert_eq!(v, serde_json::json!("SYNC"));
        let v = serde_json::to_value(LogLevel::Err).unwrap();
        assert_eq!(v, serde_json::json!("ERR"));
    }

    #[test]
    fn log_entry_helpers() {
        assert_eq!(LogEntry::ok("hi").level, LogLevel::Ok);
        assert_eq!(LogEntry::info("hi").level, LogLevel::Info);
        assert_eq!(LogEntry::sync("hi").level, LogLevel::Sync);
        assert_eq!(LogEntry::warn("hi").level, LogLevel::Warn);
        assert_eq!(LogEntry::err("hi").level, LogLevel::Err);
    }
}
