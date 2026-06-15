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
    /// Peer's OS family, carried by `Msg::Hello` (after the handshake). Kept
    /// separate from `PeerSeen` so the discovery/handshake paths — which don't
    /// know the platform — stay untouched.
    PeerPlatform {
        platform: String,
    },
    PeerLost,
    HandshakeOk,
    HandshakeTimeout,
    SetTrustedPeer {
        name: String,
    },
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
        /// Raw clipboard bytes — UTF-8 for text/url/code, PNG for images.
        payload: Vec<u8>,
        /// Human-readable label for the history UI (truncated text, or an
        /// "Image 1280×720, 340 KB" descriptor). Never the wire payload.
        preview: String,
        sensitive: bool,
        lamport: u64,
    },
    FrameReceivedClipboard {
        hash: [u8; 32],
        kind: Kind,
        /// Raw clipboard bytes — UTF-8 for text/url/code, PNG for images.
        payload: Vec<u8>,
        /// Human-readable label for the history UI.
        preview: String,
        sensitive: bool,
        lamport: u64,
    },
    Reconnect,
    /// FluxMesh Phase 3: a non-primary mesh peer joined, left, or updated its
    /// Hello/Battery. Carries no payload — it only asks the FSM to re-emit
    /// State so the daemon can rebuild the `peers` list from the live session
    /// set. Never mutates the single-peer State fields (those stay the
    /// primary's projection).
    MeshPeersChanged,
    /// FluxMesh robustness: the primary peer's link died while a secondary
    /// mesh session is still live. The daemon has already promoted that
    /// secondary into the primary transport slot; this rebinds the
    /// single-peer State to the promoted peer so the link stays connected
    /// instead of dropping to Discovering. Unlike `PeerSeen`, it is accepted
    /// while Linked — the promoted peer is already authenticated and trusted,
    /// so it deliberately bypasses the anti-hijack `is_peer_mismatch` guard.
    PrimaryFailover {
        peer_id: [u8; 32],
        name: String,
        platform: String,
    },
    /// FluxVault: pin/unpin a history item (by its hex content hash) as a
    /// favorite. Favorites are exempt from the vault's TTL and disk cap, so a
    /// pinned item is never aged or capped out. Mutates only the matching
    /// `HistoryItem.favorite` flag(s) and re-emits State.
    SetFavorite {
        hash: String,
        favorite: bool,
    },
    /// Clipboard firewall (chantier A): the user approved (`allow=true`) or
    /// rejected (`allow=false`) an item the `Ask` rule had parked. Keyed by the
    /// pending item's hex content `hash`. On approval the FSM re-emits the held
    /// `SendItem`/`WriteClipboard`; either way the entry leaves `State.pending`.
    ResolvePending {
        hash: String,
        allow: bool,
    },
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
        /// Raw bytes to put on the wire as the `ClipboardItem` payload.
        payload: Vec<u8>,
        sensitive: bool,
    },
    AckItem {
        hash: [u8; 32],
    },
    WriteClipboard {
        kind: Kind,
        /// Raw bytes to write to the OS clipboard — decoded per `kind`.
        payload: Vec<u8>,
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
