//! IPC command + response wire shapes (NDJSON over UNIX socket /
//! Named Pipe). One JSON object per line. See `docs/PROTOCOL.md` §5.

use fluxsync_core::{HistoryItem, LogEntry, State};
use serde::{Deserialize, Serialize};

/// Opening line on every IPC connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Subscribe {
    pub subscribe: Channel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Cmd,
    State,
    Logs,
}

/// Request envelope on the `cmd` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdRequest {
    pub id: u64,
    #[serde(flatten)]
    pub op: CmdOp,
}

/// Every CLI verb. The `op` field selects the variant via serde tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CmdOp {
    Status,
    Peers,
    Push {
        text: String,
    },
    Pull,
    Tail {
        n: usize,
    },
    SetThreshold {
        value: u8,
    },
    SetChargeOverride {
        value: bool,
    },
    Revoke {
        peer_id: String,
    },
    /// Manually unpair from the current active peer and reset state.
    Unpair {},
    DebugCapture {},
    Shutdown {},
    /// Force a reconnection by dropping the current session and starting discovery.
    Reconnect {},
    /// Wake/sleep the FSM. `on=true` fires `Event::ToggleOn`, sending
    /// the daemon from `Idle` into `Discovering`. `on=false` returns
    /// to `Idle`.
    Toggle {
        on: bool,
    },
    /// Print this device's pair info (peer-id, base32 static pubkey,
    /// 6-word fingerprint, LAN address hint, and the QR-encodable
    /// `fluxsync://pair/...` URI).
    PairShow {},
    /// Trust the given remote pubkey + start the initiator handshake.
    /// `addr` is required when mDNS is unavailable (pre-discovery).
    PairAccept {
        pubkey_b32: String,
        name: String,
        addr: Option<String>,
    },
    /// Parse a `fluxsync://pair/...` URI and trust the embedded peer.
    /// Equivalent to a `PairAccept` with values pulled from the URI.
    /// `name` is supplied separately because the URI deliberately
    /// excludes it (one less field to URL-encode + the receiving user
    /// usually wants to nickname the peer at scan time).
    PairFromUri {
        uri: String,
        name: String,
    },
    /// Push the host OS battery percentage + charging flag into the
    /// daemon. Fired by the Android `MainActivity` whenever the system
    /// `ACTION_BATTERY_CHANGED` broadcast arrives. Without this, the
    /// daemon reports a hardcoded 100% and the peer device sees stale
    /// battery info — which the FSM also feeds into the
    /// pause-on-low-battery policy.
    SetSelfBattery {
        level: u8,
        charging: bool,
    },
    SetLaunchAtLogin {
        value: bool,
    },
    SetPreferLan {
        value: bool,
    },
}

/// Response envelope on the `cmd` channel. `id` echoes the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<CmdData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Tagged response payloads. Each variant matches the request that
/// produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CmdData {
    State(Box<State>),
    Peers(Vec<PeerEntry>),
    Tail(Vec<LogEntry>),
    Pull(Option<HistoryItem>),
    PairInfo {
        peer_id_hex: String,
        pubkey_b32: String,
        fingerprint_words: Vec<String>,
        /// Best-guess LAN socket address (`<ip>:<port>`) the daemon is
        /// reachable at. Falls back to `0.0.0.0:<port>` if no route is
        /// available — callers should treat that as "unknown" and ask
        /// the user for the IP.
        addr_hint: String,
        /// Self-contained URI suitable for QR encoding. Format:
        /// `fluxsync://pair/<pubkey_b32>?a=<ip:port>&f=<w1.w2.w3.w4.w5.w6>`
        uri: String,
    },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub peer_id: String, // hex of the 32-byte BLAKE3(static_pub)
    pub name: String,
    pub addr: String,
    pub link_latency_ms: u32,
    pub battery: u8,
    pub charging: bool,
    pub linked: bool,
}

impl CmdResponse {
    #[must_use]
    pub fn ok(id: u64, data: Option<CmdData>) -> Self {
        Self {
            id,
            ok: true,
            data,
            err: None,
        }
    }
    #[must_use]
    pub fn err(id: u64, msg: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            err: Some(msg.into()),
        }
    }
}
