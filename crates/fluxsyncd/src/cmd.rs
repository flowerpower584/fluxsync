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
    Push { text: String },
    Pull,
    Tail { n: usize },
    SetThreshold { value: u8 },
    SetChargeOverride { value: bool },
    Revoke { peer_id: String },
    DebugCapture,
    Shutdown,
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
