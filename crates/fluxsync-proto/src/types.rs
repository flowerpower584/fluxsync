use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Clipboard payload kind, matching the frontend's history items.
///
/// Serialized as the lower-case strings `"text"`, `"url"`, `"code"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Text,
    Url,
    Code,
}

/// Top-level wire envelope. Every UDP datagram, after decryption, decodes to
/// exactly one `Frame`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub version: u8,
    pub msg: Msg,
}

/// Message variants. Externally tagged: `{"<VariantName>": <payload>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    HandshakeInit(HandshakeInit),
    HandshakeResp(HandshakeResp),
    ClipboardItem(ClipboardItem),
    BatteryStatus(BatteryStatus),
    Heartbeat(Heartbeat),
    Chunk(Chunk),
    Ack(Ack),
    Bye,
    /// Sent once per side immediately after the Linked transition.
    /// Carries the sender's `peer_name_self` so the receiver can drop
    /// the TOFU "pending" placeholder and show the real device name.
    Hello(Hello),
}

/// Post-handshake greeting. The Noise IK handshake itself doesn't carry
/// friendly names — only static pubkeys — so the responder ends up with
/// a placeholder until this frame arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardItem {
    pub lamport: u64,
    pub hash: [u8; 32],
    pub kind: Kind,
    pub payload: Vec<u8>,
    pub sensitive: bool,
    pub wall_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatteryStatus {
    pub lamport: u64,
    pub level: u8,
    pub charging: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub lamport: u64,
    pub rtt_hint: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub item_id: [u8; 32],
    pub idx: u16,
    pub total: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub lamport: u64,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub peer_id: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub lamport: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResp {
    pub peer_id: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub lamport: u64,
}

/// Cached info about a peer the daemon has seen recently. Not part of `Msg`;
/// lives here so `fluxsyncd` and `fluxctl` share one shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub name: String,
    pub addr: SocketAddr,
}
