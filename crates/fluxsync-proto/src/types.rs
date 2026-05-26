use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Clipboard payload kind, matching the frontend's history items.
///
/// Serialized as the lower-case strings `"text"`, `"url"`, `"code"`, `"image"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Text,
    Url,
    Code,
    /// Binary image payload — PNG bytes (phase 1 is PNG-only).
    Image,
}

/// Top-level wire envelope. Every UDP datagram, after decryption, decodes to
/// exactly one `Frame`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Selective negative-ack for an in-progress chunked transfer. The
    /// receiver sends this periodically while reassembly is incomplete so
    /// the sender resends only the missing chunks instead of the whole
    /// item — the difference between converging and not under UDP loss.
    Nak(Nak),
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
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardItem {
    pub lamport: u64,
    pub hash: [u8; 32],
    pub kind: Kind,
    pub payload: Vec<u8>,
    pub sensitive: bool,
    pub wall_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatteryStatus {
    pub lamport: u64,
    pub level: u8,
    pub charging: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub lamport: u64,
    pub rtt_hint: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub item_id: [u8; 32],
    pub idx: u16,
    pub total: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub lamport: u64,
    pub hash: [u8; 32],
}

/// Selective negative-ack: the chunk indices a receiver still needs for
/// the chunked item `item_id`. `want_header` is set when the header
/// datagram (the empty-payload `ClipboardItem`) was lost, so the sender
/// resends that too. `missing` is bounded by the sender of the Nak to
/// stay within one datagram — see `MAX_NAK_MISSING`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nak {
    pub item_id: [u8; 32],
    pub want_header: bool,
    pub missing: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeInit {
    pub peer_id: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub lamport: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeResp {
    pub peer_id: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub lamport: u64,
}

/// Cached info about a peer the daemon has seen recently. Not part of `Msg`;
/// lives here so `fluxsyncd` and `fluxctl` share one shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub name: String,
    pub addr: SocketAddr,
}
