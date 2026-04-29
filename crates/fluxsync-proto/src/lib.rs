//! FluxSync wire types + CBOR codec.
//!
//! Every byte that crosses the LAN is a [`Frame`] encoded with `ciborium` and
//! sealed inside a Noise IK ChaCha20-Poly1305 ciphertext. This crate is
//! deliberately small and depends on nothing else in the workspace so it can
//! be exercised in property tests without dragging in a runtime.
//!
//! See `docs/PROTOCOL.md` for the full wire-format specification.

mod codec;
mod error;
mod types;

pub use codec::{decode, encode};
pub use error::ProtoError;
pub use types::{
    Ack, BatteryStatus, Chunk, ClipboardItem, Frame, HandshakeInit, HandshakeResp, Heartbeat, Kind,
    Msg, PeerInfo,
};

/// Wire-format version. Bumped on any breaking change to the CBOR shapes.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Largest reassembled clipboard payload v0.1 will accept (256 KiB).
pub const MAX_PAYLOAD: usize = 256 * 1024;

/// Largest data section inside a single [`Chunk`] frame (1 KiB).
pub const MAX_CHUNK_DATA: usize = 1024;

/// Hard cap on chunk-count per item — bounds reassembly buffer and refuses
/// trivial DoS allocations from a malicious peer.
pub const MAX_CHUNKS: u16 = 256;
