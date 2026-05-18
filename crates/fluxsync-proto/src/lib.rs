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
    Ack, BatteryStatus, Chunk, ClipboardItem, Frame, HandshakeInit, HandshakeResp, Heartbeat,
    Hello, Kind, Msg, PeerInfo,
};

/// Wire-format version. Bumped on any breaking change to the CBOR shapes.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Largest reassembled clipboard payload we accept (16 MiB) — sized for
/// Retina / S21-Ultra PNG screenshots, which run 8-12 MiB.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Largest data section inside a single [`Chunk`] frame (1 KiB). Held at 1 KiB
/// so the final datagram (CBOR + Noise overhead ≈ 1.1-1.2 KiB) stays under the
/// 1500 B Wi-Fi MTU — one lost IP fragment would kill the whole UDP datagram.
pub const MAX_CHUNK_DATA: usize = 1024;

/// Hard cap on chunk-count per item — bounds reassembly buffer and refuses
/// trivial DoS allocations from a malicious peer. 16384 × 1 KiB = 16 MiB,
/// matching [`MAX_PAYLOAD`] (u16 ceiling ≈ 64 MiB).
pub const MAX_CHUNKS: u16 = 16384;
