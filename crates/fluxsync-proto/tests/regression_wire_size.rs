//! REGRESSION: payload bytes go on the wire as a CBOR byte string.
//!
//! `ClipboardItem.payload` and `Chunk.data` used serde's default `Vec<u8>`
//! encoding — a CBOR *array* of integers, two bytes per byte ≥ 0x18 — so a
//! full 1 KiB chunk encoded to ~2 KiB, past the 1500 B Wi-Fi MTU that
//! `MAX_CHUNK_DATA` was sized to stay under, and every chunk fragmented.
//!
//! Asserts the frame sizes, and that the change is wire-compatible both
//! ways with builds that still use the array form.

use fluxsync_proto::{
    decode, encode, Chunk, ClipboardItem, Frame, Kind, Msg, MAX_CHUNK_DATA, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};

/// Plaintext budget per datagram: PROTOCOL.md's 1232 B (IPv6 minimum MTU
/// minus IP/UDP headers) less the envelope — 1 type byte, 12-byte nonce,
/// 16-byte AEAD tag.
const DATAGRAM_BUDGET: usize = 1232 - 1 - 12 - 16;

fn chunk_frame(fill: u8) -> Frame {
    Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Chunk(Chunk {
            item_id: [0xAB; 32],
            idx: 7,
            total: 9,
            data: vec![fill; MAX_CHUNK_DATA],
        }),
    }
}

fn text_frame(len: usize) -> Frame {
    Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::ClipboardItem(ClipboardItem {
            lamport: 1,
            hash: [0xCD; 32],
            kind: Kind::Text,
            payload: "x".repeat(len).into_bytes(),
            sensitive: false,
            wall_time_ms: 1,
            origin: [0xEF; 32],
            event_seq: 1,
        }),
    }
}

#[test]
fn full_chunk_fits_one_datagram() {
    for fill in [0x00, 0x7F, 0xFF] {
        let n = encode(&chunk_frame(fill)).expect("encode").len();
        assert!(n <= DATAGRAM_BUDGET, "1 KiB chunk (fill {fill:#x}) encoded to {n} B");
    }
}

#[test]
fn single_frame_text_fits_one_datagram() {
    let n = encode(&text_frame(MAX_CHUNK_DATA)).expect("encode").len();
    assert!(n <= DATAGRAM_BUDGET, "1 KiB text item encoded to {n} B");
}

// ── Compatibility with the legacy array encoding ──────────────────────
// Mirror of the v0.7.0 wire shape: same field order and names, plain
// `Vec<u8>` (serde default → CBOR array of integers).

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct LegacyFrame {
    version: u8,
    msg: LegacyMsg,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum LegacyMsg {
    Chunk(LegacyChunk),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct LegacyChunk {
    item_id: [u8; 32],
    idx: u16,
    total: u16,
    data: Vec<u8>,
}

fn legacy_chunk() -> LegacyFrame {
    LegacyFrame {
        version: PROTOCOL_VERSION,
        msg: LegacyMsg::Chunk(LegacyChunk {
            item_id: [0xAB; 32],
            idx: 7,
            total: 9,
            data: (0..=255u8).cycle().take(MAX_CHUNK_DATA).collect(),
        }),
    }
}

#[test]
fn legacy_array_frames_still_decode() {
    let legacy = legacy_chunk();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&legacy, &mut bytes).expect("encode legacy");
    let frame = decode(&bytes).expect("an array-encoded chunk from an older build must decode");
    let Msg::Chunk(c) = frame.msg else {
        panic!("decoded to the wrong message")
    };
    let LegacyMsg::Chunk(l) = legacy.msg;
    assert_eq!(c.data, l.data);
}

#[test]
fn older_builds_decode_new_byte_string_frames() {
    let LegacyMsg::Chunk(l) = legacy_chunk().msg;
    let new = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Chunk(Chunk {
            item_id: l.item_id,
            idx: l.idx,
            total: l.total,
            data: l.data.clone(),
        }),
    };
    let bytes = encode(&new).expect("encode");
    let old: LegacyFrame = ciborium::de::from_reader(bytes.as_slice())
        .expect("a v0.7.0 decoder must accept the byte-string form");
    assert_eq!(old.msg, LegacyMsg::Chunk(l));
}
