//! Property-based round-trip tests for every wire variant.
//!
//! Random `Frame`s are generated, encoded, decoded, and checked for equality.
//! Boundaries are clamped to the v0.1 caps so the property tests never wander
//! into the validation rejection paths covered by `codec::tests`.

use fluxsync_proto::{
    decode, encode, Ack, BatteryStatus, Chunk, ClipboardItem, Frame, HandshakeInit, HandshakeResp,
    Heartbeat, Hello, Kind, Msg, Nak, MAX_CAP_LEN, MAX_HELLO_CAPS, MAX_HELLO_NAME,
    MAX_HELLO_PLATFORM, MAX_NAK_MISSING, PROTOCOL_VERSION,
};
use proptest::prelude::*;

fn arb_kind() -> impl Strategy<Value = Kind> {
    prop_oneof![Just(Kind::Text), Just(Kind::Url), Just(Kind::Code)]
}

fn arb_array32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn arb_clipboard_item() -> impl Strategy<Value = ClipboardItem> {
    (
        any::<u64>(),
        arb_array32(),
        arb_kind(),
        prop::collection::vec(any::<u8>(), 0..4096),
        any::<bool>(),
        any::<u64>(),
        arb_array32(),
        any::<u64>(),
    )
        .prop_map(
            |(lamport, hash, kind, payload, sensitive, wall_time_ms, origin, event_seq)| {
                ClipboardItem {
                    lamport,
                    hash,
                    kind,
                    payload,
                    sensitive,
                    wall_time_ms,
                    origin,
                    event_seq,
                }
            },
        )
}

fn arb_battery() -> impl Strategy<Value = BatteryStatus> {
    (any::<u64>(), 0u8..=100, any::<bool>()).prop_map(|(lamport, level, charging)| BatteryStatus {
        lamport,
        level,
        charging,
    })
}

fn arb_heartbeat() -> impl Strategy<Value = Heartbeat> {
    (any::<u64>(), prop::option::of(any::<u32>()))
        .prop_map(|(lamport, rtt_hint)| Heartbeat { lamport, rtt_hint })
}

fn arb_chunk() -> impl Strategy<Value = Chunk> {
    (
        1u16..=256,
        prop::collection::vec(any::<u8>(), 0..=1024),
        arb_array32(),
    )
        .prop_flat_map(|(total, data, item_id)| {
            (0u16..total, Just(total), Just(data), Just(item_id))
        })
        .prop_map(|(idx, total, data, item_id)| Chunk {
            item_id,
            idx,
            total,
            data,
        })
}

fn arb_ack() -> impl Strategy<Value = Ack> {
    (any::<u64>(), arb_array32()).prop_map(|(lamport, hash)| Ack { lamport, hash })
}

fn arb_handshake_init() -> impl Strategy<Value = HandshakeInit> {
    (arb_array32(), arb_array32(), arb_array32(), any::<u64>()).prop_map(
        |(peer_id, ephemeral_pub, static_pub, lamport)| HandshakeInit {
            peer_id,
            ephemeral_pub,
            static_pub,
            lamport,
        },
    )
}

fn arb_handshake_resp() -> impl Strategy<Value = HandshakeResp> {
    (arb_array32(), arb_array32(), arb_array32(), any::<u64>()).prop_map(
        |(peer_id, ephemeral_pub, static_pub, lamport)| HandshakeResp {
            peer_id,
            ephemeral_pub,
            static_pub,
            lamport,
        },
    )
}

// ASCII-only so `.len()` (the byte length `validate()` checks) equals the
// char count exactly, which keeps boundary generation exact. Weighted so the
// cap-boundary case is exercised often rather than left to a 1-in-(max_len+1)
// chance of a uniform pick landing on it.
fn arb_bounded_ascii(max_len: usize) -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::collection::vec(prop::char::range('a', 'z'), 0..=max_len)
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        1 => Just("x".repeat(max_len)),
    ]
}

fn arb_cap() -> impl Strategy<Value = String> {
    // Printable-ASCII only (matches the decoder's charset bound), no spaces —
    // real cap tags look like "core-1" / "x-future-test".
    prop::collection::vec(
        prop_oneof![prop::char::range('a', 'z'), prop::char::range('0', '9')],
        1..=MAX_CAP_LEN,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
}

fn arb_caps() -> impl Strategy<Value = Vec<String>> {
    prop_oneof![
        3 => prop::collection::vec(arb_cap(), 0..=MAX_HELLO_CAPS),
        1 => Just(vec!["x".repeat(MAX_CAP_LEN); MAX_HELLO_CAPS]),
    ]
}

fn arb_hello() -> impl Strategy<Value = Hello> {
    (
        arb_bounded_ascii(MAX_HELLO_NAME),
        arb_bounded_ascii(MAX_HELLO_PLATFORM),
        arb_caps(),
    )
        .prop_map(|(name, platform, caps)| Hello {
            name,
            platform,
            caps,
        })
}

fn arb_nak_missing() -> impl Strategy<Value = Vec<u16>> {
    prop_oneof![
        3 => prop::collection::vec(any::<u16>(), 0..=MAX_NAK_MISSING),
        1 => Just(vec![0u16; MAX_NAK_MISSING]),
    ]
}

fn arb_nak() -> impl Strategy<Value = Nak> {
    (arb_array32(), any::<bool>(), arb_nak_missing()).prop_map(|(item_id, want_header, missing)| {
        Nak {
            item_id,
            want_header,
            missing,
        }
    })
}

fn arb_msg() -> impl Strategy<Value = Msg> {
    prop_oneof![
        arb_handshake_init().prop_map(Msg::HandshakeInit),
        arb_handshake_resp().prop_map(Msg::HandshakeResp),
        arb_clipboard_item().prop_map(Msg::ClipboardItem),
        arb_battery().prop_map(Msg::BatteryStatus),
        arb_heartbeat().prop_map(Msg::Heartbeat),
        arb_chunk().prop_map(Msg::Chunk),
        arb_ack().prop_map(Msg::Ack),
        arb_nak().prop_map(Msg::Nak),
        Just(Msg::Bye),
        Just(Msg::Revoke),
        arb_hello().prop_map(Msg::Hello),
    ]
}

fn arb_frame() -> impl Strategy<Value = Frame> {
    arb_msg().prop_map(|msg| Frame {
        version: PROTOCOL_VERSION,
        msg,
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn frame_roundtrips(frame in arb_frame()) {
        let bytes = encode(&frame).expect("encode within v0.1 bounds");
        let back = decode(&bytes).expect("decode within v0.1 bounds");
        prop_assert_eq!(frame, back);
    }
}

// `Msg::Revoke` had no round-trip coverage anywhere before this — not even
// via `arb_msg()` above. A plain #[test] locks it in independent of proptest
// ever generating that arm.
#[test]
fn revoke_round_trip_explicit() {
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Revoke,
    };
    let bytes = encode(&frame).expect("encode Revoke");
    let back = decode(&bytes).expect("decode Revoke");
    assert_eq!(frame, back);
}
