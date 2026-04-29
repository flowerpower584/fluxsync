//! Property-based round-trip tests for every wire variant.
//!
//! Random `Frame`s are generated, encoded, decoded, and checked for equality.
//! Boundaries are clamped to the v0.1 caps so the property tests never wander
//! into the validation rejection paths covered by `codec::tests`.

use fluxsync_proto::{
    decode, encode, Ack, BatteryStatus, Chunk, ClipboardItem, Frame, HandshakeInit, HandshakeResp,
    Heartbeat, Kind, Msg, PROTOCOL_VERSION,
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
    )
        .prop_map(
            |(lamport, hash, kind, payload, sensitive, wall_time_ms)| ClipboardItem {
                lamport,
                hash,
                kind,
                payload,
                sensitive,
                wall_time_ms,
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

fn arb_msg() -> impl Strategy<Value = Msg> {
    prop_oneof![
        arb_handshake_init().prop_map(Msg::HandshakeInit),
        arb_handshake_resp().prop_map(Msg::HandshakeResp),
        arb_clipboard_item().prop_map(Msg::ClipboardItem),
        arb_battery().prop_map(Msg::BatteryStatus),
        arb_heartbeat().prop_map(Msg::Heartbeat),
        arb_chunk().prop_map(Msg::Chunk),
        arb_ack().prop_map(Msg::Ack),
        Just(Msg::Bye),
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
