//! Regression for C6: Hello.platform length is enforced on the RECEIVE/decode
//! path, not only on send/encode. A hostile peer can craft raw CBOR bytes
//! directly (bypassing our `encode()` validation) with an oversized platform
//! string and feed them to `decode()` — the real wire ingress. `decode()`
//! re-runs `validate()`, so the oversized platform is rejected there too.

use fluxsync_proto::{decode, encode, Frame, Hello, Msg, ProtoError, MAX_HELLO_PLATFORM, PROTOCOL_VERSION};

/// Serialize a Frame straight through ciborium, skipping `encode()`'s
/// `validate()` gate. This is exactly what an attacker's own (non-FluxSync)
/// encoder would put on the wire.
fn raw_cbor(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(frame, &mut out).expect("ciborium serialize");
    out
}

#[test]
fn hostile_oversized_platform_rejected_on_decode() {
    let huge = "x".repeat(10_000);
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "A".into(),
            platform: huge.clone(),
        }),
    };

    // Hostile peer ships these raw bytes (our own encode() would refuse).
    let bytes = raw_cbor(&frame);
    eprintln!("raw hostile datagram = {} bytes", bytes.len());

    let result = decode(&bytes);
    eprintln!("decode() result = {result:?}");

    // The receive path enforces the platform cap: decode() rejects the
    // oversized platform with the actual length reported in the error.
    assert!(
        matches!(result, Err(ProtoError::HelloPlatformTooLong(10_000))),
        "decode() must reject a 10_000-byte platform, got {result:?}"
    );
}

#[test]
fn boundary_16_ok_17_rejected_on_decode() {
    // Exactly at the cap: must decode fine.
    let at_cap = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "A".into(),
            platform: "x".repeat(MAX_HELLO_PLATFORM),
        }),
    };
    let ok = decode(&raw_cbor(&at_cap));
    assert!(ok.is_ok(), "platform == {MAX_HELLO_PLATFORM} must decode, got {ok:?}");

    // One over the cap: must be rejected on decode.
    let over = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "A".into(),
            platform: "x".repeat(MAX_HELLO_PLATFORM + 1),
        }),
    };
    let err = decode(&raw_cbor(&over));
    assert!(
        matches!(err, Err(ProtoError::HelloPlatformTooLong(n)) if n == MAX_HELLO_PLATFORM + 1),
        "platform == {}+1 must be rejected on decode, got {err:?}",
        MAX_HELLO_PLATFORM
    );
}

#[test]
fn no_silent_truncation_send_path() {
    // Confirm encode() also refuses (send path) rather than silently
    // truncating to 16 bytes.
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "A".into(),
            platform: "x".repeat(10_000),
        }),
    };
    let err = encode(&frame);
    assert!(
        matches!(err, Err(ProtoError::HelloPlatformTooLong(10_000))),
        "encode() must reject (not truncate), got {err:?}"
    );
}
