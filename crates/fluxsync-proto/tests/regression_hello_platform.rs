//! Regression for C6: Hello.platform length is enforced on the RECEIVE/decode
//! path, not only on send/encode. A hostile peer can craft raw CBOR bytes
//! directly (bypassing our `encode()` validation) with an oversized platform
//! string and feed them to `decode()` — the real wire ingress. `decode()`
//! re-runs `validate()`, so the oversized platform is rejected there too.

use fluxsync_proto::{
    decode, encode, Frame, Hello, Msg, ProtoError, MAX_HELLO_PLATFORM, PROTOCOL_VERSION,
};

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
            caps: vec![],
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
            caps: vec![],
        }),
    };
    let ok = decode(&raw_cbor(&at_cap));
    assert!(
        ok.is_ok(),
        "platform == {MAX_HELLO_PLATFORM} must decode, got {ok:?}"
    );

    // One over the cap: must be rejected on decode.
    let over = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "A".into(),
            platform: "x".repeat(MAX_HELLO_PLATFORM + 1),
            caps: vec![],
        }),
    };
    let err = decode(&raw_cbor(&over));
    assert!(
        matches!(err, Err(ProtoError::HelloPlatformTooLong(n)) if n == MAX_HELLO_PLATFORM + 1),
        "platform == {MAX_HELLO_PLATFORM}+1 must be rejected on decode, got {err:?}"
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
            caps: vec![],
        }),
    };
    let err = encode(&frame);
    assert!(
        matches!(err, Err(ProtoError::HelloPlatformTooLong(10_000))),
        "encode() must reject (not truncate), got {err:?}"
    );
}

// Terminal-injection regression: `Hello.name` / `Hello.platform` are peer-
// controlled strings that flow straight into the tray UI and into fluxctl's
// raw `println!` terminal output. `Hello.caps` already got an ASCII-
// printable gate; `name`/`platform` never did, so a paired (or mDNS-name-
// spoofing) peer could smuggle ANSI/OSC escape sequences or CR/NUL bytes
// into a victim's terminal on the next `fluxctl status`. These tests mirror
// the raw-CBOR technique above so a hostile peer that crafts bytes bypassing
// our own `encode()` gate is still rejected by `decode()`, the real wire
// ingress.

fn raw_hello(name: &str, platform: &str) -> Vec<u8> {
    raw_cbor(&Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: name.to_string(),
            platform: platform.to_string(),
            caps: vec![],
        }),
    })
}

#[test]
fn hostile_control_chars_in_name_rejected_on_decode() {
    for hostile in ["evil\rname", "evil\x1bname", "evil\0name"] {
        let bytes = raw_hello(hostile, "linux");
        let result = decode(&bytes);
        assert!(
            matches!(result, Err(ProtoError::HelloNameNotPrintable)),
            "decode() must reject a control char in name ({hostile:?}), got {result:?}"
        );
    }
}

#[test]
fn hostile_control_chars_in_platform_rejected_on_decode() {
    for hostile in ["lin\rux", "lin\x1bux", "lin\0ux"] {
        let bytes = raw_hello("A", hostile);
        let result = decode(&bytes);
        assert!(
            matches!(result, Err(ProtoError::HelloPlatformNotAsciiPrintable)),
            "decode() must reject a control char in platform ({hostile:?}), got {result:?}"
        );
    }
}

#[test]
fn normal_ascii_name_and_platform_decode_fine() {
    let bytes = raw_hello("Dethie's MacBook", "macos");
    assert!(decode(&bytes).is_ok());
}

#[test]
fn legit_non_ascii_utf8_name_decodes_fine() {
    // Device names are user-chosen and may be non-ASCII (accented / CJK
    // characters); only control characters are disallowed, not the full
    // non-ASCII range that `Hello.caps` restricts.
    let bytes = raw_hello("松本さんのMac", "macos");
    assert!(
        decode(&bytes).is_ok(),
        "a non-ASCII UTF-8 device name with no control chars must decode"
    );
}

#[test]
fn non_ascii_platform_is_rejected() {
    // Unlike `name`, `platform` is drawn from a closed ASCII set
    // (macos/windows/linux/android/ios/unknown), so it stays ASCII-printable
    // only, same gate as `Hello.caps`.
    let bytes = raw_hello("A", "état");
    assert!(matches!(
        decode(&bytes),
        Err(ProtoError::HelloPlatformNotAsciiPrintable)
    ));
}

#[test]
fn no_silent_truncation_send_path_control_chars() {
    // encode() (send path) must also refuse control chars, not just decode().
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "evil\rname".into(),
            platform: "linux".into(),
            caps: vec![],
        }),
    };
    let err = encode(&frame);
    assert!(matches!(err, Err(ProtoError::HelloNameNotPrintable)));
}
