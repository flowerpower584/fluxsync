//! RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD known-answer tests.
//!
//! Verifies that the AEAD primitive `snow` uses transitively (via the
//! `chacha20poly1305` crate, which `snow`'s default resolver pulls in)
//! reproduces the ciphertext + tag from the spec verbatim.
//!
//! Rationale: if `snow` ever swaps its AEAD backend or a dependency
//! introduces a regression, we want the build to fail HERE, not in a
//! deployed daemon.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hex_literal::hex;

// Inputs from RFC 8439 §2.8.2 ─────────────────────────────────────────────
const KEY: [u8; 32] = hex!(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
);
const NONCE: [u8; 12] = hex!("070000004041424344454647");
const AAD: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

// 114-byte ciphertext concatenated with the 16-byte Poly1305 tag.
const CIPHERTEXT_AND_TAG: [u8; 130] = hex!(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "61161ae10b594f09e26a7e902ecbd060"
    "0691"
);

#[test]
fn rfc8439_2_8_2_aead_encrypt() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
    let actual = cipher
        .encrypt(
            Nonce::from_slice(&NONCE),
            Payload {
                msg: PLAINTEXT,
                aad: &AAD,
            },
        )
        .expect("encrypt");
    assert_eq!(actual.len(), CIPHERTEXT_AND_TAG.len());
    assert_eq!(actual.as_slice(), &CIPHERTEXT_AND_TAG);
}

#[test]
fn rfc8439_2_8_2_aead_decrypt() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
    let actual = cipher
        .decrypt(
            Nonce::from_slice(&NONCE),
            Payload {
                msg: &CIPHERTEXT_AND_TAG,
                aad: &AAD,
            },
        )
        .expect("decrypt");
    assert_eq!(actual.as_slice(), PLAINTEXT);
}

#[test]
fn rfc8439_2_8_2_aead_decrypt_rejects_tampered_tag() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
    let mut tampered = CIPHERTEXT_AND_TAG;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01; // flip one bit in the Poly1305 tag
    let res = cipher.decrypt(
        Nonce::from_slice(&NONCE),
        Payload {
            msg: &tampered,
            aad: &AAD,
        },
    );
    assert!(res.is_err(), "tampered tag must fail authentication");
}
