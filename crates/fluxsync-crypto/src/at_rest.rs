//! At-rest authenticated encryption for FluxVault's persisted clipboard
//! history.
//!
//! The wire path (Noise IK + `snow`) protects data in flight; this module
//! protects the small JSON blob the daemon writes to `~/.fluxsync` so a
//! restart can rehydrate history. It is deliberately separate from the
//! transport crypto: different key (derived via [`Identity::derive_at_rest_key`]),
//! different threat model (a file on the user's own disk, not a network peer).
//!
//! Format: `nonce (24 bytes) || XChaCha20-Poly1305(ciphertext + 16-byte tag)`.
//! A fresh random 192-bit nonce per [`seal`] makes nonce reuse across the
//! repeated whole-file rewrites negligible without tracking a counter.

use crate::error::CryptoError;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

/// XChaCha20-Poly1305 nonce length (192 bits).
const NONCE_LEN: usize = 24;

/// Encrypt `plaintext` under `key`, returning `nonce || ciphertext+tag`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Reverse [`seal`]. Fails on a truncated blob, a wrong key, or any
/// tampering (the Poly1305 tag won't verify).
pub fn open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::Decrypt("at-rest blob too short".into()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{open, seal, NONCE_LEN};

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let msg = b"clipboard history blob";
        let blob = seal(&key, msg).unwrap();
        assert_eq!(open(&key, &blob).unwrap(), msg);
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = [9u8; 32];
        let blob = seal(&key, b"").unwrap();
        assert!(open(&key, &blob).unwrap().is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&[1u8; 32], b"secret").unwrap();
        assert!(open(&[2u8; 32], &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [3u8; 32];
        let mut blob = seal(&key, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&key, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let key = [4u8; 32];
        assert!(open(&key, &[0u8; NONCE_LEN - 1]).is_err());
    }

    #[test]
    fn distinct_nonces_per_seal() {
        let key = [5u8; 32];
        let a = seal(&key, b"same").unwrap();
        let b = seal(&key, b"same").unwrap();
        // Random nonce ⇒ the two blobs (and their nonce prefixes) differ.
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }
}
