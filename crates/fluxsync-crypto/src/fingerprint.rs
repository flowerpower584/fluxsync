use crate::session::HANDSHAKE_HASH_LEN;
use crate::wordlist::WORDLIST;
use blake3::Hasher;

/// Number of words in a verbal fingerprint (10 bits per word).
pub const FINGERPRINT_WORDS: usize = 6;

/// Derive a 6-word verbal fingerprint from a 32-byte X25519 public key.
///
/// The hash is `BLAKE3(public_key)`. Six 10-bit indices are taken from the
/// low 60 bits of the first 8 bytes, in least-significant-first order, so
/// any two implementations that agree on this function and on `WORDLIST`
/// will always produce the same words for the same key.
#[must_use]
pub fn fingerprint(public_key: &[u8; 32]) -> [&'static str; FINGERPRINT_WORDS] {
    let mut h = Hasher::new();
    h.update(public_key);
    let hash = h.finalize();
    words_from_hash_bytes(hash.as_bytes())
}

/// Derive a 6-word verbal SAS from the Noise handshake hash `h`.
///
/// Unlike [`fingerprint`], which authenticates the peer's *long-term*
/// identity, this binds the *current session*: each handshake produces a
/// fresh `h`, so a MITM that re-keys against a previously seen pubkey gets
/// a different SAS and the verbal compare detects it. FS-052 uses this for
/// the pair-time confirmation gate.
///
/// Callers should pass the full `Session::handshake_hash()`
/// (`HANDSHAKE_HASH_LEN` = 32 bytes for `BLAKE2s`). The typed array
/// signature makes len < 8 unrepresentable at compile time.
#[must_use]
pub fn fingerprint_from_handshake_hash(
    hash: &[u8; HANDSHAKE_HASH_LEN],
) -> [&'static str; FINGERPRINT_WORDS] {
    words_from_hash_bytes(hash)
}

/// Chop the first 8 bytes of `bytes` into six 10-bit slots, in
/// least-significant-first order. Shared core for both `fingerprint`
/// (input is `BLAKE3(pubkey)`) and `fingerprint_from_handshake_hash`
/// (input is the Noise `h`).
fn words_from_hash_bytes(bytes: &[u8]) -> [&'static str; FINGERPRINT_WORDS] {
    let mut head = [0u8; 8];
    head.copy_from_slice(&bytes[..8]);
    let v = u64::from_le_bytes(head);

    let mut words: [&str; FINGERPRINT_WORDS] = [""; FINGERPRINT_WORDS];
    for (i, slot) in words.iter_mut().enumerate() {
        let idx = ((v >> (i * 10)) & 0x3FF) as usize;
        *slot = WORDLIST[idx];
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, fingerprint_from_handshake_hash, FINGERPRINT_WORDS};

    #[test]
    fn fs052_handshake_sas_is_deterministic() {
        let hash = [7u8; 32];
        let a = fingerprint_from_handshake_hash(&hash);
        let b = fingerprint_from_handshake_hash(&hash);
        assert_eq!(a, b, "same hash must yield same SAS on both peers");
        assert_eq!(a.len(), FINGERPRINT_WORDS);
        assert!(a.iter().all(|w| !w.is_empty()));
    }

    #[test]
    fn fs052_handshake_sas_changes_with_hash() {
        let a = fingerprint_from_handshake_hash(&[1u8; 32]);
        let b = fingerprint_from_handshake_hash(&[2u8; 32]);
        assert_ne!(a, b, "different handshake hash must yield different SAS");
    }

    #[test]
    fn fs056_handshake_sas_is_distinct_from_pubkey_fingerprint() {
        let key = [9u8; 32];
        let pk_words = fingerprint(&key);
        let h_words = fingerprint_from_handshake_hash(&key);
        // Pubkey path runs BLAKE3 first; handshake path uses bytes directly.
        // The two derivations therefore differ even when the input bytes
        // are identical — proves they cannot be transposed by accident.
        assert_ne!(pk_words, h_words);
    }

}
