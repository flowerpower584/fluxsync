// Test cases for rust.fluxsync.untyped-hash-slice
// Each public function that takes `&[u8]`, returns a fixed-size array,
// and uses `debug_assert!(...len() >= ...)` + silent fallback should match.

pub fn words_from_hash_bytes(_b: &[u8]) -> [&'static str; 6] {
    [""; 6]
}

// ruleid: rust.fluxsync.untyped-hash-slice
pub fn fingerprint_from_handshake_hash(hash: &[u8]) -> [&'static str; 6] {
    debug_assert!(
        hash.len() >= 8,
        "handshake hash must be at least 8 bytes, got {}",
        hash.len()
    );
    if hash.len() < 8 {
        return [""; 6];
    }
    words_from_hash_bytes(hash)
}

// ruleid: rust.fluxsync.untyped-hash-slice
pub fn derive_key_words(input: &[u8]) -> [u8; 32] {
    debug_assert!(input.len() >= 16, "key input too short");
    if input.len() < 16 {
        return [0u8; 32];
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&input[..32]);
    out
}

// ok: rust.fluxsync.untyped-hash-slice
// Properly typed — length is enforced at compile time, no runtime check needed.
pub fn fingerprint_typed(hash: &[u8; 32]) -> [&'static str; 6] {
    words_from_hash_bytes(hash)
}

// ok: rust.fluxsync.untyped-hash-slice
// Variable-length input by contract (Noise/AEAD plaintext), no fixed-array return.
pub fn encrypt(_plaintext: &[u8]) -> Result<Vec<u8>, String> {
    Ok(vec![])
}

// ok: rust.fluxsync.untyped-hash-slice
// Returns fixed array but no debug_assert/fallback — caller validates upstream.
pub fn truncate_to_8(input: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..input.len().min(8)].copy_from_slice(&input[..input.len().min(8)]);
    out
}

// Private function with the same anti-pattern — still worth fixing
// (Semgrep cannot reliably distinguish `pub fn` from `fn` in Rust).
// ruleid: rust.fluxsync.untyped-hash-slice
fn private_helper(hash: &[u8]) -> [&'static str; 6] {
    if hash.len() < 8 {
        return [""; 6];
    }
    [""; 6]
}
