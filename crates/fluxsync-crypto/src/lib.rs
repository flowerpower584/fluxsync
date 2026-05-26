//! FluxSync identity, Noise IK handshake, and ChaCha20-Poly1305 transport.
//!
//! All wire-crypto sits inside this crate. Higher layers see only opaque
//! [`Session`]s that take and return byte slices. Two design choices worth
//! noting:
//!
//! * [`Identity`] owns the long-term static keypair and lives behind the OS
//!   keychain in production. The crate itself only deals with raw 32-byte
//!   blobs; the keychain integration belongs in `fluxsyncd::keystore`.
//! * The Noise pattern is hard-coded to [`NOISE_PATTERN`]. A pattern change
//!   is a wire-format break and must bump
//!   `fluxsync_proto::PROTOCOL_VERSION`.
//!
//! See `docs/SECURITY.md` for the threat model this crate defends against.

pub mod error;
mod fingerprint;
mod handshake;
mod identity;
mod session;
mod wordlist;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use error::CryptoError;
pub use fingerprint::{fingerprint, fingerprint_from_handshake_hash, FINGERPRINT_WORDS};
pub use handshake::{Initiator, Responder};
pub use identity::{validate_peer_pubkey, Identity};
pub use session::Session;
pub use wordlist::WORDLIST;

/// Noise pattern in use. Changing this is a wire-protocol break.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// PR2: cryptographically-random 6-digit pairing PIN.
///
/// Each PIN is freshly drawn from the OS CSPRNG so an attacker on the
/// LAN cannot predict the next rotation. 6 digits = 1,000,000 values;
/// the PIN ages out after the daemon-side TOFU window (90 s), and
/// post-handshake SAS-words verification still gates trust — the PIN
/// is one-of-two factors, not the only one.
#[must_use]
pub fn gen_pair_pin() -> String {
    use rand_core::{OsRng, RngCore};
    // `next_u32() % 1_000_000` is biased by ~2^32 / 1_000_000 ≈ 4295 —
    // the bias affects at most the top 967 values out of 4,294,967,296
    // draws. For a 90 s human-entered PIN that's invisible. Rejection
    // sampling would be cleaner but is overkill here.
    let n = OsRng.next_u32() % 1_000_000;
    format!("{n:06}")
}
