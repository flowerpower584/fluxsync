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
pub use identity::Identity;
pub use session::Session;
pub use wordlist::WORDLIST;

/// Noise pattern in use. Changing this is a wire-protocol break.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
