use zeroize::Zeroize;

use crate::error::CryptoError;

/// Size of the explicit nonce prefix prepended to every transport frame.
const NONCE_PREFIX_LEN: usize = 8;

/// Width of the anti-replay sliding window, in frames.
const REPLAY_WINDOW: u64 = 64;

/// Length of the Noise handshake hash `h` captured at session install,
/// for `Noise_IK_25519_ChaChaPoly_BLAKE2s` (BLAKE2s output = 32 bytes).
pub const HANDSHAKE_HASH_LEN: usize = 32;

/// Established Noise IK transport session. Wraps `snow::TransportState`.
///
/// FluxSync runs Noise transport over **UDP**, which is unordered and
/// lossy. `snow`'s stateful `read_message` assumes a strictly in-order
/// stream: a single dropped or reordered datagram desyncs the receiving
/// nonce counter and every subsequent frame fails to decrypt until the
/// session is torn down and re-handshaked (the ~30s clipboard "flap").
///
/// To survive a lossy transport each [`Session::encrypt`] frame carries
/// its own 8-byte little-endian nonce, and [`Session::decrypt`] pins the
/// receiving cipher to that nonce before authenticating — so frames
/// decrypt independently of arrival order. A sliding-window replay guard
/// rejects duplicated or stale nonces (the in-order counter used to give
/// replay protection for free).
pub struct Session {
    transport: snow::TransportState,
    replay: ReplayWindow,
    handshake_hash: [u8; HANDSHAKE_HASH_LEN],
}

impl Session {
    pub(crate) fn new(
        transport: snow::TransportState,
        handshake_hash: [u8; HANDSHAKE_HASH_LEN],
    ) -> Self {
        Self {
            transport,
            replay: ReplayWindow::default(),
            handshake_hash,
        }
    }

    /// Return the Noise handshake hash `h` captured at session install.
    /// Both peers derive the same value once the handshake completes;
    /// FS-052 uses it as the input to a session-binding SAS so a MITM that
    /// rekeys against a known pubkey produces different words for the
    /// verbal compare.
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8; HANDSHAKE_HASH_LEN] {
        &self.handshake_hash
    }

    /// Encrypt a single payload for a lossy transport.
    ///
    /// Returns the frame `nonce(8 LE) || ciphertext || tag(16)`, which is
    /// 24 bytes longer than the plaintext. The nonce is the value the
    /// sending cipher uses for this frame; the peer reads it back so the
    /// frame can be decrypted out of order.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.transport.sending_nonce();
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        buf.truncate(n);

        let mut out = Vec::with_capacity(NONCE_PREFIX_LEN + n);
        out.extend_from_slice(&nonce.to_le_bytes());
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Decrypt a frame produced by [`Session::encrypt`].
    ///
    /// Reads the explicit nonce prefix, rejects replayed/stale nonces,
    /// pins the receiving cipher to that nonce, then authenticates. A
    /// dropped or reordered datagram no longer poisons the session — only
    /// that one frame is lost.
    pub fn decrypt(&mut self, framed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // F-CT2: every public-boundary failure path returns the same
        // opaque "decryption failed" message so a log/Sentry reader
        // cannot use the error class to probe the replay-window bitmap
        // (oracle: replay-error means nonce N already accepted, AEAD
        // error means nonce N still fresh). Add a verbose-log opt-in
        // later if on-host debugging needs the specific cause — keep
        // the crate `tracing`-free for now.
        const OPAQUE: &str = "decryption failed";

        let Some(nonce_bytes) = framed.first_chunk::<NONCE_PREFIX_LEN>() else {
            return Err(CryptoError::Decrypt(OPAQUE.into()));
        };
        let nonce = u64::from_le_bytes(*nonce_bytes);
        let ciphertext = match framed.get(NONCE_PREFIX_LEN..) {
            Some(c) if c.len() >= 16 => c,
            _ => return Err(CryptoError::Decrypt(OPAQUE.into())),
        };

        if !self.replay.is_fresh(nonce) {
            return Err(CryptoError::Decrypt(OPAQUE.into()));
        }

        self.transport.set_receiving_nonce(nonce);
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|_| CryptoError::Decrypt(OPAQUE.into()))?;
        buf.truncate(n);

        // Only burn a replay slot once the frame is proven authentic — a
        // forged nonce that fails the tag must not advance the window.
        self.replay.accept(nonce);
        Ok(buf)
    }
}

/// Scrubs the session's own sensitive material when a `Session` is
/// dropped — notably on every 24h/1GiB rekey, where the retired `Session`
/// is replaced by plain assignment.
///
/// `handshake_hash` is fully owned by this struct, so it is zeroized here.
///
/// **SAFETY/LIMITATION:** the ChaCha20-Poly1305 transport keys live inside
/// `snow::TransportState` -> `CipherState` -> `Box<dyn Cipher>` (all
/// private to `snow`). Checked `snow` 0.9.6's source directly: neither
/// `TransportState` nor `CipherState` implements `Zeroize` or a scrubbing
/// `Drop`, and there is no accessor to reach the key bytes from outside the
/// crate. This `Drop` therefore cannot scrub the transport keys without
/// forking `snow`; they remain in heap memory, unscrubbed, until reclaimed
/// or overwritten by the allocator. This is a documented residual, not an
/// oversight — revisit if `snow` ever adds a zeroize hook.
impl Drop for Session {
    fn drop(&mut self) {
        self.handshake_hash.zeroize();
    }
}

/// IPsec-style anti-replay sliding window over `u64` frame nonces.
///
/// `bitmap` bit `i` records that `highest - i` was accepted; bit 0 is
/// `highest` itself. Nonces older than [`REPLAY_WINDOW`] behind `highest`
/// are rejected, as are any already marked.
///
/// **Constant-time review (FS-057):** all branches in `is_fresh` /
/// `accept` are driven by the wire nonce, which is sent in clear in the
/// frame prefix and is therefore *not* secret. Tag authentication
/// (`read_message`) happens *after* `is_fresh` clears the frame, so the
/// only secret-dependent compare in the whole decrypt path is the
/// ChaCha20-Poly1305 tag check inside `snow` (which uses
/// `chacha20poly1305`'s `subtle::ConstantTimeEq`). No timing channel on
/// keys or plaintext leaks from this module.
#[derive(Default)]
struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    started: bool,
}

impl ReplayWindow {
    /// True if `nonce` has not been seen and is not too old to track.
    /// Pure check — call [`ReplayWindow::accept`] only after the frame
    /// authenticates.
    fn is_fresh(&self, nonce: u64) -> bool {
        if !self.started || nonce > self.highest {
            return true;
        }
        let diff = self.highest - nonce;
        if diff >= REPLAY_WINDOW {
            return false;
        }
        self.bitmap & (1u64 << diff) == 0
    }

    /// Record `nonce` as accepted, advancing the window if it is newer
    /// than anything seen so far.
    fn accept(&mut self, nonce: u64) {
        if !self.started {
            self.started = true;
            self.highest = nonce;
            self.bitmap = 1;
            return;
        }
        if nonce > self.highest {
            let shift = nonce - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = nonce;
        } else {
            let diff = self.highest - nonce;
            if diff < REPLAY_WINDOW {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayWindow, REPLAY_WINDOW};

    /// Safe Rust can't assert the heap bytes are actually scrubbed, but
    /// this pins down that `Drop` runs cleanly on a real, handshaked
    /// `Session` (not just a bare struct literal) and that the session is
    /// fully usable — encrypt/decrypt round-trip and `handshake_hash()` —
    /// right up until it goes out of scope. A regression that made `Drop`
    /// panic (e.g. a bad field access) or that broke the pre-drop API
    /// would fail this test.
    #[test]
    fn session_encrypts_and_drops_cleanly() {
        use crate::identity::Identity;
        use crate::test_util::pair_for_test;

        let a = Identity::generate();
        let b = Identity::generate();
        let (mut a_session, mut b_session) = pair_for_test(&a, &b).expect("handshake");

        assert_eq!(a_session.handshake_hash(), b_session.handshake_hash());

        let frame = a_session.encrypt(b"defense-in-depth").expect("encrypt");
        let plain = b_session.decrypt(&frame).expect("decrypt");
        assert_eq!(plain, b"defense-in-depth");

        // Simulate a rekey: the old sessions drop here via scope exit,
        // running Session's Drop (zeroizes handshake_hash) without panicking.
    }

    #[test]
    fn replay_window_accepts_fresh_in_order() {
        let mut w = ReplayWindow::default();
        for n in 0..200 {
            assert!(w.is_fresh(n), "nonce {n} should be fresh");
            w.accept(n);
        }
    }

    #[test]
    fn replay_window_rejects_exact_replay() {
        let mut w = ReplayWindow::default();
        w.accept(10);
        assert!(!w.is_fresh(10), "an accepted nonce must not be fresh again");
    }

    #[test]
    fn replay_window_accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::default();
        w.accept(100);
        // A frame that arrives late but still inside the window.
        assert!(w.is_fresh(98));
        w.accept(98);
        assert!(!w.is_fresh(98), "the late frame is now a replay");
        // The gap at 99 is still open.
        assert!(w.is_fresh(99));
    }

    #[test]
    fn replay_window_rejects_stale_below_window() {
        let mut w = ReplayWindow::default();
        w.accept(0);
        w.accept(REPLAY_WINDOW + 10);
        // 0 is now further than REPLAY_WINDOW behind highest.
        assert!(!w.is_fresh(0));
    }

    #[test]
    fn replay_window_large_jump_does_not_panic() {
        let mut w = ReplayWindow::default();
        w.accept(1);
        // Jump far past the window — must not shift-overflow.
        w.accept(1_000_000);
        assert!(w.is_fresh(999_999));
        assert!(!w.is_fresh(1_000_000));
    }
}
