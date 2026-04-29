//! Test-only handshake helper.
//!
//! Gated behind `cfg(any(test, feature = "test-util"))`. Lets integration
//! tests in higher crates (notably `fluxsyncd::tests`) skip the QR /
//! safe-words pairing UX and inject a pre-paired session directly into
//! both daemons. That way a sync-path failure stays distinct from a
//! pairing-flow failure when the test suite goes red.
//!
//! To consume from another workspace crate:
//! ```ignore
//! [dev-dependencies]
//! fluxsync-crypto = { path = "../fluxsync-crypto", features = ["test-util"] }
//! ```

use crate::error::CryptoError;
use crate::handshake::{Initiator, Responder};
use crate::identity::Identity;
use crate::session::Session;

/// Run an in-memory Noise IK handshake between two `Identity`s and return
/// the two ends of the resulting transport session.
pub fn pair_for_test(a: &Identity, b: &Identity) -> Result<(Session, Session), CryptoError> {
    let (initiator, msg1) = Initiator::start(a, &b.public_key())?;
    let (b_session, msg2, a_static_seen) = Responder::step(b, &msg1)?;
    debug_assert_eq!(a_static_seen, a.public_key(), "responder saw wrong static");
    let a_session = initiator.finish(&msg2)?;
    Ok((a_session, b_session))
}
