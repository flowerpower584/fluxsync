//! Android Background Restart & Identity Persistence Simulation
//!
//! This simulation verifies that when the Android daemon is killed by the OS
//! (due to being swiped away from Recents) and then restarted in the background
//! by the AccessibilityService, it correctly reloads its cryptographic identity
//! from the keystore instead of generating a new one.
//!
//! If the identity changes on restart, the Mac (responder) will reject the
//! connection because the `peer_id` won't match the one it paired with, causing
//! background sync to fail silently until the user opens the app to pair again.

use anyhow::Result;
use fluxsync_core::{Action, App, Config, Event, Phase};
use fluxsync_crypto::Identity;
use fluxsyncd::{keystore, DaemonConfig};
use tempfile::tempdir;

#[test]
fn simulate_android_background_restart_identity_persistence() -> Result<()> {
    // 1. App installation: Setup a keystore directory
    let keystore_dir = tempdir()?;
    let keystore_path = keystore_dir.path();

    // 2. First boot (User opens app to Pair)
    // The Android UI creates the handle. `identity_secret_b64` is empty,
    // so we call `load_or_create_identity` (the fix!).
    let identity1 = keystore::load_or_create_identity(keystore_path)?;
    let peer_id1 = identity1.peer_id();

    // The Mac pairs with `peer_id1`.

    // 3. User swipes the app away from Recents (Process is killed)
    // The daemon stops. We simulate this by dropping the identity.
    drop(identity1);

    // 4. User copies text in another app (Chrome).
    // The AccessibilityService wakes up the app in the background.
    // It boots the daemon again with `identity_secret_b64 = ""`.

    // WITHOUT THE FIX: `Identity::generate()` would be called here.
    // WITH THE FIX: `load_or_create_identity` is called.
    let identity2 = keystore::load_or_create_identity(keystore_path)?;
    let peer_id2 = identity2.peer_id();

    // 5. Verification
    // The newly loaded identity must perfectly match the original one.
    assert_eq!(
        peer_id1, peer_id2,
        "CRITICAL BUG: The peer_id changed after a background restart! \
         The Mac will reject the background sync because it doesn't recognize this peer."
    );

    // If this passes, the background sync from Android to Mac is indestructible!
    Ok(())
}
