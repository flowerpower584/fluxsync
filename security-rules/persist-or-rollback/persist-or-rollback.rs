// Test fixtures for the `persist-or-rollback` Semgrep rule.
//
// Names mirror the FluxSync daemon: `save_peers` / `save_current_peers`
// are unqualified inside `driver.rs` and `handshake.rs`; the cross-module
// form `crate::keystore::save_peers` shows up in pair-insert paths.
//
// Positive cases (`ruleid:`) reproduce the VULN-001 anti-pattern.
// Negative cases (`ok:`) demonstrate the correct shape.

#![allow(dead_code, unused_variables, unused_imports, unused_macros)]

use std::path::Path;

struct StoredPeer;
type TrustedSet = std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<[u8; 32], ()>>>;
struct Transport;

async fn save_peers(_dir: &Path, _peers: &[StoredPeer]) -> anyhow::Result<()> { Ok(()) }
async fn save_current_peers(_dir: &Path, _t: &TrustedSet, _tr: &Transport) -> anyhow::Result<()> { Ok(()) }
async fn save_peers_with_retry(_dir: &Path, _t: &TrustedSet, _tr: &Transport) -> anyhow::Result<()> { Ok(()) }
async fn save_peers_with_retry_stored(_dir: &Path, _peers: &[StoredPeer]) -> anyhow::Result<()> { Ok(()) }

pub mod keystore {
    use std::path::Path;
    pub struct StoredPeer;
    pub fn save_peers(_dir: &Path, _peers: &[StoredPeer]) -> anyhow::Result<()> { Ok(()) }
}

async fn ex_warn_swallow(dir: &Path, peers: &[StoredPeer]) {
    // ruleid: persist-or-rollback
    if let Err(e) = save_peers(dir, peers).await {
        tracing::warn!(error = %e, "failed to persist unpair to keystore");
    }
}

async fn ex_error_swallow(dir: &Path, peers: &[StoredPeer]) {
    // ruleid: persist-or-rollback
    if let Err(e) = save_peers(dir, peers).await {
        tracing::error!(error = %e, "failed to persist revocation");
    }
}

async fn ex_current_peers_warn(dir: &Path, trusted: &TrustedSet, transport: &Transport) {
    // ruleid: persist-or-rollback
    if let Err(e) = save_current_peers(dir, trusted, transport).await {
        tracing::warn!(error = %e, "failed to persist rejection to keystore");
    }
}

async fn ex_current_peers_error(dir: &Path, trusted: &TrustedSet, transport: &Transport) {
    // ruleid: persist-or-rollback
    if let Err(e) = save_current_peers(dir, trusted, transport).await {
        tracing::error!(error = %e, "persist failure swallowed");
    }
}

fn ex_keystore_save_peers_warn(dir: &Path, stored: &[keystore::StoredPeer]) {
    // ruleid: persist-or-rollback
    if let Err(e) = crate::keystore::save_peers(dir, stored) {
        tracing::warn!(error = %e, "failed to persist peer to keystore");
    }
}

fn ex_keystore_save_peers_error(dir: &Path, stored: &[keystore::StoredPeer]) {
    // ruleid: persist-or-rollback
    if let Err(e) = crate::keystore::save_peers(dir, stored) {
        tracing::error!(error = %e, "swallow");
    }
}

async fn ok_retry_with_rollback(
    dir: &Path,
    trusted: &TrustedSet,
    transport: &Transport,
) -> Result<(), String> {
    let snapshot = trusted.lock().await.clone();
    trusted.lock().await.clear();
    // ok: persist-or-rollback
    if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
        *trusted.lock().await = snapshot;
        return Err(format!("persist failed: {e}; unpair rolled back"));
    }
    Ok(())
}

async fn ok_retry_stored_with_rollback(
    dir: &Path,
    stored: &[StoredPeer],
) -> Result<(), String> {
    // ok: persist-or-rollback
    if let Err(e) = save_peers_with_retry_stored(dir, stored).await {
        return Err(format!("persist failed: {e}; pair rolled back"));
    }
    Ok(())
}

async fn ok_question_mark_propagation(
    dir: &Path,
    peers: &[StoredPeer],
) -> anyhow::Result<()> {
    // ok: persist-or-rollback
    save_peers(dir, peers).await?;
    Ok(())
}

async fn ok_bail_on_err(dir: &Path, peers: &[StoredPeer]) -> anyhow::Result<()> {
    // ok: persist-or-rollback
    if let Err(e) = save_peers(dir, peers).await {
        anyhow::bail!("TOFU refused: persist failed: {e}");
    }
    Ok(())
}

async fn ok_match_with_rollback(
    dir: &Path,
    trusted: &TrustedSet,
    transport: &Transport,
) {
    let snapshot = trusted.lock().await.clone();
    // ok: persist-or-rollback
    match save_peers_with_retry(dir, trusted, transport).await {
        Ok(()) => {}
        Err(e) => {
            *trusted.lock().await = snapshot;
            tracing::error!(error = %e, "rolled back");
        }
    }
}

mod tracing {
    #[macro_export] macro_rules! _shim_warn  { ($($t:tt)*) => { let _ = format_args!($($t)*); }; }
    #[macro_export] macro_rules! _shim_error { ($($t:tt)*) => { let _ = format_args!($($t)*); }; }
    pub use _shim_warn as warn;
    pub use _shim_error as error;
}
