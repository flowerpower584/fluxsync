//! On-disk persistence for the daemon's long-term identity and the
//! trusted-peer registry.
//!
//! Layout (rooted at the keystore directory, default `~/.fluxsync`):
//!
//! ```text
//! identity.bin   — raw 32-byte X25519 secret. Mode 0600 on unix.
//! peers.json     — JSON list of {peer_id_hex, static_pub_hex, name}.
//! ```
//!
//! Both files are written atomically (`*.tmp` + rename) so a crash
//! mid-write cannot leave a half-baked secret on disk.
//!
//! v0.1.2: this is plain-file storage. v0.1.3 will move the secret to
//! the OS keychain (Keychain on macOS, Secret Service on Linux,
//! Credential Manager on Windows). The on-disk peers.json stays —
//! pubkeys aren't secret.

use anyhow::{anyhow, Context, Result};
use fluxsync_crypto::Identity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const IDENTITY_FILE: &str = "identity.bin";
const PEERS_FILE: &str = "peers.json";

/// One entry in `peers.json`. The `peer_id_hex` field is redundant
/// (`BLAKE3(static_pub)`) but stored explicitly so a human can grep
/// the file without recomputing the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPeer {
    pub peer_id_hex: String,
    pub static_pub_hex: String,
    pub name: String,
    pub last_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PeersFile {
    peers: Vec<StoredPeer>,
}

/// Create the keystore directory if it doesn't exist and tighten its
/// permissions to 0700 on unix. No-op on Windows; ACL hardening lands
/// with the keychain migration.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create keystore dir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dir)
            .with_context(|| format!("stat {}", dir.display()))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(dir, perms).with_context(|| format!("chmod 700 {}", dir.display()))?;
    }
    Ok(())
}

/// Load the daemon's identity from `identity.bin`, or generate and
/// persist a fresh one if the file is missing.
///
/// Returns an error (rather than silently overwriting) if the file
/// exists but is the wrong length — that case usually means a corrupted
/// keystore, and clobbering it would invalidate every paired peer.
pub fn load_or_create_identity(dir: &Path) -> Result<Identity> {
    ensure_dir(dir)?;
    let path = dir.join(IDENTITY_FILE);
    if path.exists() {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "identity file {} has length {}, expected 32 (refusing to overwrite — \
                 delete it manually if you really want a fresh identity)",
                path.display(),
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        tracing::info!(path = %path.display(), "loaded identity");
        Ok(Identity::from_secret_bytes(arr))
    } else {
        let id = Identity::generate();
        let secret = id.secret_bytes();
        write_secret_atomic(&path, &secret)?;
        tracing::info!(path = %path.display(), "generated and persisted new identity");
        Ok(id)
    }
}

#[cfg(unix)]
fn write_secret_atomic(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_atomic(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Load the trusted-peer registry. Returns an empty vector if the file
/// is missing or empty (first boot).
pub fn load_peers(dir: &Path) -> Result<Vec<StoredPeer>> {
    let path = dir.join(PEERS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let s = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    let pf: PeersFile =
        serde_json::from_str(&s).with_context(|| format!("parse {}", path.display()))?;
    Ok(pf.peers)
}

/// Persist the trusted-peer registry. Atomic via `*.tmp` + rename so
/// a crash mid-write can't leave the file unparseable.
pub fn save_peers(dir: &Path, peers: &[StoredPeer]) -> Result<()> {
    ensure_dir(dir)?;
    let path = dir.join(PEERS_FILE);
    let pf = PeersFile {
        peers: peers.to_vec(),
    };
    let s = serde_json::to_string_pretty(&pf)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &s).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
