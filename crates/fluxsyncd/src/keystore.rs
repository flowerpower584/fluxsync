//! On-disk persistence for the daemon's long-term identity and the
//! trusted-peer registry.
//!
//! Layout (rooted at the keystore directory, default `~/.fluxsync`):
//!
//! ```text
//! identity.bin   — (legacy) raw 32-byte X25519 secret. Mode 0600 on unix.
//!                 Auto-migrated to the OS keychain on first boot of
//!                 v0.6.0+ and best-effort wiped from disk.
//! peers.json     — JSON list of {peer_id_hex, static_pub_hex, name}.
//! ```
//!
//! Identity storage (FS-053):
//!
//! * non-Android desktops: stored in the OS-native credential store via
//!   the `keyring` crate (Keychain on macOS, Credential Manager on
//!   Windows, Secret Service / kwallet on Linux).
//! * Android: still on-disk under the app's private data dir (which is
//!   already isolated by the OS). The `keyring` crate has no Android
//!   backend; a future migration to Android Keystore via JNI is tracked
//!   separately.
//!
//! `peers.json` is written atomically (`*.tmp` + fsync + rename) so a
//! crash mid-write cannot corrupt the registry. The fallback identity
//! file on Android uses the same atomic write.

use anyhow::{anyhow, Context, Result};
use fluxsync_crypto::Identity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const IDENTITY_FILE: &str = "identity.bin";
const PEERS_FILE: &str = "peers.json";

/// Service name used for the keychain entry. Keep stable: changing it
/// after the first release would orphan every existing user's identity.
#[cfg(not(target_os = "android"))]
const KEYCHAIN_SERVICE: &str = "fluxsyncd";

// C3 (open) — the `keyring` crate stores secrets as a generic password
// with the default ACL: any process running as the current user can
// read them without prompting. That preserves the disk-level hardening
// from Phase 1 (no plaintext file) but does not stop a same-UID
// malware from harvesting the Noise IK static key via
// `security find-generic-password -s fluxsyncd -w` (macOS) or the
// equivalent on Windows/Linux.
//
// Fix path (deferred to a follow-up because it requires bypassing
// `keyring` and calling `security-framework` directly on macOS plus
// equivalent platform code on Windows/Linux):
//   1. macOS: `SecAccessControlCreateWithFlags` + `kSecAttrAccess`
//      whitelisting the signed daemon binary, optionally chained with
//      biometry (`kSecAccessControlBiometryAny`) for sensitive ops.
//   2. Windows: bind DPAPI with `CRYPTPROTECT_AUDIT` and an entropy
//      derived from `KnownFolderId::LocalAppData` so non-daemon
//      processes cannot unprotect.
//   3. Linux: Secret Service items with the `org.freedesktop.Secret.Item`
//      attribute set to a peer-locked schema.
//
// Tracked in `docs/THREAT-MODEL.md` (FS-053 follow-up).

/// Account name on the keychain entry. We only ever store one secret
/// per service today (the long-term Noise identity), so a constant
/// works. If we add a second secret later (e.g. group key), pick a new
/// account name rather than overloading this one.
#[cfg(not(target_os = "android"))]
const KEYCHAIN_ACCOUNT: &str = "identity";

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

/// Load the daemon's identity from the OS keychain (or the legacy file
/// on Android / fallback) and generate + persist a fresh one if none is
/// found.
///
/// Boot-time flow on desktops (FS-053):
///
/// 1. Try the keychain entry (`KEYCHAIN_SERVICE` / `KEYCHAIN_ACCOUNT`).
/// 2. If empty, look for the legacy `identity.bin`:
///    * if present → import it into the keychain, then best-effort
///      wipe the file (overwrite with zeros + remove). This is the
///      one-shot migration path; subsequent boots take branch 1.
///    * if absent → generate a fresh keypair and store it in the
///      keychain.
/// 3. If the keychain backend is unavailable (no `dbus` on Linux, no
///    login keychain unlocked, etc.) we surface the error rather than
///    silently fall back to a file: the user must fix the backend or
///    explicitly re-run with `--no-keychain` (future flag) once we add
///    it.
///
/// On Android the keychain crate has no backend, so we keep the
/// existing file-based path. The app's private data directory is
/// already isolated by the OS sandbox.
///
/// Returns an error (rather than silently overwriting) if the legacy
/// file exists but is the wrong length — corrupted store, clobbering
/// would invalidate every paired peer.
// `return` statements below are required: each platform branch lives in
// its own `#[cfg(...)]` block, and clippy::pedantic does not see through
// conditional compilation when judging needless-return.
#[allow(clippy::needless_return)]
pub fn load_or_create_identity(dir: &Path) -> Result<Identity> {
    ensure_dir(dir)?;

    // Escape hatch: when the OS keychain is unreachable (headless boot,
    // a detached/differently-signed binary that triggers a GUI auth
    // prompt macOS can't satisfy, locked login keychain, no dbus) the
    // user can opt back into the file-based identity with
    // `FLUXSYNC_NO_KEYCHAIN=1`. This restores the legacy `identity.bin`
    // path on the same `#[cfg(unix)]` write helper Android uses. It is
    // strictly opt-in so the default stays "no plaintext secret on disk".
    #[cfg(all(unix, not(target_os = "android")))]
    if std::env::var("FLUXSYNC_NO_KEYCHAIN").as_deref() == Ok("1") {
        let path = dir.join(IDENTITY_FILE);
        if path.exists() {
            let id = read_legacy_identity(&path)?;
            tracing::warn!(
                path = %path.display(),
                "FLUXSYNC_NO_KEYCHAIN set: loaded identity from plaintext file (keychain bypassed)"
            );
            return Ok(id);
        }
        let id = Identity::generate();
        let secret = id.secret_bytes();
        write_secret_atomic(&path, &secret)?;
        tracing::warn!(
            path = %path.display(),
            "FLUXSYNC_NO_KEYCHAIN set: generated identity in plaintext file (keychain bypassed)"
        );
        return Ok(id);
    }

    #[cfg(not(target_os = "android"))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
            .context("open OS keychain entry for fluxsyncd identity")?;

        match entry.get_password() {
            Ok(raw) => {
                // ZA-0001: `keyring::Entry::get_password` returns a plain
                // `String` whose heap buffer is freed without zeroization.
                // Wrap immediately so the hex-encoded secret is scrubbed
                // on drop before the allocator reuses the slab.
                let hex = zeroize::Zeroizing::new(raw);
                let id = decode_identity_hex(&hex)?;
                tracing::info!(
                    service = KEYCHAIN_SERVICE,
                    account = KEYCHAIN_ACCOUNT,
                    "loaded identity from OS keychain"
                );
                let legacy = dir.join(IDENTITY_FILE);
                if legacy.exists() {
                    // The keychain wins; a stray legacy file is just
                    // an old copy from before the migration landed.
                    // Wipe it so a backup grab can't lift the secret.
                    secure_wipe_identity_file(&legacy);
                }
                return Ok(id);
            }
            Err(keyring::Error::NoEntry) => {
                // First boot on this machine, or a fresh user.
                let legacy = dir.join(IDENTITY_FILE);
                let id = if legacy.exists() {
                    let imported = read_legacy_identity(&legacy)?;
                    store_identity_in_keychain(&entry, &imported)?;
                    secure_wipe_identity_file(&legacy);
                    tracing::info!(
                        path = %legacy.display(),
                        "migrated identity from legacy identity.bin to OS keychain"
                    );
                    imported
                } else {
                    let fresh = Identity::generate();
                    store_identity_in_keychain(&entry, &fresh)?;
                    tracing::info!(
                        service = KEYCHAIN_SERVICE,
                        account = KEYCHAIN_ACCOUNT,
                        "generated and persisted new identity in OS keychain"
                    );
                    fresh
                };
                return Ok(id);
            }
            Err(e) => {
                return Err(anyhow!(
                    "OS keychain unavailable ({e}); refusing to fall back to plaintext \
                     identity.bin. Fix the backend (unlock Keychain / start dbus / \
                     enable Credential Manager), or set FLUXSYNC_NO_KEYCHAIN=1 to use a \
                     file-based identity, and retry."
                ));
            }
        }
    }

    #[cfg(target_os = "android")]
    {
        let path = dir.join(IDENTITY_FILE);
        if path.exists() {
            let id = read_legacy_identity(&path)?;
            tracing::info!(path = %path.display(), "loaded identity from app-private file");
            return Ok(id);
        }
        let id = Identity::generate();
        let secret = id.secret_bytes();
        write_secret_atomic(&path, &secret)?;
        tracing::info!(path = %path.display(), "generated and persisted new identity");
        Ok(id)
    }
}

/// Read + validate a legacy `identity.bin`. Buffer is wrapped in
/// `Zeroizing` so the secret never lingers in freed memory.
fn read_legacy_identity(path: &Path) -> Result<Identity> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "identity file {} has length {}, expected 32 (refusing to overwrite — \
             delete it manually if you really want a fresh identity)",
            path.display(),
            bytes.len()
        ));
    }
    let mut arr = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&bytes);
    // The Vec backing `bytes` also held a copy of the secret — wrap so
    // Drop scrubs it before the buffer is freed.
    let _scrub = zeroize::Zeroizing::new(bytes);
    Identity::from_secret_bytes(arr).context("decode persisted identity bytes")
}

#[cfg(not(target_os = "android"))]
fn store_identity_in_keychain(entry: &keyring::Entry, id: &Identity) -> Result<()> {
    let secret = id.secret_bytes();
    let hex_secret = zeroize::Zeroizing::new(hex::encode(secret.as_ref()));
    entry
        .set_password(&hex_secret)
        .context("write fluxsyncd identity to OS keychain")
}

#[cfg(not(target_os = "android"))]
fn decode_identity_hex(hex_str: &str) -> Result<Identity> {
    let decoded = hex::decode(hex_str.trim()).context("decode keychain identity hex")?;
    if decoded.len() != 32 {
        return Err(anyhow!(
            "keychain identity has length {}, expected 32 (corrupted entry; \
             delete it from the OS keychain to regenerate)",
            decoded.len()
        ));
    }
    let mut arr = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&decoded);
    // Wrap the Vec storage so its copy of the secret is scrubbed too.
    let _scrub = zeroize::Zeroizing::new(decoded);
    Identity::from_secret_bytes(arr).context("decode persisted identity bytes")
}

/// Best-effort secure wipe of a legacy on-disk identity.
///
/// We overwrite the file in place with zeros, fsync, then unlink. On
/// COW filesystems (APFS, Btrfs, ZFS) the prior bytes can still survive
/// in snapshots/backups, so this is **not** a forensic wipe — it just
/// reduces the window where a casual `cat identity.bin` returns the
/// real secret. The threat model documents that anyone with disk-level
/// access predating the migration may still have a copy.
#[cfg(not(target_os = "android"))]
fn secure_wipe_identity_file(path: &Path) {
    use std::io::{Seek, SeekFrom, Write};

    let result = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&[0u8; 32])?;
        f.sync_all()?;
        drop(f);
        fs::remove_file(path)?;
        Ok(())
    })();
    match result {
        Ok(()) => tracing::info!(path = %path.display(), "wiped legacy identity.bin"),
        Err(e) => tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to wipe legacy identity.bin; remove it manually"
        ),
    }
}

/// Atomic, mode-0600 write of the legacy `identity.bin`. Compiled on
/// every unix host: Android at runtime, the `FLUXSYNC_NO_KEYCHAIN`
/// escape hatch on macOS/Linux, and tests exercising the migration
/// logic without the real keychain.
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

/// Persist the trusted-peer registry. Atomic via `*.tmp` + rename, and
/// the tmp file is fsynced before the rename so a crash mid-write can't
/// leave the registry empty or unparseable — same durability guarantee
/// as `write_secret_atomic`.
pub fn save_peers(dir: &Path, peers: &[StoredPeer]) -> Result<()> {
    use std::io::Write;

    ensure_dir(dir)?;
    let path = dir.join(PEERS_FILE);
    let pf = PeersFile {
        peers: peers.to_vec(),
    };
    let s = serde_json::to_string_pretty(&pf)?;
    let tmp = path.with_extension("json.tmp");
    {
        // M1: mode 0o600. Trust topology (peer names + pubkeys) must
        // not be world-readable; other local accounts could enumerate
        // who this daemon trusts and harvest stable peer-ids for
        // correlation. Public keys are public, but the *set* is sensitive.
        #[cfg(unix)]
        let opts = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = fs::OpenOptions::new();
            o.create(true).write(true).truncate(true).mode(0o600);
            o
        };
        #[cfg(not(unix))]
        let opts = {
            let mut o = fs::OpenOptions::new();
            o.create(true).write(true).truncate(true);
            o
        };
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(s.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Insert `new` into `peers`, replacing any existing entry with the same
/// `peer_id_hex`. Last-write-wins: callers that re-pair a known peer get a
/// refreshed entry instead of a duplicate.
pub fn upsert_peer(peers: &mut Vec<StoredPeer>, new: StoredPeer) {
    peers.retain(|p| p.peer_id_hex != new.peer_id_hex);
    peers.push(new);
}

#[cfg(test)]
mod tests {
    use super::{load_peers, save_peers, upsert_peer, StoredPeer, IDENTITY_FILE, PEERS_FILE};
    use super::{read_legacy_identity, write_secret_atomic};

    fn peer(name: &str) -> StoredPeer {
        StoredPeer {
            peer_id_hex: "aa".repeat(32),
            static_pub_hex: "bb".repeat(32),
            name: name.to_owned(),
            last_addr: None,
        }
    }

    /// FS-028: `save_peers` must round-trip through `load_peers` and leave
    /// no stale `*.tmp` behind. The fsync durability itself has no
    /// observable effect without a crash; it is verified by inspection
    /// against `write_secret_atomic`.
    #[test]
    fn fs028_save_peers_round_trips_and_cleans_tmp() {
        let dir = tempfile::tempdir().expect("create temp keystore dir");

        save_peers(dir.path(), &[peer("Galaxy S21"), peer("MacBook")])
            .expect("save_peers must succeed");

        let loaded = load_peers(dir.path()).expect("load_peers must succeed");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "Galaxy S21");
        assert_eq!(loaded[1].name, "MacBook");

        let tmp = dir.path().join(PEERS_FILE).with_extension("json.tmp");
        assert!(!tmp.exists(), "the .tmp file must not survive the rename");
    }

    /// FS-029: `upsert_peer` must dedup by `peer_id_hex` (last-write-wins)
    /// so re-pairing a known peer cannot append a duplicate to peers.json.
    #[test]
    fn fs029_upsert_peer_dedups_by_peer_id() {
        let mut peers: Vec<StoredPeer> = Vec::new();

        for i in 0..10 {
            upsert_peer(
                &mut peers,
                StoredPeer {
                    peer_id_hex: "aa".repeat(32),
                    static_pub_hex: "bb".repeat(32),
                    name: "Galaxy S21".to_owned(),
                    last_addr: Some(format!("10.0.0.{i}:41889")),
                },
            );
        }
        assert_eq!(peers.len(), 1, "same peer_id must collapse to one entry");
        assert_eq!(
            peers[0].last_addr.as_deref(),
            Some("10.0.0.9:41889"),
            "the freshest upsert must win"
        );

        upsert_peer(
            &mut peers,
            StoredPeer {
                peer_id_hex: "cc".repeat(32),
                static_pub_hex: "dd".repeat(32),
                name: "MacBook".to_owned(),
                last_addr: None,
            },
        );
        assert_eq!(peers.len(), 2, "a distinct peer_id must be a new entry");
    }

    /// FS-053: a legacy 32-byte `identity.bin` round-trips through
    /// `read_legacy_identity` — used by the keychain migration path.
    #[test]
    fn fs053_read_legacy_identity_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(IDENTITY_FILE);
        let secret = [0x42u8; 32];
        write_secret_atomic(&path, &secret).expect("write legacy identity");

        let id = read_legacy_identity(&path).expect("read legacy identity");
        assert_eq!(
            id.secret_bytes().as_ref(),
            &secret,
            "round-trip must preserve the raw 32-byte secret"
        );
    }

    /// FS-053: corrupt files (wrong length) must error, not silently
    /// regenerate — otherwise migration would invalidate every paired peer.
    #[test]
    fn fs053_read_legacy_identity_rejects_wrong_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(IDENTITY_FILE);
        std::fs::write(&path, [0u8; 16]).expect("write short identity");

        // `Identity` does not implement `Debug` (so secrets never leak
        // into panic messages), so we cannot use `expect_err`. Match
        // explicitly instead.
        match read_legacy_identity(&path) {
            Ok(_) => panic!("must reject wrong-length identity"),
            Err(err) => assert!(
                err.to_string().contains("length 16"),
                "error must name the actual length, got: {err}"
            ),
        }
    }

    /// FS-053: `secure_wipe_identity_file` overwrites then removes the
    /// legacy file. Verifies the file is gone after the call; the
    /// overwrite step is best-effort on COW filesystems and not asserted.
    #[test]
    #[cfg(not(target_os = "android"))]
    fn fs053_secure_wipe_removes_legacy_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(IDENTITY_FILE);
        write_secret_atomic(&path, &[0x55u8; 32]).expect("write legacy identity");
        assert!(path.exists(), "fixture must be on disk");

        super::secure_wipe_identity_file(&path);
        assert!(
            !path.exists(),
            "secure_wipe must remove the legacy identity.bin"
        );
    }

    /// FS-053: keychain hex decoder must reject malformed payloads
    /// (truncated entry, non-hex chars) so a tampered keychain item
    /// cannot smuggle in a short key.
    #[test]
    #[cfg(not(target_os = "android"))]
    fn fs053_decode_identity_hex_validates_length() {
        // Wrong byte length after decode.
        match super::decode_identity_hex("deadbeef") {
            Ok(_) => panic!("short hex must fail"),
            Err(err) => assert!(err.to_string().contains("length 4"), "got: {err}"),
        }

        // Garbage hex.
        let bad = "zzzz".repeat(16);
        assert!(
            super::decode_identity_hex(&bad).is_err(),
            "non-hex must fail"
        );

        // Round-trip a real 64-char hex.
        let raw = [0xa5u8; 32];
        let id = super::decode_identity_hex(&hex::encode(raw)).expect("valid hex must decode");
        assert_eq!(id.secret_bytes().as_ref(), &raw);
    }
}
