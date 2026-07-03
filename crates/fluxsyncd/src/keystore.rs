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
//! Keychain ACL (FS-062 / DIR-P2-01, macOS only, **opt-in**): `keyring`'s
//! macOS write path leaves the item with the OS default access-control
//! list, on which "Always Allow" grants accumulate silently — a one-time
//! human mistake becomes a permanent skeleton key for that app. Setting
//! `FLUXSYNC_STRICT_KEYCHAIN=1` routes writes through `mac_acl` below,
//! which attaches a self-only ACL via the legacy `SecAccessCreate` API
//! and re-asserts it on every boot; reads are unaffected since
//! `SecItemAdd` and `keyring`'s `SecKeychainFindGenericPassword` read
//! path operate on the same underlying keychain item.
//!
//! Strict mode is NOT the default because the trusted-application entry
//! is anchored to the binary's identity: unsigned/self-built daemons
//! change identity on every rebuild, so a strict ACL makes macOS
//! re-prompt for the keychain password after each update — recurring
//! prompts, which the product explicitly rejects ("it just works"). It
//! becomes the default once Developer ID signing (DIR-P4-01) lands: a
//! signature-anchored trusted-application entry survives app updates
//! without re-prompting. In default mode the boot path performs exactly
//! the same keychain calls as before FS-062 (plain `keyring` get/set).
//! See `docs/SECURITY.md` §2.4 for the full per-platform breakdown,
//! including why Windows/Linux are left as documented residuals rather
//! than given equivalent ceremony.
//!
//! `peers.json` is written atomically (`*.tmp` + fsync + rename) so a
//! crash mid-write cannot corrupt the registry. The fallback identity
//! file on Android uses the same atomic write.

use anyhow::{anyhow, Context, Result};
use fluxsync_core::FirewallPolicy;
use fluxsync_crypto::Identity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const IDENTITY_FILE: &str = "identity.bin";
const PEERS_FILE: &str = "peers.json";
const FIREWALL_FILE: &str = "firewall.json";
const DEVICE_NAME_FILE: &str = "device_name.json";

/// Service name used for the keychain entry. Keep stable: changing it
/// after the first release would orphan every existing user's identity.
#[cfg(not(target_os = "android"))]
const KEYCHAIN_SERVICE: &str = "fluxsyncd";

// C3 (FS-062 / DIR-P2-01) — the `keyring` crate stores secrets as a
// generic password with the default ACL: any process running as the
// current user can read them without prompting once trust has ever been
// granted once (e.g. a human clicking "Always Allow" on a `security
// find-generic-password -s fluxsyncd -w` prompt during debugging).
//
// Fix, by platform:
//   1. macOS: built, opt-in via `FLUXSYNC_STRICT_KEYCHAIN=1` (see
//      `strict_keychain_enabled`). `mac_acl::store_with_acl` /
//      `mac_acl::tighten_access` below attach an explicit self-only ACL
//      via the legacy `SecAccessCreate` API. Not the default: the
//      trusted-app entry pins the exact binary, so unsigned dev builds
//      re-prompt after every rebuild (prompt fatigue). Becomes the
//      default with Developer ID signing (DIR-P4-01). The modern
//      `kSecAttrAccessControl` / Data Protection Keychain path was tried
//      first and rejected: it needs the `keychain-access-groups`
//      entitlement, which an unsigned/self-built daemon binary does not
//      have (confirmed: `SecItemAdd` fails with
//      `errSecMissingEntitlement`, and forcing an ad-hoc entitlement gets
//      the process killed by AMFI before it touches the keychain). If
//      fluxsyncd ever gets a stable Developer ID signature, the DPK is
//      the natural upgrade.
//   2. Windows: not changed. Credential Manager is already DPAPI-backed
//      at rest, and has no per-app ACL primitive to attach — any same-user
//      process can call `CredReadW`. Documented as an accepted residual
//      in `docs/SECURITY.md` §2.4 rather than given ceremony that
//      wouldn't raise the real bar.
//   3. Linux: not changed. The Secret Service model grants access per
//      D-Bus session, not per requesting binary; no per-app ACL to
//      attach either. Documented as an accepted residual.
//
// Tracked in `docs/THREAT-MODEL.md` (FS-053 follow-up) and
// `docs/SECURITY.md` §2.4 / §7 (FS-062).

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
    /// Last known remote `SocketAddr` this peer linked from, as a string
    /// (`Display`-formatted, e.g. `"192.168.1.5:41889"`). Used as a
    /// unicast redial hint at boot so re-linking to an already-paired
    /// peer does not depend entirely on mDNS rediscovery. `#[serde(default)]`
    /// because a `peers.json` written by a pre-existing binary (before this
    /// field existed) lacks the key entirely — it must load as `None`, not
    /// fail to parse.
    #[serde(default)]
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
                // FS-062 / DIR-P2-01: in strict mode only, idempotently
                // re-assert the self-only ACL on every successful load.
                // A no-op (zero keychain calls) unless
                // FLUXSYNC_STRICT_KEYCHAIN=1 — the default boot path must
                // never issue a call that can trigger or worsen a
                // keychain prompt. Non-fatal: this boot already has `id`
                // in memory either way, so a failure here is logged and
                // retried next boot, never surfaced as a startup error.
                #[cfg(target_os = "macos")]
                tighten_keychain_acl_if_needed(&entry, &hex);
                return Ok(id);
            }
            Err(keyring::Error::NoEntry) => {
                // First boot on this machine, or a fresh user.
                let legacy = dir.join(IDENTITY_FILE);
                let id = if legacy.exists() {
                    let imported = read_legacy_identity(&legacy)?;
                    store_identity_in_keychain(&entry, &imported)?;
                    // Fail-safe migration order: the secret is already
                    // safely in the keychain at this point; confirm it
                    // reads back correctly *before* wiping the only other
                    // copy. This is the device's cryptographic identity —
                    // losing it unpairs every peer — so we refuse to wipe
                    // on any doubt.
                    verify_keychain_readback(&entry, &imported)
                        .context("post-migration readback check for legacy identity.bin")?;
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

/// FS-062 / DIR-P2-01: whether the opt-in strict self-only keychain ACL
/// is enabled (macOS only). Default OFF — the trusted-application entry
/// pins the exact binary, so unsigned/self-built daemons would re-prompt
/// for the keychain password after every rebuild. Mirrors how
/// `FLUXSYNC_NO_KEYCHAIN` is read.
#[cfg(target_os = "macos")]
fn strict_keychain_enabled() -> bool {
    std::env::var("FLUXSYNC_STRICT_KEYCHAIN").as_deref() == Ok("1")
}

/// Persist the identity in the OS keychain. Default path on every
/// platform is `keyring::Entry::set_password` — identical to the
/// pre-FS-062 behavior. On macOS with `FLUXSYNC_STRICT_KEYCHAIN=1`, the
/// write goes through `mac_acl::store_with_acl` instead, which attaches a
/// self-only ACL at creation (see the `mac_acl` module doc for why this
/// is opt-in).
#[cfg(not(target_os = "android"))]
fn store_identity_in_keychain(entry: &keyring::Entry, id: &Identity) -> Result<()> {
    let secret = id.secret_bytes();
    let hex_secret = zeroize::Zeroizing::new(hex::encode(secret.as_ref()));
    #[cfg(target_os = "macos")]
    if strict_keychain_enabled() {
        return mac_acl::store_with_acl(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, hex_secret.as_bytes())
            .context("write fluxsyncd identity to OS keychain with self-only ACL");
    }
    entry
        .set_password(&hex_secret)
        .context("write fluxsyncd identity to OS keychain")
}

/// Re-read the keychain entry and confirm it decodes to exactly `expected`.
/// Used right after a migration writes the keychain for the first time and
/// before the only other copy of the secret (the legacy file) is wiped —
/// losing this identity unpairs every peer, so the wipe must never run on
/// unverified faith that the write succeeded.
#[cfg(not(target_os = "android"))]
fn verify_keychain_readback(entry: &keyring::Entry, expected: &Identity) -> Result<()> {
    let raw = entry
        .get_password()
        .context("read back identity from OS keychain immediately after writing it")?;
    let hex = zeroize::Zeroizing::new(raw);
    let id = decode_identity_hex(&hex).context("decode keychain identity during readback verification")?;
    if id.secret_bytes().as_ref() == expected.secret_bytes().as_ref() {
        Ok(())
    } else {
        Err(anyhow!(
            "keychain readback does not match the identity that was just written; refusing to \
             wipe the legacy identity.bin"
        ))
    }
}

/// FS-062 / DIR-P2-01: in strict mode, idempotently re-assert the
/// self-only keychain ACL on every successful load. Covers an item
/// created before strict mode was enabled (default ACL), or one loosened
/// by a stray "Always Allow" click during manual debugging with
/// `security find-generic-password`. A no-op — zero keychain API calls —
/// unless `FLUXSYNC_STRICT_KEYCHAIN=1`: in default mode nothing here may
/// run, because `SecItemUpdate` on an item this (rebuilt, unsigned)
/// binary is not trusted for would itself trigger a password prompt.
/// Non-fatal by design: the caller already has a valid `id` in memory for
/// this boot regardless of outcome, so failures here are logged and
/// retried next boot, never surfaced as a startup error.
#[cfg(target_os = "macos")]
fn tighten_keychain_acl_if_needed(entry: &keyring::Entry, expected_hex: &str) {
    if !strict_keychain_enabled() {
        return;
    }
    if let Err(e) = mac_acl::tighten_access(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
        tracing::warn!(
            error = %e,
            "failed to tighten keychain ACL for fluxsyncd identity; will retry next boot"
        );
        return;
    }
    match entry.get_password() {
        Ok(readback_raw) => {
            let readback = zeroize::Zeroizing::new(readback_raw);
            if readback.as_str() == expected_hex {
                tracing::info!("tightened keychain ACL for fluxsyncd identity to self-only access");
            } else {
                tracing::error!(
                    "keychain identity readback mismatch immediately after ACL tighten; this \
                     boot's in-memory identity is still correct, but the on-disk keychain entry \
                     may be inconsistent — investigate before the next restart"
                );
            }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "keychain identity became unreadable immediately after ACL tighten; this boot's \
                 in-memory identity is still correct, but investigate before the next restart"
            );
        }
    }
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

/// Load the persisted clipboard firewall policy (chantier A). Returns the
/// disabled default when the file is missing, empty, or unparseable — a
/// corrupt policy must never wedge boot, and "off" is the safe fallback.
#[must_use]
pub fn load_firewall(dir: &Path) -> FirewallPolicy {
    let path = dir.join(FIREWALL_FILE);
    let Ok(s) = fs::read_to_string(&path) else {
        return FirewallPolicy::default();
    };
    serde_json::from_str(&s).unwrap_or_default()
}

/// Persist the clipboard firewall policy. Atomic via `*.tmp` + fsync +
/// rename, same durability guarantee as `save_peers`. Not a secret (rules,
/// not keys), but written 0o600 for consistency with the other state files.
pub fn save_firewall(dir: &Path, policy: &FirewallPolicy) -> Result<()> {
    use std::io::Write;

    ensure_dir(dir)?;
    let path = dir.join(FIREWALL_FILE);
    let s = serde_json::to_string_pretty(policy)?;
    let tmp = path.with_extension("json.tmp");
    {
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

/// On-disk shape of `device_name.json`. A tiny wrapper (rather than a bare
/// string file) so the format matches every other keystore file and can
/// grow fields later without a migration.
#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceNameFile {
    name: String,
}

/// DIR-P3-01: load the persisted device name, if any. Returns `None` when
/// the file is missing, empty, or unparseable — first boot, or a corrupt
/// file, both fall back to the caller's own default (hostname-derived or
/// `--peer-name`) rather than a hardcoded string.
#[must_use]
pub fn load_device_name(dir: &Path) -> Option<String> {
    let path = dir.join(DEVICE_NAME_FILE);
    let s = fs::read_to_string(&path).ok()?;
    let f: DeviceNameFile = serde_json::from_str(&s).ok()?;
    if f.name.trim().is_empty() {
        None
    } else {
        Some(f.name)
    }
}

/// Persist the device name so a `CmdOp::SetDeviceName` survives a restart.
/// Atomic via `*.tmp` + fsync + rename, same durability guarantee as
/// `save_peers`/`save_firewall`. Not a secret, but written 0o600 for
/// consistency with the other state files.
pub fn save_device_name(dir: &Path, name: &str) -> Result<()> {
    use std::io::Write;

    ensure_dir(dir)?;
    let path = dir.join(DEVICE_NAME_FILE);
    let s = serde_json::to_string_pretty(&DeviceNameFile {
        name: name.to_string(),
    })?;
    let tmp = path.with_extension("json.tmp");
    {
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

/// FS-062 / DIR-P2-01 — self-only keychain ACL for the identity item.
///
/// **Opt-in** (`FLUXSYNC_STRICT_KEYCHAIN=1`, see `strict_keychain_enabled`
/// and the module doc at the top of this file): the trusted-application
/// entry created here pins the exact binary, so unsigned/self-built
/// daemons re-prompt after every rebuild. The machinery is kept complete
/// and tested so it can become the default once Developer ID signing
/// (DIR-P4-01) lands — a signature-anchored entry survives updates
/// without re-prompting.
///
/// Not expressible through `keyring`, nor through `security-framework`'s
/// safe wrapper: both only support the default (unrestricted) ACL. The
/// modern alternative, `kSecAttrAccessControl` on the Data Protection
/// Keychain (`kSecUseDataProtectionKeychain`), was tried and rejected —
/// it needs the `keychain-access-groups` entitlement, which an
/// unsigned/self-built daemon binary does not have. Confirmed empirically:
/// `SecItemAdd` with `kSecAttrAccessControl` fails with
/// `errSecMissingEntitlement` (-34018) for this binary, and forcing an
/// ad-hoc entitlements claim gets the process killed by AMFI before it
/// ever reaches the keychain. If fluxsyncd ever ships with a stable
/// Developer ID signature, the Data Protection Keychain is the natural
/// upgrade over what's here.
///
/// So this calls the legacy `SecAccessCreate` / `kSecAttrAccess` API
/// directly against the classic file keychain, which needs no
/// entitlement — it's the same mechanism `keyring`'s own macOS backend
/// (`SecKeychainAddGenericPassword`) implicitly relies on, just with an
/// explicit trusted-application list instead of the OS default. `SecItemAdd`
/// / `SecItemUpdate` (used here) and the legacy
/// `SecKeychainFindGenericPassword` (used by `keyring::Entry::get_password`,
/// still used for all reads in this file) operate on the same underlying
/// keychain item, so reads did not need to change — verified: an item
/// created here is found and returned correctly by `keyring::Entry`.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod mac_acl {
    use anyhow::{anyhow, Result};
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::array::CFArrayRef;
    use core_foundation_sys::base::{CFRelease, CFTypeRef, OSStatus};
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::base::{errSecDuplicateItem, SecAccessRef};
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemUpdate};
    use std::os::raw::c_char;
    use std::ptr;

    // Not bound by `security-framework-sys` (only the modern
    // `kSecAttrAccessControl` path is). Declared straight from
    // `Security/SecAccess.h` and `Security/SecTrustedApplication.h` —
    // deprecated since macOS 10.10 but still present and linkable.
    // `security-framework-sys`'s build script already links
    // `Security.framework`, so no extra linker configuration is needed.
    enum OpaqueSecTrustedApplication {}
    type SecTrustedApplicationRef = *mut OpaqueSecTrustedApplication;

    extern "C" {
        static kSecAttrAccess: CFStringRef;

        /// NULL `path` resolves to "the calling application" per Apple's
        /// documented behavior. Returns a `CF_RETURNS_RETAINED` ref.
        fn SecTrustedApplicationCreateFromPath(
            path: *const c_char,
            app: *mut SecTrustedApplicationRef,
        ) -> OSStatus;

        /// A `trusted_list` of exactly one app makes that app the sole
        /// reader that bypasses the system authorization prompt. Returns a
        /// `CF_RETURNS_RETAINED` ref.
        fn SecAccessCreate(
            descriptor: CFStringRef,
            trusted_list: CFArrayRef,
            access_ref: *mut SecAccessRef,
        ) -> OSStatus;
    }

    /// Build a `SecAccess` whose trusted-application list contains
    /// exactly the current process. Any other process — signed or not —
    /// that later tries to read the item is handed to the system's
    /// keychain authorization UI instead of getting the secret silently.
    fn self_only_access() -> Result<CFType> {
        // Safety: `SecTrustedApplicationCreateFromPath` writes a
        // `CF_RETURNS_RETAINED` ref into `app_ref` on success;
        // `wrap_under_create_rule` takes ownership of that retain and
        // releases it on drop. `SecTrustedApplication` is a
        // toll-free-bridged CF type, so wrapping it as the generic
        // `CFType` is valid (`CFRelease` doesn't need the concrete type).
        let app: CFType = unsafe {
            let mut app_ref: SecTrustedApplicationRef = ptr::null_mut();
            let status = SecTrustedApplicationCreateFromPath(
                ptr::null(),
                std::ptr::addr_of_mut!(app_ref),
            );
            if status != 0 || app_ref.is_null() {
                return Err(anyhow!(
                    "SecTrustedApplicationCreateFromPath failed with OSStatus {status}"
                ));
            }
            CFType::wrap_under_create_rule(app_ref as CFTypeRef)
        };
        let trusted_list = CFArray::from_CFTypes(&[app]);
        let descriptor = CFString::new("FluxSync device identity");

        // Safety: same reasoning as above — `SecAccess` is also
        // `CF_RETURNS_RETAINED` and toll-free-bridged. `descriptor` and
        // `trusted_list` outlive the call.
        unsafe {
            let mut access_ref: SecAccessRef = ptr::null_mut();
            let status = SecAccessCreate(
                descriptor.as_concrete_TypeRef(),
                trusted_list.as_concrete_TypeRef(),
                std::ptr::addr_of_mut!(access_ref),
            );
            if status != 0 || access_ref.is_null() {
                return Err(anyhow!("SecAccessCreate failed with OSStatus {status}"));
            }
            Ok(CFType::wrap_under_create_rule(access_ref as CFTypeRef))
        }
    }

    /// `kSecClass`/`kSecAttrService`/`kSecAttrAccount` triple identifying
    /// the item, shared by add/update/query dictionaries.
    fn class_service_account(service: &str, account: &str) -> Vec<(CFString, CFType)> {
        // Safety: `kSecClass`, `kSecClassGenericPassword`,
        // `kSecAttrService`, `kSecAttrAccount` are read-only `CFStringRef`
        // constants exported by `Security.framework`, valid for the
        // process lifetime.
        unsafe {
            vec![
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::from(service).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::from(account).into_CFType(),
                ),
            ]
        }
    }

    fn access_pair(access: CFType) -> (CFString, CFType) {
        // Safety: `kSecAttrAccess` is a read-only constant (see above).
        (unsafe { CFString::wrap_under_get_rule(kSecAttrAccess) }, access)
    }

    fn data_pair(secret: &[u8]) -> (CFString, CFType) {
        // Safety: `kSecValueData` is a read-only constant; `secret`
        // outlives the call that consumes this pair.
        unsafe {
            (
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(secret).into_CFType(),
            )
        }
    }

    /// Update the ACL (and, if `secret` is `Some`, the data) of an
    /// existing item matching `service`/`account`, in one atomic call.
    fn update(service: &str, account: &str, secret: Option<&[u8]>, access: CFType) -> Result<()> {
        let query = CFDictionary::from_CFType_pairs(&class_service_account(service, account));
        let mut pairs = vec![access_pair(access)];
        if let Some(secret) = secret {
            pairs.push(data_pair(secret));
        }
        let update = CFDictionary::from_CFType_pairs(&pairs);
        // Safety: both dictionaries are valid CF objects for the duration
        // of the call; `SecItemUpdate` does not retain them past return.
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
        if status == 0 {
            Ok(())
        } else {
            Err(anyhow!("SecItemUpdate failed with OSStatus {status}"))
        }
    }

    /// Create the keychain item with `secret` and a self-only ACL. If one
    /// already exists (an older boot lost a race, or this runs twice),
    /// falls back to updating it in place with the same data + ACL —
    /// matching `keyring::Entry::set_password`'s create-or-update
    /// semantics.
    pub(super) fn store_with_acl(service: &str, account: &str, secret: &[u8]) -> Result<()> {
        let access = self_only_access()?;
        let mut pairs = class_service_account(service, account);
        pairs.push(data_pair(secret));
        pairs.push(access_pair(access.clone()));
        let add_dict = CFDictionary::from_CFType_pairs(&pairs);

        // Safety: `add_dict` is a valid CF object for the duration of the
        // call. On success the output ref is `CF_RETURNS_RETAINED`; we
        // don't need it, so it's released immediately.
        let status = unsafe {
            let mut result: CFTypeRef = ptr::null();
            let status = SecItemAdd(add_dict.as_concrete_TypeRef(), std::ptr::addr_of_mut!(result));
            if !result.is_null() {
                CFRelease(result);
            }
            status
        };
        if status == 0 {
            return Ok(());
        }
        if status == errSecDuplicateItem {
            return update(service, account, Some(secret), access);
        }
        Err(anyhow!("SecItemAdd failed with OSStatus {status}"))
    }

    /// Re-assert the self-only ACL on an item that already exists and was
    /// just read successfully, without touching its secret data.
    /// Idempotent: safe to call on every boot. `SecItemUpdate` is a
    /// single atomic call, so there is no window where the item is
    /// missing or only partially written.
    pub(super) fn tighten_access(service: &str, account: &str) -> Result<()> {
        let access = self_only_access()?;
        update(service, account, None, access)
    }

    #[cfg(test)]
    mod tests {
        use super::{class_service_account, store_with_acl, tighten_access};
        use core_foundation::base::TCFType;
        use core_foundation::dictionary::CFDictionary;
        use security_framework_sys::keychain_item::SecItemDelete;

        // All three tests are `#[ignore]`: they exercise the REAL login
        // keychain (there is no mockable seam below `SecItemAdd`), and
        // although they only ever touch dedicated `fluxsyncd-dir-p2-01-
        // test-*` service names — never the real `KEYCHAIN_SERVICE` /
        // `KEYCHAIN_ACCOUNT` item — any leftover item from an aborted
        // previous run was created by a *different* test binary (each
        // rebuild changes the binary identity), and reading or
        // overwriting such an item makes macOS raise a keychain
        // password prompt. Repo invariant: a default `cargo test` run
        // must produce ZERO keychain dialogs. Run these explicitly with
        // `cargo test -p fluxsyncd --lib mac_acl -- --ignored`.
        //
        // Each test gets its own service name rather than sharing one,
        // because `cargo test` runs tests in parallel and a shared
        // keychain item across threads would race.
        const TEST_ACCOUNT: &str = "identity-test";

        /// Delete the test item WITHOUT reading its data. `SecItemDelete`
        /// never decrypts the secret, so unlike `keyring`'s
        /// `delete_credential` (which does a find-with-data first) it
        /// cannot trigger an authorization prompt even on a stale item
        /// whose ACL trusts a previous test binary. Called at both start
        /// (purge leftovers from aborted runs) and end of every test so
        /// stale-ACL items never accumulate across rebuilds.
        fn cleanup(service: &str) {
            let query =
                CFDictionary::from_CFType_pairs(&class_service_account(service, TEST_ACCOUNT));
            // Safety: `query` is a valid CF dictionary for the duration
            // of the call; a not-found status is fine (nothing to clean).
            unsafe {
                SecItemDelete(query.as_concrete_TypeRef());
            }
        }

        /// `store_with_acl` creates an item that `keyring::Entry` (the
        /// read path every platform actually uses) can read back — this
        /// is the interoperability guarantee the whole design leans on.
        #[test]
        #[ignore = "touches real login keychain — run explicitly with --ignored"]
        fn store_with_acl_is_readable_via_keyring() {
            let service = "fluxsyncd-dir-p2-01-test-readable";
            cleanup(service);
            store_with_acl(service, TEST_ACCOUNT, b"deadbeef00").expect("create with ACL");
            let entry = keyring::Entry::new(service, TEST_ACCOUNT).expect("open entry");
            assert_eq!(entry.get_password().expect("read back"), "deadbeef00");
            cleanup(service);
        }

        /// Calling `store_with_acl` again on the same service/account
        /// exercises the `errSecDuplicateItem` fallback path and must
        /// overwrite the data.
        #[test]
        #[ignore = "touches real login keychain — run explicitly with --ignored"]
        fn store_with_acl_overwrites_existing_item() {
            let service = "fluxsyncd-dir-p2-01-test-overwrite";
            cleanup(service);
            store_with_acl(service, TEST_ACCOUNT, b"first-value").expect("first create");
            store_with_acl(service, TEST_ACCOUNT, b"second-value")
                .expect("second store hits the duplicate-item fallback");
            let entry = keyring::Entry::new(service, TEST_ACCOUNT).expect("open entry");
            assert_eq!(entry.get_password().expect("read back"), "second-value");
            cleanup(service);
        }

        /// `tighten_access` must not touch the stored data, only the ACL.
        #[test]
        #[ignore = "touches real login keychain — run explicitly with --ignored"]
        fn tighten_access_leaves_data_untouched() {
            let service = "fluxsyncd-dir-p2-01-test-tighten";
            cleanup(service);
            store_with_acl(service, TEST_ACCOUNT, b"untouched-secret").expect("create");
            tighten_access(service, TEST_ACCOUNT).expect("tighten");
            let entry = keyring::Entry::new(service, TEST_ACCOUNT).expect("open entry");
            assert_eq!(entry.get_password().expect("read back"), "untouched-secret");
            cleanup(service);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        load_device_name, load_firewall, load_peers, save_device_name, save_firewall, save_peers,
        upsert_peer, StoredPeer, DEVICE_NAME_FILE, FIREWALL_FILE, PEERS_FILE,
    };
    #[cfg(unix)]
    use super::{read_legacy_identity, write_secret_atomic, IDENTITY_FILE};
    use fluxsync_core::{FirewallPolicy, Rule};

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

    /// Chantier A: the firewall policy round-trips through disk and leaves no
    /// stale `*.tmp`; a missing file yields the disabled default.
    #[test]
    fn firewall_save_load_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");

        // Missing file → disabled default.
        assert_eq!(load_firewall(dir.path()), FirewallPolicy::default());

        let policy = FirewallPolicy {
            enabled: true,
            text: Rule::Deny,
            image: Rule::Ask,
            ..FirewallPolicy::default()
        };
        save_firewall(dir.path(), &policy).expect("save_firewall must succeed");
        assert_eq!(load_firewall(dir.path()), policy);

        let tmp = dir.path().join(FIREWALL_FILE).with_extension("json.tmp");
        assert!(!tmp.exists(), "the .tmp file must not survive the rename");
    }

    /// A corrupt firewall.json must fall back to the safe default, never panic.
    #[test]
    fn firewall_corrupt_file_falls_back_to_default() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(FIREWALL_FILE), b"{ not json").unwrap();
        assert_eq!(load_firewall(dir.path()), FirewallPolicy::default());
    }

    /// DIR-P3-01: the renamed device name round-trips through disk and
    /// leaves no stale `*.tmp`; a missing file yields `None` so the caller
    /// falls back to its own hostname-derived default.
    #[test]
    fn device_name_save_load_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");

        assert_eq!(load_device_name(dir.path()), None);

        save_device_name(dir.path(), "Dethie's MacBook").expect("save_device_name must succeed");
        assert_eq!(
            load_device_name(dir.path()),
            Some("Dethie's MacBook".to_string())
        );

        let tmp = dir
            .path()
            .join(DEVICE_NAME_FILE)
            .with_extension("json.tmp");
        assert!(!tmp.exists(), "the .tmp file must not survive the rename");
    }

    /// A corrupt or empty-name device_name.json must fall back to `None`
    /// (caller default), never panic.
    #[test]
    fn device_name_corrupt_or_empty_falls_back_to_none() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(DEVICE_NAME_FILE), b"{ not json").unwrap();
        assert_eq!(load_device_name(dir.path()), None);

        save_device_name(dir.path(), "   ").expect("save_device_name must succeed");
        assert_eq!(load_device_name(dir.path()), None);
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

    /// `StoredPeer` roundtrips through raw `serde_json` (not just via the
    /// `save_peers`/`load_peers` file helpers) for both the `Some` and
    /// `None` shapes of `last_addr`.
    #[test]
    fn stored_peer_serde_roundtrip_some_and_none() {
        let with_addr = StoredPeer {
            peer_id_hex: "aa".repeat(32),
            static_pub_hex: "bb".repeat(32),
            name: "Pixel 8".to_owned(),
            last_addr: Some("192.168.1.5:41889".to_owned()),
        };
        let json = serde_json::to_string(&with_addr).expect("serialize Some(addr)");
        let back: StoredPeer = serde_json::from_str(&json).expect("deserialize Some(addr)");
        assert_eq!(back.last_addr.as_deref(), Some("192.168.1.5:41889"));
        assert_eq!(back.name, "Pixel 8");

        let without_addr = peer("iPad");
        let json = serde_json::to_string(&without_addr).expect("serialize None");
        let back: StoredPeer = serde_json::from_str(&json).expect("deserialize None");
        assert_eq!(back.last_addr, None);
    }

    /// Downgrade-compat (old-file / new-binary direction): a `peers.json`
    /// entry written before `last_addr` existed has no such key at all.
    /// `#[serde(default)]` on the field must make this deserialize to
    /// `None` rather than erroring "missing field last_addr".
    #[test]
    fn stored_peer_deserializes_old_format_missing_addr_field() {
        let old_json = format!(
            r#"{{"peer_id_hex":"{}","static_pub_hex":"{}","name":"Old Peer"}}"#,
            "aa".repeat(32),
            "bb".repeat(32)
        );
        let parsed: StoredPeer = serde_json::from_str(&old_json)
            .expect("old-format JSON (no last_addr key) must still parse");
        assert_eq!(parsed.last_addr, None);
        assert_eq!(parsed.name, "Old Peer");
    }

    /// Downgrade-compat (new-file / old-binary direction, empirical check):
    /// neither `StoredPeer` nor its container `PeersFile` derives
    /// `#[serde(deny_unknown_fields)]` anywhere in the chain (unlike the
    /// wire-protocol types in `fluxsync-proto`, which do), so a JSON blob
    /// carrying a field this struct doesn't know about must be silently
    /// ignored rather than a hard deserialize error. This is what makes an
    /// OLD binary able to read a `peers.json` written by a NEWER one that
    /// added a field after `last_addr`.
    #[test]
    fn stored_peer_deserialize_tolerates_unknown_fields() {
        let json_with_extra_field = format!(
            r#"{{"peer_id_hex":"{}","static_pub_hex":"{}","name":"New Peer","last_addr":null,"some_future_field":42}}"#,
            "aa".repeat(32),
            "bb".repeat(32)
        );
        let parsed: StoredPeer = serde_json::from_str(&json_with_extra_field)
            .expect("unknown fields must be ignored, not hard-error");
        assert_eq!(parsed.last_addr, None);
        assert_eq!(parsed.name, "New Peer");
    }

    /// FS-053: a legacy 32-byte `identity.bin` round-trips through
    /// `read_legacy_identity` — used by the keychain migration path.
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(all(unix, not(target_os = "android")))]
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
