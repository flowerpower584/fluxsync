//! FluxVault: encrypted, on-disk persistence of clipboard history.
//!
//! The daemon's history (`State.history`) is volatile — a restart loses it.
//! This module persists it to `~/.fluxsync/history.enc`, encrypted at rest
//! with a key derived from the daemon identity (see
//! [`fluxsync_crypto::Identity::derive_at_rest_key`]), so a restart can
//! rehydrate the list.
//!
//! Retention is bounded two ways, enforced on every save and on load:
//!
//! * **TTL** — non-favorite entries older than `ttl_secs` are dropped.
//! * **disk cap** — at most `cap` non-favorite entries are kept (newest
//!   first); favorites are exempt from both limits so a pinned item never
//!   ages or caps out.
//!
//! Sensitive items never reach here: the core already excludes
//! `sensitive == true` from `State.history` before it is ever built.
//!
//! The file is written atomically (`*.tmp`, mode 0600 on unix, fsync,
//! rename) — the same durability guarantee as `keystore::save_peers`.

use crate::keystore;
use anyhow::{anyhow, Context, Result};
use fluxsync_core::HistoryItem;
use fluxsync_crypto::at_rest;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const HISTORY_FILE: &str = "history.enc";

/// BLAKE3-KDF context for the at-rest history key. Stable forever: changing
/// it would orphan every existing user's persisted history (it would fail to
/// decrypt and be treated as empty).
pub const AT_REST_CONTEXT: &str = "fluxsync at-rest history v1";

/// Default disk retention: entries older than this are pruned (unless
/// favorited). 7 days.
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Default max non-favorite entries retained on disk. Favorites are exempt.
pub const DEFAULT_DISK_CAP: usize = 500;

/// On-disk file format version. Bump only on an incompatible schema change;
/// an older/newer file that fails to parse is treated as empty (history is
/// best-effort, never load-fatal).
const VAULT_VERSION: u32 = 1;

/// One persisted history row: the UI `HistoryItem` plus the one piece of
/// metadata the wire DTO doesn't carry — an absolute timestamp for TTL
/// (`HistoryItem.time` is only `"HH:MM"`). The favorite flag lives on the
/// `HistoryItem` itself so it round-trips to the clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub item: HistoryItem,
    /// Wall-clock milliseconds since the epoch at insertion.
    pub created_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VaultFile {
    version: u32,
    entries: Vec<VaultEntry>,
}

/// Apply TTL and the disk cap to `entries` (assumed newest-first).
///
/// Favorites survive both limits. Non-favorites are dropped once older than
/// `ttl_secs`, and only the newest `cap` of the survivors are kept. Order is
/// preserved.
#[must_use]
pub fn prune(entries: Vec<VaultEntry>, now_ms: u64, ttl_secs: u64, cap: usize) -> Vec<VaultEntry> {
    let ttl_ms = ttl_secs.saturating_mul(1000);
    let mut kept = Vec::with_capacity(entries.len());
    let mut non_fav = 0usize;
    for e in entries {
        if e.item.favorite {
            kept.push(e);
            continue;
        }
        if now_ms.saturating_sub(e.created_ms) > ttl_ms {
            continue; // expired
        }
        if non_fav >= cap {
            continue; // over the non-favorite cap
        }
        non_fav += 1;
        kept.push(e);
    }
    kept
}

/// Load persisted history, pruning TTL-expired entries. Returns an empty
/// vector when the file is missing or empty (first boot). A decrypt or parse
/// failure is surfaced as an error so the caller can decide; history is
/// best-effort, so the daemon logs and falls back to empty rather than
/// aborting startup.
pub fn load(dir: &Path, key: &[u8; 32], now_ms: u64, ttl_secs: u64) -> Result<Vec<VaultEntry>> {
    let path = dir.join(HISTORY_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let blob = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    let plain = at_rest::open(key, &blob).map_err(|e| anyhow!("decrypt {}: {e}", path.display()))?;
    let vf: VaultFile =
        serde_json::from_slice(&plain).with_context(|| format!("parse {}", path.display()))?;
    Ok(prune(vf.entries, now_ms, ttl_secs, usize::MAX))
}

/// Persist `entries` (newest-first), pruned by TTL + `cap`, encrypted at rest
/// and written atomically.
pub fn save(
    dir: &Path,
    key: &[u8; 32],
    entries: &[VaultEntry],
    now_ms: u64,
    ttl_secs: u64,
    cap: usize,
) -> Result<()> {
    keystore::ensure_dir(dir)?;
    let pruned = prune(entries.to_vec(), now_ms, ttl_secs, cap);
    let vf = VaultFile {
        version: VAULT_VERSION,
        entries: pruned,
    };
    let plain = serde_json::to_vec(&vf).context("serialize history")?;
    let blob = at_rest::seal(key, &plain).map_err(|e| anyhow!("encrypt history: {e}"))?;
    write_bytes_atomic(&dir.join(HISTORY_FILE), &blob)
}

/// Delete the persisted history. Used to mirror the in-memory security wipes
/// (untrusted-peer-seen, ghost-timeout) so a restart can't resurrect history
/// the daemon deliberately cleared. A missing file is success.
pub fn clear(dir: &Path) -> Result<()> {
    let path = dir.join(HISTORY_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

/// Atomic binary write: tmp file (mode 0600 on unix), fsync, rename.
fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("enc.tmp");
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
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

#[cfg(test)]
mod tests {
    use super::{clear, load, prune, save, VaultEntry, DEFAULT_DISK_CAP, DEFAULT_TTL_SECS};
    use fluxsync_core::{HistoryItem, HistorySource, Kind};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique throwaway dir under the OS temp dir; no tempfile dep needed.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "fluxvault-test-{}-{}",
                std::process::id(),
                n
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entry(preview: &str, created_ms: u64, favorite: bool) -> VaultEntry {
        VaultEntry {
            item: HistoryItem {
                kind: Kind::Text,
                preview: preview.to_string(),
                time: "12:00".to_string(),
                source: HistorySource::Local,
                sensitive: false,
                lamport: created_ms,
                hash: "00".repeat(32),
                favorite,
            },
            created_ms,
        }
    }

    #[test]
    fn roundtrip_save_load() {
        let d = TmpDir::new();
        let key = [1u8; 32];
        let items = vec![entry("c", 3000, false), entry("b", 2000, false), entry("a", 1000, false)];
        save(d.path(), &key, &items, 3000, DEFAULT_TTL_SECS, DEFAULT_DISK_CAP).unwrap();
        let got = load(d.path(), &key, 3000, DEFAULT_TTL_SECS).unwrap();
        assert_eq!(got, items);
    }

    #[test]
    fn file_is_encrypted_at_rest() {
        let d = TmpDir::new();
        let key = [2u8; 32];
        save(d.path(), &key, &[entry("TOPSECRET", 1000, false)], 1000, DEFAULT_TTL_SECS, DEFAULT_DISK_CAP).unwrap();
        let raw = std::fs::read(d.path().join("history.enc")).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"TOPSECRET"));
    }

    #[test]
    fn wrong_key_load_errors() {
        let d = TmpDir::new();
        save(d.path(), &[3u8; 32], &[entry("x", 1000, false)], 1000, DEFAULT_TTL_SECS, DEFAULT_DISK_CAP).unwrap();
        assert!(load(d.path(), &[4u8; 32], 1000, DEFAULT_TTL_SECS).is_err());
    }

    #[test]
    fn missing_file_loads_empty() {
        let d = TmpDir::new();
        assert!(load(d.path(), &[0u8; 32], 0, DEFAULT_TTL_SECS).unwrap().is_empty());
    }

    #[test]
    fn clear_removes_file_and_is_idempotent() {
        let d = TmpDir::new();
        let key = [5u8; 32];
        save(d.path(), &key, &[entry("x", 1000, false)], 1000, DEFAULT_TTL_SECS, DEFAULT_DISK_CAP).unwrap();
        assert!(d.path().join("history.enc").exists());
        clear(d.path()).unwrap();
        assert!(!d.path().join("history.enc").exists());
        clear(d.path()).unwrap(); // idempotent: missing file is success
    }

    #[test]
    fn ttl_prunes_expired_keeps_favorite() {
        // now = 10 days, ttl = 1 day. Old non-fav dropped, old fav kept.
        let now = 10 * 24 * 60 * 60 * 1000;
        let ttl = 24 * 60 * 60;
        let out = prune(
            vec![entry("fresh", now, false), entry("old", 0, false), entry("oldfav", 0, true)],
            now,
            ttl,
            usize::MAX,
        );
        let previews: Vec<_> = out.iter().map(|e| e.item.preview.as_str()).collect();
        assert_eq!(previews, vec!["fresh", "oldfav"]);
    }

    #[test]
    fn cap_keeps_favorites_and_newest_nonfavorites() {
        let entries = vec![
            entry("n3", 3000, false),
            entry("fav", 2500, true),
            entry("n2", 2000, false),
            entry("n1", 1000, false),
        ];
        let out = prune(entries, 3000, DEFAULT_TTL_SECS, 2);
        let previews: Vec<_> = out.iter().map(|e| e.item.preview.as_str()).collect();
        // cap=2 non-favorites (newest n3, n2) + the favorite; n1 dropped.
        assert_eq!(previews, vec!["n3", "fav", "n2"]);
    }
}
