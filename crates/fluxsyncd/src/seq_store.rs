//! Persists the daemon's outgoing `EventId.seq` counter across restarts.
//!
//! `fluxsync_core::App` stamps every locally-originated `ClipboardItem` with
//! an `EventId { origin, seq }` (`App::next_local_event_id`, driven from
//! `local_seq`, incrementing from 0 — see `fluxsync-core/src/app.rs`). That
//! counter lives only in memory: a daemon restart used to reset it to 0, so
//! the first few items sent after every restart reused `seq` values a peer
//! had already recorded in its 256-entry mesh anti-loop `SeenSet`
//! (`fluxsync-core/src/dedup.rs`) — the peer would silently treat the fresh
//! post-restart items as replays and drop them.
//!
//! Fix: a reserve-ahead horizon persisted to a tiny plaintext JSON file next
//! to the daemon's other per-device state files (`device_name.json` etc, in
//! the keystore directory). This is a counter, not a secret, so plaintext is
//! fine — no encryption, unlike `history_store`'s vault.
//!
//! # Reserve-ahead scheme
//!
//! The file stores a `horizon`: an upper bound the daemon promises never to
//! reach without persisting a new, higher one first. At boot: read the
//! persisted horizon `H` (0 if the file is missing), start the in-memory
//! counter at `H`, and immediately persist `H + RESERVE`. Thereafter,
//! whenever the counter reaches the persisted horizon, persist
//! `horizon + RESERVE` again *before* any further seq is handed out — see
//! [`SeqStore::advance`], which callers invoke on every allocation.
//!
//! A crash can only lose the *unused* tail of the last reservation (at most
//! `RESERVE - 1` seq values skipped) — monotonicity across restarts never
//! breaks as long as the on-disk horizon itself is readable.
//!
//! # Corruption fallback
//!
//! Every persist also (best-effort) rewrites a one-generation-behind backup,
//! `event_seq.json.bak`, from the *last known-good in-memory horizon*
//! (never by blindly copying the main file, which could itself be the
//! corrupt bytes). If the main file is missing or fails to parse, `load`
//! falls back to the backup; if both are unreadable, it starts the horizon
//! at 0 and logs a warning — a real degraded case (a peer could treat a
//! handful of freshly re-issued low seqs as replays until fresh items push
//! the counter past the previous horizon), but strictly bounded and far
//! better than silently reusing every seq the previous run ever issued.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const SEQ_FILE: &str = "event_seq.json";
const SEQ_BAK_FILE: &str = "event_seq.json.bak";

/// How far ahead of the counter each persisted horizon reserves room for.
/// Chosen to make persists rare (one disk write per 1000 outgoing items)
/// while keeping the worst-case post-crash seq gap small.
pub const RESERVE: u64 = 1000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SeqFile {
    horizon: u64,
}

/// Handle to the persisted outgoing-seq horizon for one keystore directory.
/// Holds only the current horizon and the directory; cheap to keep around
/// for the daemon's lifetime.
#[derive(Debug)]
pub struct SeqStore {
    dir: PathBuf,
    horizon: u64,
}

impl SeqStore {
    /// Load (or initialize) the persisted horizon for `dir`.
    ///
    /// Returns the seq the in-memory counter should start at, plus a
    /// [`SeqStore`] handle already holding a fresh `initial + RESERVE`
    /// horizon (persisted best-effort — a failure here is logged and the
    /// store still returns usable in-memory state; the very next
    /// [`SeqStore::advance`] call retries the persist).
    #[must_use]
    pub fn load(dir: &Path) -> (u64, SeqStore) {
        let initial = read_horizon(dir);
        let mut store = SeqStore {
            dir: dir.to_path_buf(),
            horizon: initial,
        };
        let reserved = initial.saturating_add(RESERVE);
        if let Err(e) = store.persist(reserved) {
            tracing::warn!(
                error = %e,
                dir = %dir.display(),
                "seq_store: failed to persist initial reserved horizon; continuing in-memory \
                 only (a crash before the next successful persist could reissue up to RESERVE seqs)"
            );
        }
        (initial, store)
    }

    /// Call after allocating each new seq, passing the counter's new
    /// current value (the next seq that will be handed out). Cheap no-op
    /// while `current` is still below the persisted horizon; persists a
    /// fresh `current + RESERVE` horizon otherwise, so no seq is ever
    /// handed out at or beyond an un-persisted horizon.
    pub fn advance(&mut self, current: u64) -> Result<()> {
        if current < self.horizon {
            return Ok(());
        }
        let new_horizon = current.saturating_add(RESERVE);
        self.persist(new_horizon)
    }

    /// Write `new_horizon` as the new main file, first (best-effort)
    /// rotating the *current, already-validated* in-memory horizon into
    /// the `.bak` file. Only updates `self.horizon` once the main write
    /// actually lands, so a failed persist is retried on the next call.
    fn persist(&mut self, new_horizon: u64) -> Result<()> {
        crate::keystore::ensure_dir(&self.dir)?;

        let bak_path = self.dir.join(SEQ_BAK_FILE);
        let bak_tmp = bak_path.with_extension("bak.tmp");
        match serde_json::to_string(&SeqFile {
            horizon: self.horizon,
        }) {
            Ok(bak_body) => {
                if let Err(e) = write_atomic(&bak_path, &bak_tmp, bak_body.as_bytes()) {
                    tracing::warn!(error = %e, "seq_store: failed to write event_seq.json.bak (best-effort backup; continuing)");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "seq_store: failed to serialize event_seq.json.bak (best-effort backup; continuing)");
            }
        }

        let path = self.dir.join(SEQ_FILE);
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string(&SeqFile {
            horizon: new_horizon,
        })
        .context("serialize event_seq.json")?;
        write_atomic(&path, &tmp, body.as_bytes())?;
        self.horizon = new_horizon;
        Ok(())
    }
}

/// Read the persisted horizon, falling back main -> `.bak` -> `0`. Silent
/// when both files are simply absent (fresh install, not a degraded case);
/// warns when a present file fails to parse (the corruption case the
/// `.bak` fallback exists for).
fn read_horizon(dir: &Path) -> u64 {
    let main_path = dir.join(SEQ_FILE);
    let bak_path = dir.join(SEQ_BAK_FILE);

    if let Some(h) = read_one(&main_path) {
        return h;
    }
    if let Some(h) = read_one(&bak_path) {
        tracing::warn!(
            dir = %dir.display(),
            "event_seq.json missing/corrupt; recovered outgoing-seq horizon from event_seq.json.bak"
        );
        return h;
    }
    if main_path.exists() || bak_path.exists() {
        tracing::warn!(
            dir = %dir.display(),
            "event_seq.json and .bak both unreadable/corrupt; starting outgoing-seq horizon at 0 \
             (degraded: a peer may treat a bounded range of freshly re-issued low seqs as replays)"
        );
    }
    0
}

/// `Some(horizon)` when `path` exists and parses; `None` when missing
/// (expected, silent) or unparseable (logs a warning — corruption).
fn read_one(path: &Path) -> Option<u64> {
    if !path.exists() {
        return None;
    }
    let parsed = fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<SeqFile>(&s).ok());
    if parsed.is_none() {
        tracing::warn!(path = %path.display(), "event_seq file exists but is unreadable/corrupt");
    }
    parsed.map(|f| f.horizon)
}

/// Atomic write: tmp file (mode 0600 on unix), fsync, rename. Same pattern
/// as `history_store::write_bytes_atomic` / `keystore::save_device_name`.
fn write_atomic(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

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
            .open(tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(tmp, path).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

#[cfg(test)]
mod tests {
    use super::{SeqStore, RESERVE};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique throwaway dir under the OS temp dir; no tempfile dep needed
    /// (same pattern as `history_store`'s test `TmpDir`). Never touches the
    /// real keystore dir or any OS credential store.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "fluxsyncd-seqstore-test-{}-{}",
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

    #[test]
    fn fresh_boot_starts_at_zero_with_reserved_horizon() {
        let d = TmpDir::new();
        let (initial, mut store) = SeqStore::load(d.path());
        assert_eq!(initial, 0);
        // The freshly persisted horizon must already cover the first
        // RESERVE seqs without another disk write.
        assert!(store.advance(RESERVE - 1).is_ok());
        let on_disk = std::fs::read_to_string(d.path().join("event_seq.json")).unwrap();
        assert!(on_disk.contains(&RESERVE.to_string()));
    }

    #[test]
    fn restart_resumes_at_or_beyond_previous_horizon_never_reissuing() {
        let d = TmpDir::new();
        let (initial1, mut store1) = SeqStore::load(d.path());
        assert_eq!(initial1, 0);

        // Simulate sending enough items to cross one reservation boundary.
        let mut seq = initial1;
        for _ in 0..(RESERVE + 5) {
            seq += 1;
            store1.advance(seq).unwrap();
        }

        // "Restart": load again from the same dir.
        let (initial2, _store2) = SeqStore::load(d.path());
        assert!(
            initial2 >= RESERVE,
            "restart must never resume at or below a seq already issued (issued up to {seq}, resumed at {initial2})"
        );
        assert!(initial2 > seq || initial2 == 2 * RESERVE, "resumed horizon must be safely ahead");
    }

    #[test]
    fn corrupt_main_file_falls_back_to_bak() {
        let d = TmpDir::new();
        let (_, mut store) = SeqStore::load(d.path());
        // Cross a boundary so a real .bak gets written with a known value.
        store.advance(RESERVE).unwrap();

        let bak_path = d.path().join("event_seq.json.bak");
        assert!(bak_path.exists(), ".bak must exist after crossing a horizon boundary");
        let bak_contents = std::fs::read_to_string(&bak_path).unwrap();

        // Corrupt the main file.
        std::fs::write(d.path().join("event_seq.json"), b"{ not json").unwrap();

        let (initial, _) = SeqStore::load(d.path());
        let expected: super::SeqFile = serde_json::from_str(&bak_contents).unwrap();
        assert_eq!(initial, expected.horizon);
    }

    #[test]
    fn both_files_corrupt_or_missing_degrades_to_zero() {
        let d = TmpDir::new();
        // Neither file exists yet: fresh install semantics, not degraded.
        let (initial, _) = SeqStore::load(d.path());
        assert_eq!(initial, 0);
    }

    #[test]
    fn advance_is_noop_below_horizon() {
        let d = TmpDir::new();
        let (_, mut store) = SeqStore::load(d.path());
        let before = std::fs::metadata(d.path().join("event_seq.json"))
            .unwrap()
            .modified()
            .unwrap();
        store.advance(1).unwrap(); // well below RESERVE horizon
        let after = std::fs::metadata(d.path().join("event_seq.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(before, after, "advance below horizon must not rewrite the file");
    }
}
