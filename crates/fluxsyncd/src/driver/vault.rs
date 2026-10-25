//! FluxVault persister: mirrors in-memory history to the encrypted vault.

use super::*;

/// State the FluxVault persister carries between writes: where + how to
/// encrypt, plus a cache so a re-persist preserves each entry's original
/// `created_ms` (and favorite flag) instead of re-stamping it `now`.
pub(super) struct VaultCtx {
    pub(super) dir: PathBuf,
    pub(super) key: zeroize::Zeroizing<[u8; 32]>,
    /// The history list as last persisted — change detection.
    pub(super) last: Vec<HistoryItem>,
    /// The entries as last persisted — source of stable `created_ms`.
    pub(super) entries: Vec<VaultEntry>,
}

impl VaultCtx {
    /// Map the current in-memory history (newest-first) to vault entries,
    /// carrying each entry's original `created_ms` forward (matched on the
    /// stable hash+lamport key, so toggling `favorite` doesn't reset its TTL)
    /// and stamping freshly-seen items with `now`. Favorited entries that
    /// scrolled out of the in-memory window are re-appended so they survive in
    /// the vault (favorites are exempt from the cap + TTL).
    pub(super) fn rebuild(&self, history: &[HistoryItem], now: u64) -> Vec<VaultEntry> {
        let stable = |a: &HistoryItem, b: &HistoryItem| a.hash == b.hash && a.lamport == b.lamport;
        let mut out: Vec<VaultEntry> = history
            .iter()
            .map(|item| {
                let created_ms = self
                    .entries
                    .iter()
                    .find(|e| stable(&e.item, item))
                    .map_or(now, |prev| prev.created_ms);
                VaultEntry {
                    item: item.clone(),
                    created_ms,
                }
            })
            .collect();
        for e in &self.entries {
            if e.item.favorite && !history.iter().any(|h| stable(h, &e.item)) {
                out.push(e.clone());
            }
        }
        out
    }
}

/// One persist attempt: mirror a security wipe to disk if `wipe_gen`
/// advanced past `*last_wipe_gen`, then save `history` if it differs from
/// what's already persisted (`ctx.last`). Factored out of
/// `run_vault_persister` so the exact same logic can also run once more,
/// synchronously, during a graceful shutdown — see the final flush at the
/// end of that function.
pub(super) async fn persist_history_change(
    ctx: &mut VaultCtx,
    last_wipe_gen: &mut u64,
    history: Vec<HistoryItem>,
    wipe_gen: u64,
    disc_cache: &DiscoveryCache,
    backoff: &BackoffMap,
) {
    // A security wipe (untrusted-peer, ghost-timeout, peer-swap) cleared
    // the in-memory history for safety; mirror it on disk. Delete the
    // encrypted vault and forget cached favorites so a pinned secret can't
    // be re-appended by rebuild() and the file can't outlive the wipe.
    //
    // FIX3: this is now belt-and-braces. The main event loop (see the
    // `vault_wipe_gen` before/after check around `Some(event) =
    // event_rx.recv()` in `run()`) already performs this exact disk clear
    // SYNCHRONOUSLY, inline, before the wiping event's new state is even
    // published to subscribers — this async path only re-runs the same
    // (idempotent) clear as a backstop. CORRECTION to a previous version of
    // this comment: a crash landing in the gap between the in-memory wipe
    // and either clear reaching disk is NOT auto-healed on the next boot —
    // boot only loads+restores whatever `history.enc` exists (see `run()`'s
    // vault rehydrate, well before `initial_wipe_gen` is even seeded) and
    // never re-wipes it, so a stray file from that gap survives until some
    // later, unrelated wipe trigger clears it. Residual, low-severity (the
    // user's own secret, on the user's own device), and now far less likely
    // to matter thanks to the synchronous path above.
    if wipe_gen != *last_wipe_gen {
        ctx.entries.clear();
        // DIR-P2-04a: a security wipe means this peer relationship is no
        // longer trusted; the mDNS discovery cache still holds its
        // pubkey, name, addrs, and pairing PIN from before the wipe.
        // Purge it too — eagerly, since an in-memory clear cannot fail,
        // rather than gating it on the disk clear below.
        disc_cache.lock().await.clear();
        // DIR-P1-02: same rationale — drop every peer's backoff timer.
        backoff.lock().await.clear();
        let dir = ctx.dir.clone();
        match tokio::task::spawn_blocking(move || history_store::clear(&dir)).await {
            // Only advance past this generation once the file is actually
            // gone; on failure keep last_wipe_gen so the next state publish
            // re-attempts the clear instead of permanently losing the wipe.
            Ok(Ok(())) => *last_wipe_gen = wipe_gen,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "vault security wipe failed; will retry on next change");
            }
            Err(e) => {
                tracing::warn!(error = %e, "vault security wipe task join failed; will retry on next change");
            }
        }
        // Force the post-wipe history (empty, or freshly-started for a
        // peer-swap) to be re-persisted below instead of short-circuiting.
        ctx.last = Vec::new();
    }
    if history == ctx.last {
        return;
    }
    let now = now_ms();
    let entries = ctx.rebuild(&history, now);
    let dir = ctx.dir.clone();
    let key = *ctx.key;
    let to_save = entries.clone();
    let saved = tokio::task::spawn_blocking(move || {
        history_store::save(
            &dir,
            &key,
            &to_save,
            now,
            history_store::DEFAULT_TTL_SECS,
            history_store::DEFAULT_DISK_CAP,
        )
    })
    .await;
    match saved {
        Ok(Ok(())) => {
            ctx.entries = entries;
            ctx.last = history;
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "vault persist failed"),
        Err(e) => tracing::warn!(error = %e, "vault persist task join failed"),
    }
}

/// Persist clipboard history whenever it changes. Wakes on every state
/// publish, skips when the history list is unchanged, and writes the
/// encrypted vault off-thread (`spawn_blocking`) so the fsync never stalls
/// a runtime worker.
///
/// DEFECT 2 fix (resync-1 "every launch" loop): this task used to be a bare
/// detached `tokio::spawn`, not tracked in `run()`'s `JoinSet`, so a
/// graceful shutdown could return — and the process could exit — before the
/// LAST history change (e.g. a resync-1 delivery landing right after Hello)
/// had actually reached disk. The next boot's vault load would then miss
/// that item, `missing_resync_hashes` would call it missing again, and the
/// daemon would re-`ResyncPull` it on every subsequent relaunch forever.
/// Now this task is spawned into the tracked `JoinSet` and also selects on
/// `shutdown`, so `run()`'s `while tasks.join_next().await.is_some() {}`
/// genuinely waits for the final flush below before the caller can exit.
pub(super) async fn run_vault_persister(
    mut ctx: VaultCtx,
    mut rx: watch::Receiver<State>,
    initial_wipe_gen: u64,
    disc_cache: DiscoveryCache,
    backoff: BackoffMap,
    shutdown: CancellationToken,
) {
    // Baseline is seeded from the CONSTRUCTION snapshot, not a late
    // `rx.borrow()`: a security wipe that lands between `subscribe()` and the
    // first poll would otherwise be adopted as the baseline, so `rx.changed()`
    // would never observe it and the disk clear would be skipped while
    // ctx.entries still holds the favorite (which rebuild() would resurrect).
    let mut last_wipe_gen = initial_wipe_gen;
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            changed = rx.changed() => {
                if changed.is_err() {
                    // All senders dropped — the driver already tore down
                    // without going through the shutdown token (e.g. a test
                    // harness that just drops its `watch::Sender`). Nothing
                    // left to observe; exit exactly like the old `while
                    // rx.changed().await.is_ok()` loop did, with no extra
                    // final-flush attempt (there is no fresher state to read).
                    return;
                }
            }
        }
        let (history, wipe_gen) = {
            let snap = rx.borrow_and_update();
            // Heartbeats re-publish State every few seconds with the history
            // untouched. This is exactly `persist_history_change`'s own
            // early return (no new wipe generation, same list as on disk),
            // checked before cloning every item's full text.
            if snap.vault_wipe_gen == last_wipe_gen && snap.history == ctx.last {
                continue;
            }
            (snap.history.clone(), snap.vault_wipe_gen)
        };
        persist_history_change(
            &mut ctx,
            &mut last_wipe_gen,
            history,
            wipe_gen,
            &disc_cache,
            &backoff,
        )
        .await;
    }
    // Final flush: `shutdown` fired. The daemon may have published one more
    // history change in the same instant as the cancellation, with no
    // guarantee this task's last loop iteration observed it before
    // `shutdown.cancelled()` won the `tokio::select!` race — `rx.changed()`
    // is edge-triggered, not level-triggered, so a change that arrives and
    // is immediately followed by cancellation can otherwise be lost. Read
    // the CURRENT state directly (`borrow`, not `changed`) and persist it if
    // it differs from what's already on disk.
    let (history, wipe_gen) = {
        let snap = rx.borrow();
        (snap.history.clone(), snap.vault_wipe_gen)
    };
    persist_history_change(
        &mut ctx,
        &mut last_wipe_gen,
        history,
        wipe_gen,
        &disc_cache,
        &backoff,
    )
    .await;
}
