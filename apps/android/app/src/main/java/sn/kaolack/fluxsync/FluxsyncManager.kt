package sn.kaolack.fluxsync

import android.os.SystemClock
import sn.kaolack.fluxsync.vm.DaemonState
import sn.kaolack.fluxsync.vm.LogEntryView
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicLong

object FluxsyncManager {
    private const val LOG_VIEW_CAP = 200

    private val handleLock = Object()
    private var handle: FluxsyncHandle? = null
    private val _state = MutableStateFlow<DaemonState?>(null)
    val state = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<LogEntryView>>(emptyList())
    val logs = _logs.asStateFlow()

    /**
     * Highest log seq the polling loop has merged so far. Stored as the
     * cursor for the next `FluxsyncHandle.pollLogs` call. Backed by an
     * AtomicLong: the merge in [appendLogs] is a read-modify-write, so a
     * plain @Volatile field could lose a concurrent update and let the
     * cursor regress, causing already-seen entries to be re-delivered.
     */
    private val _logCursor = AtomicLong(0L)
    val logCursor: Long get() = _logCursor.get()

    /**
     * How long after we write or push a text a repeat of it still counts as
     * an echo: a clip listener reading back our own peer write, or the a11y
     * "Copy" detector and a clip listener both seeing one copy. Real echoes
     * land within a second or two; anything later is the user copying that
     * text again, which must sync (copy A, copy B, copy A sends A twice).
     * Mirrors `fluxsync_core::ECHO_WINDOW_MS`.
     */
    internal const val ECHO_WINDOW_MS = 5_000L

    /**
     * #6 echo guard: trimmed texts recently written to the system clipboard
     * BY US (inbound peer items), each with the elapsedRealtime of the write.
     * A bounded recency map, not a single @Volatile string — two peer items
     * landing back-to-back must BOTH stay suppressed, and the older one can't
     * be forgotten the instant the newer one arrives. Written by the a11y poll
     * loop (IO), read by MainActivity's clip listener (Main) → its own monitor.
     */
    private const val PEER_CLIP_CAP = 16
    private val peerClipLock = Any()
    private val peerClips = LinkedHashMap<String, Long>()

    fun rememberPeerClip(text: String, nowMs: Long = SystemClock.elapsedRealtime()) {
        val key = text.trim()
        if (key.isEmpty()) return
        synchronized(peerClipLock) { record(peerClips, key, nowMs, PEER_CLIP_CAP) }
    }

    /** True only within [ECHO_WINDOW_MS] of writing [text] from a peer. */
    fun isRecentPeerClip(text: String, nowMs: Long = SystemClock.elapsedRealtime()): Boolean {
        val key = text.trim()
        if (key.isEmpty()) return false
        return synchronized(peerClipLock) { isEcho(peerClips[key], nowMs) }
    }

    /** Drop the echo guard on disconnect so a fresh pair starts clean. */
    fun clearPeerClips() {
        synchronized(peerClipLock) { peerClips.clear() }
    }

    /**
     * #5 outbound dedup: trimmed texts recently pushed to the daemon, each
     * with the elapsedRealtime of the push. The a11y "Copy"-button detector
     * and the clip listeners all run in this one process; without a shared
     * window a single copy fires two pushes. [markPushedIfNew] is an atomic
     * check-and-set: true means "newly recorded, caller should push", false
     * means "pushed less than [ECHO_WINDOW_MS] ago, skip".
     */
    private const val PUSHED_CLIP_CAP = 16
    private val pushedClipLock = Any()
    private val pushedClips = LinkedHashMap<String, Long>()

    fun markPushedIfNew(text: String, nowMs: Long = SystemClock.elapsedRealtime()): Boolean {
        val key = text.trim()
        if (key.isEmpty()) return false
        synchronized(pushedClipLock) {
            if (isEcho(pushedClips[key], nowMs)) return false
            record(pushedClips, key, nowMs, PUSHED_CLIP_CAP)
            return true
        }
    }

    /**
     * MainActivity.onResume's re-push gate. onResume is not a copy event: it
     * fires on every app open, and the clipboard usually still holds what we
     * last pushed or wrote from a peer, so re-sending it clobbers the peer
     * with an old clip each time. Unlike the clip listeners, this skips any
     * text either guard still remembers, however old; only text FluxSync
     * hasn't handled is recorded (as [markPushedIfNew] would) and pushed.
     */
    fun markResumePushIfNew(text: String, nowMs: Long = SystemClock.elapsedRealtime()): Boolean {
        val key = text.trim()
        if (key.isEmpty()) return false
        if (synchronized(peerClipLock) { key in peerClips }) return false
        synchronized(pushedClipLock) {
            if (key in pushedClips) return false
            record(pushedClips, key, nowMs, PUSHED_CLIP_CAP)
            return true
        }
    }

    fun clearPushedClips() {
        synchronized(pushedClipLock) { pushedClips.clear() }
    }

    private fun isEcho(seenAtMs: Long?, nowMs: Long): Boolean =
        seenAtMs != null && nowMs - seenAtMs < ECHO_WINDOW_MS

    /** Store [key] as the newest entry, then drop the oldest past [cap]. */
    private fun record(map: LinkedHashMap<String, Long>, key: String, nowMs: Long, cap: Int) {
        map.remove(key) // re-insert so it counts as most-recent
        map[key] = nowMs
        while (map.size > cap) {
            val it = map.keys.iterator()
            it.next()
            it.remove()
        }
    }

    /**
     * FS-018: last transient FFI/daemon error, surfaced to the user as a
     * Snackbar by FluxsyncApp. Distinct from the ViewModel's fatal `error`
     * flow — this one is dismissible and auto-clears after display.
     */
    private val _lastError = MutableStateFlow<String?>(null)
    val lastError = _lastError.asStateFlow()

    fun reportError(msg: String) {
        _lastError.value = msg
    }

    fun clearError() {
        _lastError.value = null
    }

    /**
     * True once the AccessibilityService found an `identity.enc` on disk
     * that it could not decrypt (corrupted file, or an AndroidKeyStore key
     * that didn't survive a factory-reset/restore-to-new-device) and
     * therefore refused to boot the daemon with a freshly-generated
     * identity, which would silently orphan every paired peer. Unlike
     * [lastError] this is sticky — not auto-cleared on display — because
     * the only correct fix is the user noticing and deliberately clearing
     * app data / re-pairing, not dismissing a toast.
     */
    private val _identityUnreadable = MutableStateFlow(false)
    val identityUnreadable = _identityUnreadable.asStateFlow()

    fun reportIdentityUnreadable() {
        _identityUnreadable.value = true
    }

    fun setHandle(h: FluxsyncHandle?) {
        synchronized(handleLock) {
            handle = h
        }
    }

    fun getHandle(): FluxsyncHandle? {
        synchronized(handleLock) {
            return handle
        }
    }

    /**
     * Safe access to handle with guaranteed locking during operation.
     * If handle is null or becomes null, block is not executed.
     */
    fun <T> withHandle(block: (FluxsyncHandle) -> T): T? {
        synchronized(handleLock) {
            return handle?.let(block)
        }
    }

    fun updateState(s: DaemonState) {
        _state.value = s
    }

    /**
     * Merge a batch of log entries (newest first or oldest first — order
     * preserved as supplied) into the bounded log flow. Trims to
     * [LOG_VIEW_CAP] retained entries so a chatty daemon can't bloat the
     * UI's heap.
     */
    fun appendLogs(entries: List<LogEntryView>) {
        if (entries.isEmpty()) return
        _logs.update { prev ->
            val merged = prev + entries
            if (merged.size > LOG_VIEW_CAP) merged.takeLast(LOG_VIEW_CAP) else merged
        }
        val maxSeq = entries.maxOf { it.seq }
        _logCursor.accumulateAndGet(maxSeq) { current, candidate -> maxOf(current, candidate) }
    }

    /** Reset all mutable state. Test-only — this is a process-wide singleton. */
    internal fun resetForTesting() {
        _state.value = null
        _logs.value = emptyList()
        _logCursor.set(0L)
        _lastError.value = null
        _identityUnreadable.value = false
        clearPeerClips()
        clearPushedClips()
    }
}
