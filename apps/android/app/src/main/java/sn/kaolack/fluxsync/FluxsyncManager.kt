package sn.kaolack.fluxsync

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
     * Text most recently written to the system clipboard BY US (from peer).
     * Used to prevent the MainActivity clipListener from echoing it back.
     */
    @Volatile
    var lastPeerClipText: String = ""

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
        lastPeerClipText = ""
    }
}
