package sn.kaolack.fluxsync

import android.accessibilityservice.AccessibilityService
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.view.accessibility.AccessibilityEvent
import kotlinx.coroutines.*
import java.io.File

/**
 * The BRAIN of FluxSync on Android.
 *
 * This service is chosen as the daemon owner because it is the ONLY
 * Android component that survives the user swiping the app away from
 * Recents. When the user swipes, Android kills the process hosting
 * MainActivity and FluxsyncService, but the AccessibilityService
 * continues running in a separate process managed by the system.
 *
 * Responsibilities:
 *   1. Boot the Rust daemon (FluxsyncHandle) in onCreate()
 *   2. Track text selections across the entire OS
 *   3. Detect "Copy" button clicks and push selected text to the daemon
 *   4. Intercept Android 13+/Samsung clipboard overlay as fallback
 *   5. Ensure the FluxsyncService notification stays alive
 */
class FluxsyncAccessibilityService : AccessibilityService() {
    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job)

    private var lastSelectedText: String = ""
    private var lastLongClickedText: String = ""
    private var lastPushedText: String = ""

    private var lastSentLevel: Int = -1
    private var lastSentCharging: Boolean = false

    private var pollingJob: Job? = null

    private val batteryReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent == null) return
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            if (level < 0 || scale <= 0) return
            val pct = ((level.toDouble() / scale.toDouble()) * 100.0).toInt().coerceIn(0, 100)
            val plugged = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
            val charging = plugged != 0

            if (pct == lastSentLevel && charging == lastSentCharging) return
            lastSentLevel = pct
            lastSentCharging = charging

            scope.launch {
                FluxsyncManager.withHandle { h ->
                    try {
                        h.setSelfBattery(pct.toShort().toUByte(), charging)
                    } catch (e: Exception) {
                        android.util.Log.e("FluxSync", "Battery update failed: ${e.message}")
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        android.util.Log.i("FluxSync", "AccessibilityService.onCreate — BRAIN ONLINE")

        // Ensure the foreground notification service is running
        ensureForegroundService()

        // Boot the daemon if it's not already alive
        ensureDaemonAlive()

        // Register battery monitor
        registerReceiver(batteryReceiver, IntentFilter(Intent.ACTION_BATTERY_CHANGED))

        // FS-022 / M-AND-01: restore the persisted set of already-applied
        // content hashes so a process restart doesn't re-sync the daemon's
        // whole history. Dedup keys on hashes, not a Lamport cursor (the
        // daemon's Lamport clock resets to 0 on every daemon restart).
        seenHashes = try {
            LinkedHashSet(
                getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .getStringSet(KEY_SEEN_HASHES, emptySet()) ?: emptySet(),
            )
        } catch (e: Exception) {
            android.util.Log.w("FluxSync", "Failed to restore seen-hash set: ${e.message}")
            LinkedHashSet()
        }
    }

    /**
     * Boot the Rust daemon. This is the ONLY place where the daemon
     * should be created. FluxsyncService no longer boots it.
     */
    private fun ensureDaemonAlive() {
        val existingHandle = FluxsyncManager.getHandle()
        if (existingHandle != null) {
            android.util.Log.i("FluxSync", "Daemon already alive, restarting polling loop")
            startPolling()
            return
        }

        scope.launch {
            try {
                val ipc = File(filesDir, "fluxsync.sock").absolutePath
                val keystore = filesDir.absolutePath
                // SE-05: identity source is now a typed enum. The old API
                // accepted `keystoreDir=""` + `identitySecretB64=""` as a
                // silent "regenerate fresh keypair" sentinel that erased
                // pairings on any caller typo.
                val h = FluxsyncHandle.start(
                    peerName = formatPeerName(Build.MANUFACTURER, Build.MODEL),
                    ipcPath = ipc,
                    udpPort = 0.toUShort(),
                    identity = IdentitySource.Keystore(keystore)
                )
                FluxsyncManager.setHandle(h)
                android.util.Log.i("FluxSync", "Daemon booted successfully by AccessibilityService")

                // Start polling state for the notification + UI
                startPolling()
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Failed to boot daemon: ${e.message}")
            }
        }
    }

    private fun ensureForegroundService() {
        try {
            val intent = Intent(this, FluxsyncService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (e: Exception) {
            android.util.Log.w("FluxSync", "Could not start foreground service: ${e.message}")
        }
    }

    /** M-AND-01: content hashes already written to the system clipboard. */
    private var seenHashes: LinkedHashSet<String> = LinkedHashSet()

    private fun startPolling() {
        if (pollingJob?.isActive == true) {
            android.util.Log.i("FluxSync", "Polling loop already active, skipping")
            return
        }
        pollingJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                var linked = false
                try {
                    FluxsyncManager.withHandle { h ->
                        val raw = h.pollState()
                        if (raw.isNotEmpty()) {
                            val parsed = sn.kaolack.fluxsync.vm.DaemonState.parse(raw)
                            if (parsed != null) {
                                linked = parsed.active
                                FluxsyncManager.updateState(parsed)

                                // Reset the echo guard on disconnect so a
                                // fresh pair doesn't inherit a stale value.
                                if (parsed.peerName.isEmpty()) {
                                    FluxsyncManager.lastPeerClipText = ""
                                }

                                // Sync incoming clipboard items to system clipboard
                                if (parsed.history.isNotEmpty()) {
                                    // Process from oldest to newest to preserve order.
                                    val fresh = newRemoteItems(parsed.history, seenHashes)
                                    for (item in fresh) {
                                        if (item.kind == "image") {
                                            syncImageToSystemClipboard(item.hash)
                                        } else {
                                            syncToSystemClipboard(item.preview)
                                        }
                                        markSeen(item.hash)
                                    }
                                    // M-AND-01: persist only when the set actually grew,
                                    // so the tight poll doesn't write SharedPreferences
                                    // several times a second.
                                    if (fresh.isNotEmpty()) {
                                        persistSeenHashes()
                                    }
                                }
                            }
                        }

                        // Drain any new daemon log entries into the
                        // UI-visible flow. The FFI's `poll_logs(since)`
                        // only returns entries with seq > cursor, so this
                        // is cheap when the buffer is quiet.
                        try {
                            val newLogs = h.pollLogs(FluxsyncManager.logCursor.toULong())
                            if (newLogs.isNotEmpty()) {
                                FluxsyncManager.appendLogs(
                                    newLogs.map {
                                        sn.kaolack.fluxsync.vm.LogEntryView(
                                            seq = it.seq.toLong(),
                                            time = it.time,
                                            level = it.level,
                                            msg = it.msg,
                                            raw = it.raw,
                                        )
                                    }
                                )
                            }
                        } catch (e: Exception) {
                            android.util.Log.w("FluxSync", "Log poll error: ${e.message}")
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.w("FluxSync", "Poll error: ${e.message}")
                }
                delay(pollIntervalMs(linked))
            }
        }
    }

    /** M-AND-01: record a content hash as applied, capped + most-recent-kept. */
    private fun markSeen(hash: String) {
        if (hash.isEmpty()) return
        seenHashes.remove(hash) // re-insert so it counts as most-recent
        seenHashes.add(hash)
        while (seenHashes.size > MAX_SEEN_HASHES) {
            val it = seenHashes.iterator()
            if (it.hasNext()) {
                it.next()
                it.remove()
            }
        }
    }

    /** M-AND-01: persist the seen-hash set across process restarts. */
    private fun persistSeenHashes() {
        try {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putStringSet(KEY_SEEN_HASHES, HashSet(seenHashes))
                .apply()
        } catch (e: Exception) {
            android.util.Log.w("FluxSync", "Failed to persist seen-hash set: ${e.message}")
        }
    }

    private fun syncToSystemClipboard(text: String) {
        scope.launch(Dispatchers.Main) {
            try {
                // Important: Mark this as a peer item BEFORE writing to OS clipboard
                // so MainActivity's clipListener ignores the event and doesn't echo it.
                FluxsyncManager.lastPeerClipText = text.trim()

                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = android.content.ClipData.newPlainText("FluxSync", text)
                clipboard.setPrimaryClip(clip)
                android.util.Log.i("FluxSync", "✅ CLIPBOARD SYNCED: [${text.take(30)}...]")
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Failed to write to system clipboard: ${e.message}")
            }
        }
    }

    /**
     * Write an inbound peer image to the OS clipboard. The daemon keeps
     * binary out of the state JSON, so the bytes are pulled on demand via
     * the `fetch_item` FFI keyed by the history row's content hash. Android
     * forbids raw bytes on the clipboard, so the PNG is staged in the app
     * cache and shared as a `content://` URI through this app's
     * FileProvider — MainActivity's clip listener recognises that authority
     * and skips the echo.
     */
    private fun syncImageToSystemClipboard(hash: String) {
        if (hash.isEmpty()) {
            android.util.Log.w("FluxSync", "Image history row carries no hash; cannot fetch")
            return
        }
        scope.launch {
            try {
                val png = FluxsyncManager.withHandle { it.fetchItem(hash) }
                if (png == null || png.isEmpty()) {
                    android.util.Log.w("FluxSync", "fetchItem returned no bytes for $hash")
                    return@launch
                }
                val dir = File(cacheDir, "images").apply { mkdirs() }
                val file = File(dir, "clip.png")
                file.writeBytes(png)
                val uri = androidx.core.content.FileProvider.getUriForFile(
                    this@FluxsyncAccessibilityService,
                    "$packageName.fileprovider",
                    file,
                )
                withContext(Dispatchers.Main) {
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = android.content.ClipData.newUri(contentResolver, "FluxSync", uri)
                    clipboard.setPrimaryClip(clip)
                    android.util.Log.i("FluxSync", "✅ IMAGE SYNCED: ${png.size} B")
                }
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Failed to write image to clipboard: ${e.message}")
            }
        }
    }

    // ── Accessibility Event Processing ──────────────────────────────

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        // Ensure daemon is alive on every event (self-healing)
        if (FluxsyncManager.getHandle() == null) {
            ensureDaemonAlive()
        }

        try {
            when (event.eventType) {
                AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED -> {
                    // Track ALL text selections across the entire OS.
                    // This event is NOW delivered because we added
                    // typeViewTextSelectionChanged to the XML config.
                    val text = event.text?.joinToString("") ?: ""
                    if (text.isNotEmpty() && text.length > 1) {
                        lastSelectedText = text
                    }
                }
                AccessibilityEvent.TYPE_VIEW_LONG_CLICKED -> {
                    // Track long clicks for URLs/images in browsers
                    val node = event.source
                    if (node != null) {
                        val text = node.text?.toString() ?: node.contentDescription?.toString() ?: ""
                        if (text.isNotEmpty()) {
                            lastLongClickedText = text
                        }
                    }
                }
                AccessibilityEvent.TYPE_VIEW_CLICKED -> {
                    // Detect "Copy" button clicks in context menus
                    val nodeText = event.text?.joinToString("")?.lowercase() ?: ""
                    val contentDesc = event.contentDescription?.toString()?.lowercase() ?: ""

                    val isCopyAction = nodeText.contains("copy") ||
                                     nodeText.contains("copier") ||
                                     contentDesc.contains("copy") ||
                                     contentDesc.contains("copier")

                    if (isCopyAction) {
                        android.util.Log.i("FluxSync", "Copy click detected! nodeText='$nodeText' desc='$contentDesc'")
                        // Priority 1: Selected text
                        if (lastSelectedText.isNotEmpty()) {
                            pushTextToDaemon(lastSelectedText)
                            lastSelectedText = ""
                        }
                        // Priority 2: Long-clicked element (e.g. a link)
                        else if (lastLongClickedText.isNotEmpty()) {
                            pushTextToDaemon(lastLongClickedText)
                            lastLongClickedText = ""
                        }
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("FluxSync", "Error in event processing: ${e.message}")
        }
    }


    // ── Push to Daemon ─────────────────────────────────────────────

    private fun pushTextToDaemon(text: String) {
        if (text == lastPushedText) return
        lastPushedText = text

        scope.launch {
            // ✅ REMEDIATION: Acquire lock INSIDE coroutine to prevent Use-After-Free
            FluxsyncManager.withHandle { handle ->
                try {
                    handle.pushText(text)
                    android.util.Log.i("FluxSync", "Pushed text to daemon: ${text.take(30)}...")
                } catch (e: Exception) {
                    android.util.Log.e("FluxSync", "FFI push error: ${e.message}")
                    FluxsyncManager.reportError("Clipboard sync failed: ${e.message}")
                }
            } ?: run {
                android.util.Log.w("FluxSync", "Push failed: daemon handle is null")
                ensureDaemonAlive()
            }
        }
    }

    override fun onInterrupt() {}

    companion object {
        /** FS-022 / M-AND-01: SharedPreferences store for inbound dedup. */
        private const val PREFS_NAME = "fluxsync_prefs"
        private const val KEY_SEEN_HASHES = "seen_hashes"

        /** Cap on remembered inbound hashes — bounds the persisted set. */
        private const val MAX_SEEN_HASHES = 256

        /**
         * M-AND-01: remote history items not yet applied to the system
         * clipboard, oldest-first. [history] is the daemon snapshot,
         * newest-first. Dedup keys on the content [HistoryItem.hash], NOT a
         * Lamport threshold: the daemon's Lamport clock restarts at 0 on every
         * daemon restart, so a `lamport <= cursor` gate silently stopped ALL
         * inbound sync until the clock climbed back past the old cursor. A
         * seen-hash set is also immune to out-of-order arrival (two peers /
         * retransmits), which the old descending-Lamport `break` assumed away.
         */
        @JvmStatic
        fun newRemoteItems(
            history: List<sn.kaolack.fluxsync.vm.HistoryItem>,
            seen: Set<String>,
        ): List<sn.kaolack.fluxsync.vm.HistoryItem> {
            return history
                .filter { it.source == "remote" && it.hash.isNotEmpty() && it.hash !in seen }
                .reversed()
        }

        /**
         * Adaptive FFI poll cadence (FS-011). Tight 200ms while a peer is
         * linked — clipboard latency is user-visible — but relaxed to 2s when
         * idle so a backgrounded, disconnected app stops burning battery on
         * 10 FFI reads per second.
         */
        @JvmStatic
        fun pollIntervalMs(active: Boolean): Long = if (active) 200L else 2000L

        /**
         * FS-019: human-readable peer name from the device build fields.
         * `Build.MODEL` alone is a cryptic code ("SM-G998B"); prefixing the
         * manufacturer ("Samsung SM-G998B") makes it recognisable on the
         * paired Mac. Falls back to "Android" when both fields are missing.
         */
        @JvmStatic
        fun formatPeerName(manufacturer: String?, model: String?): String {
            val brand = manufacturer.orEmpty().trim()
                .replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
            val name = "$brand ${model.orEmpty().trim()}".trim()
            return name.ifEmpty { "Android" }
        }

        /** FS-013: upper bound for the blocking daemon stop in onDestroy. */
        private const val STOP_TIMEOUT_MS = 2000L

        /**
         * FS-013: run a blocking daemon stop under a hard deadline so
         * onDestroy can never ANR. Returns true if [stop] completed within
         * [timeoutMs], false if it timed out (the runtime is then left to
         * the dying process to reclaim).
         */
        @JvmStatic
        suspend fun stopWithinTimeout(timeoutMs: Long, stop: suspend () -> Unit): Boolean =
            withTimeoutOrNull(timeoutMs) {
                stop()
                true
            } ?: false
    }

    override fun onDestroy() {
        // AccessibilityService should NEVER be destroyed by the system
        // under normal circumstances. But if it is, clean up.
        android.util.Log.w("FluxSync", "AccessibilityService.onDestroy — BRAIN OFFLINE")

        // FS-013: cancel polling FIRST so no loop iteration is parked inside
        // withHandle holding handleLock, then stop the daemon OUTSIDE the
        // lock under a bounded timeout. handle.stop() is a blocking FFI call
        // and onDestroy runs on the main thread — an unbounded stop ANRs.
        pollingJob?.cancel()
        val handle = FluxsyncManager.getHandle()
        FluxsyncManager.setHandle(null)
        runBlocking {
            pollingJob?.join()
            if (handle != null) {
                val stopped = stopWithinTimeout(STOP_TIMEOUT_MS) {
                    withContext(Dispatchers.IO) {
                        try {
                            handle.stop()
                        } catch (e: Exception) {
                            android.util.Log.e("FluxSync", "Error stopping daemon: ${e.message}")
                        }
                    }
                }
                if (!stopped) {
                    android.util.Log.w("FluxSync", "Daemon stop timed out after ${STOP_TIMEOUT_MS}ms")
                }
            }
        }

        try {
            unregisterReceiver(batteryReceiver)
        } catch (_: Exception) {}
        job.cancel()
        super.onDestroy()
    }
}
