package sn.kaolack.fluxsync

import android.accessibilityservice.AccessibilityService
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
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
 *   2. Capture local copies — text AND image — via a system clipboard
 *      listener. A connected AccessibilityService is exempt from Android's
 *      background clipboard-read restriction, so this fires for every copy
 *      regardless of locale, icon-only "copy" buttons, or whether a FluxSync
 *      window is focused. This is the real background-capture path.
 *   3. Detect "Copy" button clicks as a secondary fallback that pushes the
 *      selected text (covers the rare case a copy never reaches the clipboard).
 *   4. Push captured items to the daemon
 *   5. Ensure the FluxsyncService notification stays alive
 */
class FluxsyncAccessibilityService : AccessibilityService() {
    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job)

    private var lastSelectedText: String = ""
    private var lastLongClickedText: String = ""

    private lateinit var clipboard: ClipboardManager
    private var clipListenerRegistered = false
    private val clipListener = ClipboardManager.OnPrimaryClipChangedListener { handleLocalClipChange() }

    private var lastSentLevel: Int = -1
    private var lastSentCharging: Boolean = false

    private var pollingJob: Job? = null

    /** Tracks the peer link across polls so an empty→active edge can seed the guards. */
    private var peerWasActive = false

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
            scope.launch { pushSelfBattery(pct, charging) }
        }
    }

    /**
     * Pushes a self-battery reading to the daemon, updating the dedup guard
     * ONLY after a confirmed write. `withHandle` returns null during the
     * ~1.5s daemon-boot window, so the very first (sticky) BATTERY_CHANGED
     * would otherwise be consumed-then-lost: the guard was advanced before
     * the failed push and the same value never retried until the battery
     * actually changed. Retrying across the boot window guarantees the peer
     * (and this phone's own pill) get a real reading promptly instead of the
     * 255 "—" placeholder.
     */
    private suspend fun pushSelfBattery(pct: Int, charging: Boolean) {
        repeat(10) {
            val ok = FluxsyncManager.withHandle { h ->
                try {
                    h.setSelfBattery(pct.toShort().toUByte(), charging)
                    true
                } catch (e: Exception) {
                    android.util.Log.e("FluxSync", "Battery update failed: ${e.message}")
                    false
                }
            }
            if (ok == true) {
                lastSentLevel = pct
                lastSentCharging = charging
                return
            }
            kotlinx.coroutines.delay(1000)
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

    override fun onServiceConnected() {
        super.onServiceConnected()
        // Now connected → the app counts as an enabled AccessibilityService,
        // which Android exempts from the background clipboard-read restriction.
        // A primary-clip listener therefore captures local copies (text AND
        // image) even with no FluxSync window focused — the real background
        // capture path. Guarded so a re-connect can't stack two listeners.
        if (clipListenerRegistered) return
        try {
            clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.addPrimaryClipChangedListener(clipListener)
            clipListenerRegistered = true
        } catch (e: Exception) {
            android.util.Log.w("FluxSync", "Clipboard listener registration failed: ${e.message}")
        }
    }

    /**
     * #1/#2: capture a LOCAL copy straight off the system clipboard. Reached
     * only while the service is connected (background clipboard-read
     * exemption), so it handles every locale and icon-only "copy" button the
     * TYPE_VIEW_CLICKED text heuristic misses, plus images the heuristic can't
     * see at all.
     */
    private fun handleLocalClipChange() {
        val clip = try {
            clipboard.primaryClip
        } catch (e: Exception) {
            android.util.Log.w("FluxSync", "Clipboard read failed: ${e.message}")
            null
        } ?: return
        if (clip.itemCount == 0) return
        val item = clip.getItemAt(0)

        // Image first: coerceToText on an image item returns the URI string.
        if (clip.description?.hasMimeType("image/*") == true && item.uri != null) {
            val uri = item.uri
            // Our own inbound peer images are staged via this app's
            // FileProvider; a matching authority means this is an echo.
            if (uri.authority == "$packageName.fileprovider") return
            scope.launch {
                val png = readClipboardImageAsPng(uri) ?: return@launch
                FluxsyncManager.withHandle { it.pushItem("image", png) }
                    ?: android.util.Log.w("FluxSync", "Image push failed: handle null")
            }
            return
        }

        val text = item.coerceToText(this)?.toString() ?: return
        if (text.isEmpty()) return
        // #6 echo guard: never bounce a peer item we just wrote back to it.
        if (FluxsyncManager.isRecentPeerClip(text)) return
        // pushTextToDaemon applies the #5 shared-dedup gate.
        pushTextToDaemon(text)
    }

    /**
     * Decode a clipboard image URI and re-encode as PNG (the phase-1 image
     * wire format). Returns null on decode failure or if it exceeds the
     * daemon's payload cap. Runs off the main thread by its caller.
     */
    private fun readClipboardImageAsPng(uri: Uri): ByteArray? = try {
        val bitmap = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it) }
        when {
            bitmap == null -> {
                android.util.Log.w("FluxSync", "Clipboard image decode failed: $uri")
                null
            }
            else -> {
                val out = java.io.ByteArrayOutputStream()
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                val bytes = out.toByteArray()
                if (bytes.size > MAX_IMAGE_BYTES) {
                    android.util.Log.w("FluxSync", "Clipboard image ${bytes.size}B over cap, skipping")
                    null
                } else {
                    bytes
                }
            }
        }
    } catch (e: Exception) {
        android.util.Log.w("FluxSync", "Clipboard image read error: ${e.message}")
        null
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
                //
                // DIR-P2-02: the secret itself is decrypted here from an
                // AndroidKeyStore-backed key (KeystoreIdentityStore) and
                // handed to the FFI as raw bytes via IdentitySource.Provided
                // — the daemon's Rust keystore module has no Android
                // backend for its usual OS-keychain path (the `keyring`
                // crate doesn't support Android), so it used to fall back
                // to a plaintext identity.bin. If AndroidKeyStore itself is
                // broken on this device, fall back to that legacy plaintext
                // path with a loud log rather than failing to boot at all.
                val secret = KeystoreIdentityStore.readOrMigrate(filesDir)
                val identity = if (secret != null) {
                    IdentitySource.Provided(secret = secret, dir = keystore)
                } else {
                    android.util.Log.w(
                        "FluxSync",
                        "AndroidKeyStore identity path unavailable; falling back to plaintext identity.bin",
                    )
                    IdentitySource.Keystore(keystore)
                }
                val h = try {
                    FluxsyncHandle.start(
                        peerName = formatPeerName(Build.MANUFACTURER, Build.MODEL),
                        ipcPath = ipc,
                        udpPort = 0.toUShort(),
                        identity = identity
                    )
                } finally {
                    // Best-effort: the FFI call has already copied the
                    // bytes across to Rust by the time this runs. The JVM
                    // may hold other internal copies (array growth, GC
                    // compaction) this can't reach.
                    secret?.fill(0)
                }
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
                // DIR-P3-07: heartbeat for MainActivity's self-check banner —
                // reuses this already-running loop instead of adding a new
                // timer. See ServiceHealthUtils.isServiceDead.
                lastHeartbeatMs = System.currentTimeMillis()
                var linked = false
                try {
                    // Snapshot under the handle lock, then release it BEFORE the
                    // clipboard writes — those hop to Dispatchers.Main and must
                    // not park a Main-thread write while holding handleLock.
                    val parsed = FluxsyncManager.withHandle { h ->
                        val raw = h.pollState()
                        val state = if (raw.isNotEmpty()) {
                            sn.kaolack.fluxsync.vm.DaemonState.parse(raw)
                        } else {
                            null
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
                        state
                    }

                    if (parsed != null) {
                        linked = parsed.active
                        FluxsyncManager.updateState(parsed)

                        // Session-seed guard (mirrors fluxsyncd driver.rs:2392).
                        // On a fresh peer link, record whatever is already on the
                        // OS clipboard as "known" so a value left over from a
                        // previous session — e.g. the last inbound peer item still
                        // sitting on the clipboard — is NOT bounced back to the new
                        // peer by the clip listener or an onResume re-push. Without
                        // it, clearing the echo guard on disconnect let a stale
                        // remote value resurface on the peer at reconnect.
                        val peerActive = parsed.peerName.isNotEmpty()
                        if (!peerActive) {
                            FluxsyncManager.clearPeerClips()
                        } else if (!peerWasActive) {
                            seedGuardsFromClipboard()
                        }
                        peerWasActive = peerActive

                        // Sync incoming clipboard items to the system clipboard.
                        if (parsed.history.isNotEmpty()) {
                            // Oldest to newest to preserve order.
                            val fresh = newRemoteItems(parsed.history, seenHashes)
                            var grew = false
                            for (item in fresh) {
                                // #7: mark the hash seen ONLY after the write
                                // actually lands. A thrown setPrimaryClip used
                                // to mark-then-lose the item with no retry.
                                val ok = if (item.kind == "image") {
                                    syncImageToSystemClipboard(item.hash)
                                } else {
                                    syncToSystemClipboard(item.preview)
                                }
                                if (ok) {
                                    markSeen(item.hash)
                                    grew = true
                                }
                            }
                            // M-AND-01: persist only when the set actually grew,
                            // so the tight poll doesn't write SharedPreferences
                            // several times a second.
                            if (grew) {
                                persistSeenHashes()
                            }
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

    /**
     * Session-seed guard: record the current OS clipboard text in the echo
     * guard + outbound dedup WITHOUT sending, so a value present at (re)connect
     * isn't broadcast to the freshly linked peer. Mirrors the desktop watcher's
     * fresh-session seeding in fluxsyncd driver.rs. Images are already echo-
     * guarded by their FileProvider authority, so only text needs seeding.
     */
    private suspend fun seedGuardsFromClipboard() {
        val text = withContext(Dispatchers.Main) {
            try {
                val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = cb.primaryClip ?: return@withContext null
                if (clip.itemCount == 0) return@withContext null
                clip.getItemAt(0).coerceToText(this@FluxsyncAccessibilityService)?.toString()
            } catch (e: Exception) {
                android.util.Log.w("FluxSync", "Seed clipboard read failed: ${e.message}")
                null
            }
        }
        if (!text.isNullOrEmpty()) {
            FluxsyncManager.rememberPeerClip(text)
            FluxsyncManager.markPushedIfNew(text)
        }
    }

    /** Returns true only if the write to the OS clipboard actually landed. */
    private suspend fun syncToSystemClipboard(text: String): Boolean =
        withContext(Dispatchers.Main) {
            try {
                // Mark as a peer item BEFORE writing so MainActivity's clip
                // listener treats the resulting change as an echo, not a copy.
                FluxsyncManager.rememberPeerClip(text)

                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = android.content.ClipData.newPlainText("FluxSync", text)
                clipboard.setPrimaryClip(clip)
                android.util.Log.i("FluxSync", "✅ CLIPBOARD SYNCED: [${text.take(30)}...]")
                true
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Failed to write to system clipboard: ${e.message}")
                false
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
    /** Returns true only if the image actually reached the OS clipboard. */
    private suspend fun syncImageToSystemClipboard(hash: String): Boolean {
        if (hash.isEmpty()) {
            android.util.Log.w("FluxSync", "Image history row carries no hash; cannot fetch")
            return false
        }
        return try {
            val png = FluxsyncManager.withHandle { it.fetchItem(hash) }
            if (png == null || png.isEmpty()) {
                android.util.Log.w("FluxSync", "fetchItem returned no bytes for $hash")
                return false
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
            true
        } catch (e: Exception) {
            android.util.Log.e("FluxSync", "Failed to write image to clipboard: ${e.message}")
            false
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
        // #5: shared dedup window across the a11y copy detector and
        // MainActivity's clip listener / onResume — one copy must not fan
        // out into two pushes.
        if (!FluxsyncManager.markPushedIfNew(text)) return

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

        /** Max image payload, mirrors the daemon proto `MAX_PAYLOAD` (16 MiB). */
        private const val MAX_IMAGE_BYTES = 16 * 1024 * 1024

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
         * DIR-P3-07: last time the poll loop ran, i.e. proof the service is
         * actually alive (not just toggled on in Settings). Written every
         * tick from [startPolling]; read from
         * `FluxsyncViewModel.checkAccessibility` via
         * `ServiceHealthUtils.isServiceDead`. `0L` until the first tick of
         * this process incarnation.
         */
        @Volatile
        var lastHeartbeatMs: Long = 0L

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

        if (clipListenerRegistered) {
            try {
                clipboard.removePrimaryClipChangedListener(clipListener)
            } catch (_: Exception) {}
        }
        try {
            unregisterReceiver(batteryReceiver)
        } catch (_: Exception) {}
        job.cancel()
        super.onDestroy()
    }
}
