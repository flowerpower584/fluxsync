package sn.kaolack.fluxsync

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.LaunchedEffect
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import sn.kaolack.fluxsync.ui.FluxsyncApp
import sn.kaolack.fluxsync.ui.theme.FluxsyncTheme
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * Compose entry point. Owns the `FluxsyncViewModel` (which boots/shuts
 * down the Rust daemon thread) and one piece of OS plumbing: a foreground
 * clipboard bridge.
 *
 *   * **Clipboard (outbound)** — registers a `ClipboardManager` listener
 *     so local copies (text + image) made while FluxSync is focused are
 *     pushed to the peer, and re-checks the clipboard in `onResume`.
 *     Echoes of peer items we just wrote are dropped via
 *     `FluxsyncManager.isRecentPeerClip`; a single copy is pushed once via
 *     `FluxsyncManager.markPushedIfNew`. This is a foreground convenience
 *     path only — the AccessibilityService owns the daemon AND runs the
 *     same clipboard capture in the background, so sync does not depend on
 *     this Activity being alive.
 *   * **Lifecycle** — the Activity's lifecycleScope unregisters the
 *     listener in `onDestroy`, which the ViewModel can't do (no Context).
 *
 * Inbound (peer → clipboard) and battery reporting are NOT handled here:
 * the AccessibilityService poll loop writes received items to the OS
 * clipboard and forwards battery state. There is no `vm.state.history`
 * observer in this Activity.
 *
 * Build pipeline (run from the workspace root):
 *
 *   1. cargo ndk -t arm64-v8a -o apps/android/app/src/main/jniLibs \
 *        build --release -p fluxsync-mobile-ffi
 *   2. cargo run -p uniffi-bindgen -- generate \
 *        --library apps/android/app/src/main/jniLibs/arm64-v8a/libfluxsync_mobile_ffi.so \
 *        --language kotlin \
 *        --out-dir apps/android/app/src/main/java
 *   3. (cd apps/android && ./gradlew assembleDebug)
 */
class MainActivity : ComponentActivity() {

    private lateinit var clipboard: ClipboardManager
    private var currentVm: FluxsyncViewModel? = null

    private val clipListener = ClipboardManager.OnPrimaryClipChangedListener {
        val clip = clipboard.primaryClip ?: return@OnPrimaryClipChangedListener
        if (clip.itemCount == 0) return@OnPrimaryClipChangedListener
        val vm = currentVm ?: return@OnPrimaryClipChangedListener
        val item = clip.getItemAt(0)

        // Image branch: a content URI carrying an image/* MIME type.
        // Checked before text — coerceToText on an image item returns the
        // URI string, which we must not push as clipboard text.
        if (clip.description?.hasMimeType("image/*") == true && item.uri != null) {
            val uri = item.uri
            // Skip our own writes: the AccessibilityService hands inbound
            // peer images to the OS clipboard via this app's FileProvider,
            // so a matching authority means this event is an echo.
            if (uri.authority == "$packageName.fileprovider") return@OnPrimaryClipChangedListener
            lifecycleScope.launch(Dispatchers.IO) {
                val png = readClipboardImageAsPng(uri) ?: return@launch
                vm.pushImage(png)
            }
            return@OnPrimaryClipChangedListener
        }

        val raw = item.coerceToText(this) ?: return@OnPrimaryClipChangedListener
        val text = raw.toString()
        if (text.isEmpty()) return@OnPrimaryClipChangedListener
        // #6 echo guard: skip items we just wrote from a peer. A bounded
        // recency set (not one volatile string) keeps two peer items that
        // arrive back-to-back both suppressed.
        if (FluxsyncManager.isRecentPeerClip(text)) return@OnPrimaryClipChangedListener
        // #5: dedup against the a11y copy detector so one local copy is
        // pushed once, not twice.
        if (!FluxsyncManager.markPushedIfNew(text)) return@OnPrimaryClipChangedListener

        lifecycleScope.launch { vm.pushText(text) }
    }

    /**
     * Decode a clipboard image URI and re-encode it as PNG — the wire
     * format for phase-1 image sync. Returns null on decode failure or if
     * the result exceeds the daemon's payload cap. Runs off the main
     * thread (content URI reads are blocking I/O).
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request notification permission for Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }

        clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.addPrimaryClipChangedListener(clipListener)

        setContent {
            val vm: FluxsyncViewModel = viewModel()
            currentVm = vm

            FluxsyncTheme {
                FluxsyncApp(vm)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        currentVm?.checkAccessibility()
        
        // #5: re-check the clipboard on open, but don't re-broadcast a stale
        // local item. onResume fires on every foreground, so an unguarded push
        // here clobbers the peer with an old clip each time. Skip peer echoes
        // (isRecentPeerClip) and anything already pushed (markPushedIfNew).
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val text = clip.getItemAt(0).coerceToText(this)?.toString()
            if (!text.isNullOrEmpty() &&
                !FluxsyncManager.isRecentPeerClip(text) &&
                FluxsyncManager.markPushedIfNew(text)
            ) {
                currentVm?.pushText(text)
            }
        }
    }

    override fun onDestroy() {
        try {
            clipboard.removePrimaryClipChangedListener(clipListener)
        } catch (_: Throwable) {
        }
        currentVm = null
        super.onDestroy()
    }

    companion object {
        /** Max image payload, mirrors the daemon proto `MAX_PAYLOAD` (16 MiB). */
        private const val MAX_IMAGE_BYTES = 16 * 1024 * 1024
    }
}
