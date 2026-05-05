package sn.kaolack.fluxsync

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
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
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import sn.kaolack.fluxsync.ui.FluxsyncApp
import sn.kaolack.fluxsync.ui.theme.FluxsyncTheme
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * Compose entry point. Owns the `FluxsyncViewModel` (which boots/shuts
 * down the Rust daemon thread) and three pieces of OS plumbing the
 * daemon can't do from Rust:
 *
 *   * **Clipboard** — registers a `ClipboardManager` listener so local
 *     copies are pushed to the peer; observes `vm.state.history[0]` so
 *     items received from the peer are written to the OS clipboard.
 *     Both directions dedup against `lastWrittenText` to break the
 *     read-our-own-write echo.
 *   * **Battery** — registers a `ACTION_BATTERY_CHANGED` receiver and
 *     forwards level/charging into the daemon via `vm.setSelfBattery`,
 *     so the peer device sees the real battery instead of a hardcoded
 *     100%.
 *   * **Lifecycle** — the Activity's lifecycleScope cancels the
 *     listeners + receiver in `onDestroy`, which the ViewModel can't do
 *     because it doesn't have a Context.
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
        val raw = clip.getItemAt(0).coerceToText(this) ?: return@OnPrimaryClipChangedListener
        val text = raw.toString()
        if (text.isEmpty()) return@OnPrimaryClipChangedListener
        if (text == FluxsyncManager.lastPeerClipText) return@OnPrimaryClipChangedListener
        
        val vm = currentVm ?: return@OnPrimaryClipChangedListener
        lifecycleScope.launch { vm.pushText(text) }
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
        
        // Force a clipboard check when the app is opened
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val text = clip.getItemAt(0).coerceToText(this)?.toString()?.trim()
            if (text != null && text.isNotEmpty() && text != FluxsyncManager.lastPeerClipText?.trim()) {
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
}
