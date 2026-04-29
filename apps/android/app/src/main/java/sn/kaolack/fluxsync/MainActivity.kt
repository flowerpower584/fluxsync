package sn.kaolack.fluxsync

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import java.io.File

/**
 * v0.1 skeleton: load the FluxSync UniFFI shared library, start the
 * daemon, install a state observer that logs every snapshot to logcat,
 * and display the most recent JSON in a single TextView.
 *
 * No Compose UI here yet. The shape of the data the UI will render is
 * defined by the design bundle in `design/` and the JSON shape served
 * by `start()`'s `observe_state` callback.
 *
 * Build:
 *   1. `cargo ndk -t arm64-v8a build --release -p fluxsync-mobile-ffi`
 *      (or `cross build --target aarch64-linux-android --release -p fluxsync-mobile-ffi`)
 *   2. Copy `target/aarch64-linux-android/release/libfluxsync_mobile_ffi.so`
 *      into `apps/android/app/src/main/jniLibs/arm64-v8a/`
 *   3. Generate Kotlin bindings:
 *      `cargo run -p uniffi-bindgen-cli -- generate \
 *         --library target/aarch64-linux-android/release/libfluxsync_mobile_ffi.so \
 *         --language kotlin \
 *         --out-dir apps/android/app/src/main/java`
 *   4. `./gradlew assembleDebug`
 */
class MainActivity : Activity() {

    private lateinit var view: TextView
    private var handle: FluxsyncHandle? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        view = TextView(this).apply { text = "starting fluxsync..." }
        setContentView(view)

        val ipcPath = File(filesDir, "fluxsync.sock").absolutePath
        try {
            val h = FluxsyncHandle.start(
                peerName = "${android.os.Build.MODEL}",
                ipcPath = ipcPath,
                udpPort = 41889u,
                identitySecretB64 = null, // v0.1: regenerate on every boot
            )
            handle = h

            // Hop to UI thread inside the callback — required by Compose
            // and by classic Views alike. The Rust side fires on a Rust
            // worker thread.
            h.observeState(object : StateObserver {
                override fun onState(json: String) {
                    runOnUiThread {
                        view.text = json
                    }
                }
            })

            Log.i(TAG, "fluxsync started; ipc=$ipcPath")
        } catch (t: Throwable) {
            Log.e(TAG, "fluxsync failed to start", t)
            view.text = "error: ${t.message}"
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        handle?.stop()
        handle = null
    }

    companion object {
        private const val TAG = "FluxSync"
    }
}
