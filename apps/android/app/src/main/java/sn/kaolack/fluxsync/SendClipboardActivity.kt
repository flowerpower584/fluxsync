package sn.kaolack.fluxsync

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import java.io.ByteArrayOutputStream
import kotlin.concurrent.thread

/**
 * Sends something to the paired devices without relying on the
 * Accessibility capture: the "Send clipboard" notification button, the
 * quick-settings tile, and "Share → FluxSync" all land here.
 *
 * Android only lets the app in front read the clipboard, so this invisible
 * activity takes focus for a moment, reads it, hands it to the daemon and
 * closes. A share (`ACTION_SEND`) carries its own text or image instead.
 *
 * [EXTRA_AUTO]: started by the Accessibility service right after it saw a
 * copy happen (a "Copy" tap, a "Copied" toast, the system clipboard
 * bubble), so copying on the phone syncs with no tap at all. Silent: no
 * toasts, and nothing is sent unless the clipboard holds something new.
 */
class SendClipboardActivity : Activity() {
    private var handled = false
    private val auto get() = intent?.getBooleanExtra(EXTRA_AUTO, false) == true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (auto) {
            @Suppress("DEPRECATION")
            overridePendingTransition(0, 0)
        }
        if (intent?.action == Intent.ACTION_SEND) {
            handled = true
            sendShared(intent)
            finish()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || handled) return
        handled = true
        if (auto) sendClipboardSilently() else sendClipboard()
        finish()
        if (auto) {
            @Suppress("DEPRECATION")
            overridePendingTransition(0, 0)
        }
    }

    /** Auto mode: send only what's new, and never a peer item we just wrote. */
    private fun sendClipboardSilently() {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = try {
            cb.primaryClip
        } catch (e: Exception) {
            null
        } ?: return
        if (clip.itemCount == 0) return
        FluxsyncManager.markClipboardRead()
        val item = clip.getItemAt(0)
        val uri = item.uri
        if (uri != null && clip.description?.hasMimeType("image/*") == true) {
            // Our own inbound images come through our FileProvider.
            if (uri.authority == "$packageName.fileprovider" || uri.toString() == lastAutoUri) return
            lastAutoUri = uri.toString()
            sendImage(uri, quiet = true)
            return
        }
        val text = item.coerceToText(this)?.toString().orEmpty()
        if (text.isBlank() || FluxsyncManager.isRecentPeerClip(text)) return
        if (!FluxsyncManager.markPushedIfNew(text)) return
        val sensitive = FluxsyncManager.isMarkedSensitive(clip.description)
        thread(name = "fluxsync-auto-send") {
            try {
                FluxsyncManager.withHandle { h ->
                    if (sensitive) h.pushItem("text", text.toByteArray(), true) else h.pushText(text)
                }
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Auto send failed: ${e.message}")
            }
        }
    }

    private fun sendClipboard() {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cb.primaryClip
        if (clip == null || clip.itemCount == 0) {
            toast("The clipboard is empty")
            return
        }
        val item = clip.getItemAt(0)
        val uri = item.uri
        if (uri != null && clip.description?.hasMimeType("image/*") == true) {
            sendImage(uri)
            return
        }
        if (uri != null && uri.scheme == "content") {
            sendFile(uri)
            return
        }
        val text = item.coerceToText(this)?.toString().orEmpty()
        if (text.isBlank()) {
            toast("Nothing to send")
            return
        }
        sendText(text, FluxsyncManager.isMarkedSensitive(clip.description))
    }

    private fun sendShared(intent: Intent) {
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)
        if (!text.isNullOrBlank()) {
            sendText(text, sensitive = false)
            return
        }
        val uri = if (Build.VERSION.SDK_INT >= 33) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }
        when {
            uri == null -> toast("Nothing to send")
            intent.type?.startsWith("image/") == true -> sendImage(uri)
            else -> sendFile(uri)
        }
    }

    private fun sendText(text: String, sensitive: Boolean) {
        FluxsyncManager.markPushedIfNew(text)
        push { handle ->
            if (sensitive) handle.pushItem("text", text.toByteArray(), true) else handle.pushText(text)
        }
    }

    private fun sendImage(uri: Uri, quiet: Boolean = false) {
        val app = applicationContext
        thread(name = "fluxsync-send-image") {
            val png = try {
                val bitmap = app.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it) }
                bitmap?.let {
                    ByteArrayOutputStream().also { out -> it.compress(Bitmap.CompressFormat.PNG, 100, out) }.toByteArray()
                }
            } catch (e: Exception) {
                null
            }
            if (png == null) {
                if (!quiet) toastFrom(app, "Couldn't read that image")
            } else if (quiet) {
                try {
                    FluxsyncManager.withHandle { it.pushItem("image", png, false) }
                } catch (e: Exception) {
                    android.util.Log.e("FluxSync", "Auto image send failed: ${e.message}")
                }
            } else {
                pushNow(app) { it.pushItem("image", png, false) }
            }
        }
    }

    /** Any other file: sent as-is under its own name (up to 16 MB). */
    private fun sendFile(uri: Uri) {
        val app = applicationContext
        thread(name = "fluxsync-send-file") {
            val name = try {
                app.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)
                    ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
            } catch (e: Exception) {
                null
            } ?: uri.lastPathSegment ?: "file"
            val bytes = try {
                app.contentResolver.openInputStream(uri)?.use { input ->
                    val out = ByteArrayOutputStream()
                    val buf = ByteArray(64 * 1024)
                    var total = 0
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_FILE_BYTES) return@use null
                        out.write(buf, 0, n)
                    }
                    out.toByteArray()
                }
            } catch (e: Exception) {
                null
            }
            if (bytes == null) {
                toastFrom(app, "Couldn't send that file (16 MB at most)")
            } else {
                pushNow(app) { it.pushFile(name, bytes) }
            }
        }
    }

    /** Run the FFI push off the main thread; the activity may already be gone. */
    private fun push(block: (FluxsyncHandle) -> Unit) {
        val app = applicationContext
        thread(name = "fluxsync-send") { pushNow(app, block) }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    companion object {
        /** Started by the Accessibility service after it saw a copy. */
        const val EXTRA_AUTO = "sn.kaolack.fluxsync.AUTO"

        /** Last image URI sent in auto mode (images have no text to dedup on). */
        @Volatile
        private var lastAutoUri: String? = null

        /** The daemon's 16 MiB item cap minus the name framing. */
        private const val MAX_FILE_BYTES = 16 * 1024 * 1024 - 257

        private fun pushNow(app: Context, block: (FluxsyncHandle) -> Unit) {
            val sent = try {
                FluxsyncManager.withHandle(block) != null
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Send failed: ${e.message}")
                false
            }
            toastFrom(app, if (sent) "Sent to your devices" else "FluxSync isn't running — open the app first")
        }

        private fun toastFrom(app: Context, msg: String) {
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                Toast.makeText(app, msg, Toast.LENGTH_SHORT).show()
            }
        }
    }
}
