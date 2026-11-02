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
 */
class SendClipboardActivity : Activity() {
    private var handled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        sendClipboard()
        finish()
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
        if (uri != null) sendImage(uri) else toast("Nothing to send")
    }

    private fun sendText(text: String, sensitive: Boolean) {
        FluxsyncManager.markPushedIfNew(text)
        push { handle ->
            if (sensitive) handle.pushItem("text", text.toByteArray(), true) else handle.pushText(text)
        }
    }

    private fun sendImage(uri: Uri) {
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
                toastFrom(app, "Couldn't read that image")
            } else {
                pushNow(app) { it.pushItem("image", png, false) }
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
