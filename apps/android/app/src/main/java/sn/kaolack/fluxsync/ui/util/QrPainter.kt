package sn.kaolack.fluxsync.ui.util

import android.graphics.Bitmap
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Encode `text` as a square QR `ImageBitmap`. Black-on-transparent so a
 * Compose `Image` keeps the surrounding theme color. The result is
 * cached via `remember` keyed on `(text, sizePx)` — re-encoding is
 * only triggered when the URI or the canvas size actually changes.
 */
@Composable
fun rememberQrBitmap(text: String, sizePx: Int = 512): ImageBitmap {
    return remember(text, sizePx) { encodeQr(text, sizePx).asImageBitmap() }
}

private fun encodeQr(text: String, sizePx: Int): Bitmap {
    val hints = mapOf(
        EncodeHintType.MARGIN to 1,
        // Medium error-correction is plenty for a clean LAN scan.
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
    )
    val matrix = MultiFormatWriter()
        .encode(text, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
    val w = matrix.width
    val h = matrix.height
    val pixels = IntArray(w * h)
    for (y in 0 until h) {
        val row = y * w
        for (x in 0 until w) {
            // 0xFF000000 = opaque black; 0x00000000 = transparent so
            // the surrounding surface color shows through the quiet zone.
            pixels[row + x] = if (matrix[x, y]) 0xFF000000.toInt() else 0x00000000
        }
    }
    return Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).apply {
        setPixels(pixels, 0, w, 0, 0, w, h)
    }
}
