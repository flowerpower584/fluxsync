package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.drag
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong
import sn.kaolack.fluxsync.ui.theme.FsDarkSurface
import kotlin.math.roundToInt

/**
 * Custom slider — v6: green accent fill, round thumb, 4dp track.
 *
 * Behavior:
 *   * Tap anywhere on the track → seek to that position immediately.
 *   * Drag the thumb (or anywhere) → continuous update via `drag(...)`.
 *   * Width is captured with `onSizeChanged` so percent → pixel math is
 *     stable across rotations / parent resizes.
 */
@Composable
fun ThresholdSlider(
    value: Int,
    onChange: (Int) -> Unit,
    min: Int = 5,
    max: Int = 50,
    modifier: Modifier = Modifier,
) {
    val density = LocalDensity.current
    val thumbDp = 12.dp
    val thumbPx = with(density) { thumbDp.toPx() }
    var trackWidthPx by remember { mutableStateOf(0f) }

    val pct = ((value - min).toFloat() / (max - min).toFloat()).coerceIn(0f, 1f)

    fun seek(xPx: Float) {
        if (trackWidthPx <= 0f) return
        val clamped = xPx.coerceIn(0f, trackWidthPx)
        val raw = min + (clamped / trackWidthPx) * (max - min)
        onChange(raw.roundToInt().coerceIn(min, max))
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(24.dp)
            .onSizeChanged { trackWidthPx = it.width.toFloat() }
            .pointerInput(Unit) {
                awaitEachGesture {
                    val down = awaitFirstDown(requireUnconsumed = false)
                    seek(down.position.x)
                    drag(down.id) { change ->
                        seek(change.position.x)
                        change.consume()
                    }
                }
            },
        contentAlignment = Alignment.CenterStart,
    ) {
        // Track.
        Box(
            Modifier
                .fillMaxWidth()
                .height(4.dp)
                .background(FsDarkBorderStrong, RoundedCornerShape(2.dp)),
        )
        // Filled portion (left edge → thumb).
        if (trackWidthPx > 0f) {
            val fillWidthDp = with(density) { (trackWidthPx * pct).toDp() }
            Box(
                Modifier
                    .width(fillWidthDp)
                    .height(4.dp)
                    .background(FsAccent, RoundedCornerShape(2.dp)),
            )
        }
        // Thumb (centered on the percent position).
        if (trackWidthPx > 0f) {
            val thumbXPx = (trackWidthPx * pct - thumbPx / 2f).coerceAtLeast(0f)
            Box(
                Modifier
                    .offset { IntOffset(thumbXPx.roundToInt(), 0) }
                    .size(thumbDp)
                    .background(FsAccent, CircleShape)
                    .border(width = 2.dp, color = FsDarkSurface, shape = CircleShape),
            )
        }
    }
}
