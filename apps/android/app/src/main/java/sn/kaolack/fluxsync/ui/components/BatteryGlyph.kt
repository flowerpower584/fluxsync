package sn.kaolack.fluxsync.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsCrit
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong
import sn.kaolack.fluxsync.ui.theme.FsOk
import sn.kaolack.fluxsync.ui.theme.FsWarn

/**
 * Battery glyph: 1px-outlined body + animated fill bar + 2dp cap.
 *
 * Color thresholds:
 *   * `<= 5%`             → crit (red)
 *   * `<= threshold`      → warn (amber)
 *   * else                → ok   (green)
 *
 * Mirrors `Battery` in `components.jsx`. The body height is 0.45 ×
 * width; the cap is 50% of the body height, 2dp wide, 1dp gap on the
 * right edge.
 */
@Composable
fun BatteryGlyph(
    level: Int,
    threshold: Int = 15,
    charging: Boolean = false,
    width: Dp = 28.dp,
    modifier: Modifier = Modifier,
) {
    val bodyHeight: Dp = width * 0.45f
    val color = batteryToneFor(level, threshold)
    val target = (level.coerceIn(0, 100)) / 100f
    val pct by animateFloatAsState(
        targetValue = target,
        animationSpec = tween(durationMillis = 300),
        label = "fs-battery-pct",
    )

    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(0.dp),
    ) {
        Canvas(
            Modifier
                .width(width)
                .height(bodyHeight)
                .clip(RoundedCornerShape(2.dp)),
        ) {
            drawRect(
                color = FsDarkBorderStrong,
                size = Size(size.width, size.height),
                style = Stroke(width = 1f),
            )
            val inset = 1f
            val available = size.width - inset * 2
            drawRect(
                color = color,
                topLeft = Offset(inset, inset),
                size = Size(available * pct, size.height - inset * 2),
            )
        }
        Spacer(Modifier.width(1.dp))
        Canvas(Modifier.size(width = 2.dp, height = bodyHeight * 0.5f)) {
            drawRect(color = FsDarkBorderStrong)
        }
    }
}

/** Tone-only helper so the surrounding text label can color-match. */
fun batteryToneFor(level: Int, threshold: Int): Color = when {
    level <= 5 -> FsCrit
    level <= threshold -> FsWarn
    else -> FsOk
}
