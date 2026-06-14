package sn.kaolack.fluxsync.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsCrit
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong
import sn.kaolack.fluxsync.ui.theme.FsOk
import sn.kaolack.fluxsync.ui.theme.FsWarn

/**
 * v6 battery bar: flat horizontal track + animated fill, matches
 * `.batt .bar` in `design-preview.html` (30×6, radius 3). The `%`
 * label and the charging bolt are rendered by callsites.
 *
 * Color thresholds:
 *   * `<= 5%`             → crit (red)
 *   * `<= threshold`      → warn (amber)
 *   * else                → ok   (green)
 */
@Composable
fun BatteryGlyph(
    level: Int,
    threshold: Int = 15,
    charging: Boolean = false,
    width: Dp = 30.dp,
    modifier: Modifier = Modifier,
) {
    val color = batteryToneFor(level, threshold)
    val target = (level.coerceIn(0, 100)) / 100f
    val pct by animateFloatAsState(
        targetValue = target,
        animationSpec = tween(durationMillis = 300),
        label = "fs-battery-pct",
    )

    val r = RoundedCornerShape(3.dp)
    Box(
        modifier = modifier
            .width(width)
            .height(6.dp)
            .background(FsDarkBorderStrong, r),
    ) {
        Box(
            Modifier
                .fillMaxWidth(pct)
                .fillMaxHeight()
                .background(color, r),
        )
    }
}

/** Tone-only helper so the surrounding text label can color-match. */
fun batteryToneFor(level: Int, threshold: Int): Color = when {
    level <= 5 -> FsCrit
    level <= threshold -> FsWarn
    else -> FsOk
}
