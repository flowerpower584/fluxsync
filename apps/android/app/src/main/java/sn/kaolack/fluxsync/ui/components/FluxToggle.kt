package sn.kaolack.fluxsync.ui.components

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsCrit
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsLightSurface

/**
 * Square 1px-bordered switch — 2px corner radius, no gradient. The
 * "on" state is the rouge sénégalais; "off" is a hollow rectangle with
 * a small grey thumb. Matches `Toggle` in `components.jsx`.
 *
 * Two sizes:
 *   * `Md` — 36 × 20, used in the hero card and the page-level toggle.
 *   * `Sm` — 28 × 16, used inside settings rows (resume-while-charging).
 */
enum class FluxToggleSize(val w: Dp, val h: Dp, val k: Dp) {
    Md(w = 36.dp, h = 20.dp, k = 16.dp),
    Sm(w = 28.dp, h = 16.dp, k = 12.dp),
}

@Composable
fun FluxToggle(
    on: Boolean,
    onChange: (Boolean) -> Unit,
    size: FluxToggleSize = FluxToggleSize.Md,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    val borderColor = if (on) FsCrit else FsDarkBorderStrong
    val bg = if (on) FsCrit else Color.Transparent
    val thumbColor = if (on) FsLightSurface else FsDarkMuted

    val targetX = if (on) size.w - size.k - 3.dp else 1.dp
    val animatedX by animateDpAsState(
        targetValue = targetX,
        animationSpec = tween(durationMillis = 150),
        label = "fs-toggle-x",
    )

    Box(
        modifier = modifier
            .width(size.w)
            .height(size.h)
            .alpha(if (enabled) 1f else 0.4f)
            .border(width = 1.dp, color = borderColor, shape = RoundedCornerShape(2.dp))
            .background(bg, RoundedCornerShape(2.dp))
            .clickable(enabled = enabled) { onChange(!on) },
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            Modifier
                .offset(x = animatedX, y = 0.dp)
                .size(size.k)
                .background(thumbColor, RoundedCornerShape(1.dp)),
        )
    }
}
