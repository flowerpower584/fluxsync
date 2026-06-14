package sn.kaolack.fluxsync.ui.components

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong

/**
 * v6 pill switch — flat fill, round white knob, no gradient. "On" is
 * the green accent; "off" is the strong border grey. Matches `.tgl`
 * in `design-preview.html`.
 *
 * Two sizes:
 *   * `Md` — 42 × 25, used in the hero card and the page-level toggle.
 *   * `Sm` — 32 × 19, used inside settings rows (resume-while-charging).
 */
enum class FluxToggleSize(val w: Dp, val h: Dp, val k: Dp) {
    Md(w = 42.dp, h = 25.dp, k = 20.dp),
    Sm(w = 32.dp, h = 19.dp, k = 15.dp),
}

@Composable
fun FluxToggle(
    on: Boolean,
    onChange: (Boolean) -> Unit,
    size: FluxToggleSize = FluxToggleSize.Md,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    val bg = if (on) FsAccent else FsDarkBorderStrong
    val inset = (size.h - size.k) / 2

    val targetX = if (on) size.w - size.k - inset else inset
    val animatedX by animateDpAsState(
        targetValue = targetX,
        animationSpec = spring(dampingRatio = 0.6f, stiffness = Spring.StiffnessMedium),
        label = "fs-toggle-x",
    )

    Box(
        modifier = modifier
            .width(size.w)
            .height(size.h)
            .alpha(if (enabled) 1f else 0.4f)
            .background(bg, CircleShape)
            .clickable(enabled = enabled) { onChange(!on) },
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            Modifier
                .offset(x = animatedX, y = 0.dp)
                .size(size.k)
                .background(Color.White, CircleShape),
        )
    }
}
