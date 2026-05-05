package sn.kaolack.fluxsync.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Colored status dot with the 3px translucent halo from the design
 * system. `pulse = true` softly fades the dot's alpha (1.6s) to mark
 * "live" / "synchronizing" states.
 *
 * Matches `Dot` in `components.jsx`.
 */
@Composable
fun StatusDot(
    color: Color,
    size: Dp = 6.dp,
    pulse: Boolean = false,
    modifier: Modifier = Modifier,
) {
    val alpha: Float = if (pulse) {
        val transition = rememberInfiniteTransition(label = "fs-pulse")
        val a by transition.animateFloat(
            initialValue = 1f,
            targetValue = 0.45f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1600, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "fs-pulse-alpha",
        )
        a
    } else {
        1f
    }

    Box(
        modifier = modifier.size(size + 6.dp),
        contentAlignment = Alignment.Center,
    ) {
        // 3px halo on each side, 0.13 alpha (matches `${color}22`).
        Box(
            Modifier
                .size(size + 6.dp)
                .background(color.copy(alpha = 0.13f * alpha), CircleShape),
        )
        Box(
            Modifier
                .size(size)
                .background(color.copy(alpha = alpha), CircleShape),
        )
    }
}
