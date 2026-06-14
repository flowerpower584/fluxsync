package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import sn.kaolack.fluxsync.ui.theme.FsCardFlat
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsSans

/**
 * v6 "E2E" pill with a small padlock glyph. Matches `.pill-badge` in
 * `design-preview.html` (phone header).
 */
@Composable
fun E2EBadge(
    modifier: Modifier = Modifier,
    compact: Boolean = true,
) {
    val v = if (compact) 4.dp else 5.dp
    val h = if (compact) 9.dp else 11.dp
    val pill = RoundedCornerShape(8.dp)
    Row(
        modifier = modifier
            .border(width = 1.dp, color = FsDarkBorder, shape = pill)
            .background(FsCardFlat, pill)
            .padding(horizontal = h, vertical = v),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        LockGlyph()
        Text(
            text = "E2E",
            color = FsDarkMuted,
            fontFamily = FsSans,
            fontWeight = FontWeight.W600,
            fontSize = 10.sp,
        )
    }
}

@Composable
private fun LockGlyph() {
    val color = FsDarkMuted
    Canvas(Modifier.size(9.dp, 10.dp)) {
        val s = size.width / 9f
        val stroke = Stroke(width = 1.2f * s)
        // body
        drawRect(
            color = color,
            topLeft = Offset(1f * s, 4.5f * s),
            size = Size(7f * s, 4.8f * s),
            style = stroke,
        )
        // shackle
        drawArc(
            color = color,
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(2.5f * s, 0.8f * s),
            size = Size(4f * s, 5.4f * s),
            style = stroke,
        )
    }
}
