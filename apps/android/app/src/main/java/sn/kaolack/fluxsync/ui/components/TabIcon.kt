package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

/**
 * Bottom-nav tab icons, ported from the SVGs in
 * design/project/FluxSync-Mobile.html (viewBox 0 0 18 18, stroke 1.4).
 * Each tab gets a distinct shape; [color] tints active vs inactive.
 */
@Composable
fun TabIcon(id: String, color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier.size(18.dp)) {
        val k = size.width / 18f
        val sw = 1.4f
        scale(k, k, pivot = Offset.Zero) {
            when (id) {
                "home" -> drawPath(
                    PathParser().parsePathString(
                        "M3 8L9 3l6 5v6.5a.5.5 0 01-.5.5H3.5a.5.5 0 01-.5-.5V8z",
                    ).toPath(),
                    color = color,
                    style = Stroke(width = sw, join = StrokeJoin.Round),
                )
                "devices" -> {
                    drawRoundRect(
                        color = color,
                        topLeft = Offset(2f, 4f),
                        size = Size(9f, 11f),
                        cornerRadius = CornerRadius(1f, 1f),
                        style = Stroke(width = sw),
                    )
                    drawRoundRect(
                        color = color,
                        topLeft = Offset(12f, 7f),
                        size = Size(4f, 8f),
                        cornerRadius = CornerRadius(0.8f, 0.8f),
                        style = Stroke(width = sw),
                    )
                }
                "logs" -> drawPath(
                    PathParser().parsePathString("M3 4h12M3 9h12M3 14h8").toPath(),
                    color = color,
                    style = Stroke(width = sw, cap = StrokeCap.Round),
                )
                "firewall" -> drawPath(
                    // Shield with an inner check — the firewall guarding the
                    // clipboard. viewBox 0 0 18 18 to match the other tabs.
                    PathParser().parsePathString(
                        "M9 2.5L14.5 4.8V9.2C14.5 12.4 12.1 14.6 9 15.5" +
                            "C5.9 14.6 3.5 12.4 3.5 9.2V4.8L9 2.5z" +
                            "M6.6 8.9l1.8 1.8 3-3.4",
                    ).toPath(),
                    color = color,
                    style = Stroke(width = sw, join = StrokeJoin.Round, cap = StrokeCap.Round),
                )
                "settings" -> {
                    drawCircle(
                        color = color,
                        radius = 2f,
                        center = Offset(9f, 9f),
                        style = Stroke(width = sw),
                    )
                    drawPath(
                        PathParser().parsePathString(
                            "M9 2v2M9 14v2M2 9h2M14 9h2M4 4l1.4 1.4M12.6 12.6L14 14" +
                                "M4 14l1.4-1.4M12.6 5.4L14 4",
                        ).toPath(),
                        color = color,
                        style = Stroke(width = sw, cap = StrokeCap.Round),
                    )
                }
            }
        }
    }
}
