package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import sn.kaolack.fluxsync.ui.theme.FsDarkSubtle
import sn.kaolack.fluxsync.ui.theme.FsSans

/**
 * Section caption with an optional right-side value (e.g. "5 items").
 * v6: sentence case, no divider — matches `.ph-sec` in
 * `design-preview.html`.
 */
@Composable
fun SectionLabel(
    title: String,
    modifier: Modifier = Modifier,
    right: (@Composable () -> Unit)? = null,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = title,
            color = FsDarkSubtle,
            fontFamily = FsSans,
            fontWeight = FontWeight.W600,
            fontSize = 11.5.sp,
        )
        if (right != null) {
            right()
        }
    }
}
