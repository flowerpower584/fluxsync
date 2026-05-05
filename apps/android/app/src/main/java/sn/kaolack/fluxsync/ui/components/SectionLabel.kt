package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkSubtle

/**
 * Uppercase mono caption above a panel, with an optional right-side
 * value (e.g. "5 ITEMS"). Underlined with a 1px divider.
 *
 * Matches `SectionLabel` in `components.jsx`.
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
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = title.uppercase(),
            color = FsDarkSubtle,
            style = MaterialTheme.typography.labelSmall,
        )
        if (right != null) {
            right()
        }
    }
    HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
}
