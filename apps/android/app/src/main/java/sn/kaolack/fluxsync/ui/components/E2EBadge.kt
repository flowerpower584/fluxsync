package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted

/**
 * Small "E2E · X25519" pill that lives next to the section header.
 * No icon yet — the `<svg>` lock in the mockup translates poorly to
 * a one-off vector here, and the text alone reads.
 *
 * Matches `E2EBadge` in `components.jsx` (compact variant).
 */
@Composable
fun E2EBadge(
    modifier: Modifier = Modifier,
    compact: Boolean = true,
) {
    val v = if (compact) 2.dp else 3.dp
    val h = if (compact) 5.dp else 7.dp
    Row(
        modifier = modifier
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(2.dp))
            .padding(horizontal = h, vertical = v),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Text(
            text = "E2E · X25519",
            color = FsDarkMuted,
            style = MaterialTheme.typography.labelSmall,
        )
    }
}
