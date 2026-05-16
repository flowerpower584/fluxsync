package sn.kaolack.fluxsync.ui.components

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import sn.kaolack.fluxsync.ui.theme.FsCrit

/** Centered spinner shown while the daemon state has not arrived yet. */
@Composable
fun LoadingState() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(color = FsCrit, strokeWidth = 2.dp)
    }
}
