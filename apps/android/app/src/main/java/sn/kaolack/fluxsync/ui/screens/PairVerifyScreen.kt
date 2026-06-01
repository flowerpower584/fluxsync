package sn.kaolack.fluxsync.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import kotlinx.coroutines.delay
import org.json.JSONArray
import sn.kaolack.fluxsync.ui.theme.FsCrit
import sn.kaolack.fluxsync.ui.theme.FsDarkBg
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong
import sn.kaolack.fluxsync.ui.theme.FsDarkFg
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsDarkSubtle
import sn.kaolack.fluxsync.ui.theme.FsDarkSurface
import sn.kaolack.fluxsync.ui.theme.FsLightSurface
import sn.kaolack.fluxsync.ui.theme.FsOk
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * FS-052 verify-words gate for the scanning (initiator) side. After a QR
 * scan the daemon TOFU-trusts the peer but holds clipboard until the user
 * confirms the 6 SAS words match the ones shown on the peer. Symmetric with
 * the desktop verify screen — both devices must accept before sync flows.
 */
@Composable
fun PairVerifyScreen(
    vm: FluxsyncViewModel,
    onConfirmed: () -> Unit,
    onRejected: () -> Unit,
) {
    var peerId by remember { mutableStateOf<String?>(null) }
    var words by remember { mutableStateOf<List<String>>(emptyList()) }
    var failed by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    // Poll pair_pending: run_initiator inserts the entry once the handshake
    // completes, which races the navigation into this screen.
    LaunchedEffect(Unit) {
        repeat(25) {
            val json = vm.pairPending()
            if (json != null) {
                val arr = runCatching { JSONArray(json) }.getOrNull()
                val o = if (arr != null && arr.length() > 0) arr.optJSONObject(0) else null
                if (o != null) {
                    peerId = o.optString("peer_id", "").ifEmpty { null }
                    val w = o.optJSONArray("sas_words")
                    words = if (w == null) emptyList()
                    else (0 until w.length()).map { i -> w.optString(i, "") }
                    return@LaunchedEffect
                }
            }
            delay(200)
        }
        failed = true
    }

    Column(Modifier.fillMaxSize().background(FsDarkBg)) {
        Spacer(Modifier.height(36.dp))
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                "VERIFY",
                color = FsDarkSubtle,
                style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.12.em),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                "These 6 words must match the ones on the other device. If they differ, reject.",
                color = FsDarkMuted,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(28.dp))

            when {
                failed -> Text(
                    "No pending pair surfaced by the daemon. Reject and scan again.",
                    color = FsCrit,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                words.isEmpty() -> {
                    CircularProgressIndicator(color = FsDarkMuted)
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "Completing handshake…",
                        color = FsDarkMuted,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                else -> Box(
                    Modifier.fillMaxWidth()
                        .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(8.dp))
                        .background(FsDarkSurface, RoundedCornerShape(8.dp))
                        .padding(vertical = 24.dp, horizontal = 16.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        words.joinToString(" ").uppercase(),
                        color = FsDarkFg,
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = 0.06.em,
                        ),
                    )
                }
            }
        }

        Spacer(Modifier.weight(1f))
        HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
        Row(
            Modifier.fillMaxWidth().padding(20.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Reject — always available; also the escape hatch on failure.
            Box(
                Modifier.weight(1f)
                    .border(1.dp, FsCrit, RoundedCornerShape(6.dp))
                    .clickable(enabled = !busy) {
                        busy = true
                        peerId?.let { vm.pairConfirm(it, false) }
                        onRejected()
                    }
                    .padding(vertical = 14.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "DON'T MATCH",
                    color = FsCrit,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                )
            }
            // Accept — only once words + peer_id are loaded.
            val canAccept = !busy && peerId != null && words.isNotEmpty()
            Box(
                Modifier.weight(1f)
                    .background(
                        if (canAccept) FsOk else FsDarkBorderStrong,
                        RoundedCornerShape(6.dp),
                    )
                    .clickable(enabled = canAccept) {
                        busy = true
                        peerId?.let { vm.pairConfirm(it, true) }
                        onConfirmed()
                    }
                    .padding(vertical = 14.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "WORDS MATCH",
                    color = FsLightSurface,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}
