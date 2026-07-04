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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import org.json.JSONArray
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsCard
import sn.kaolack.fluxsync.ui.theme.FsCrit
import sn.kaolack.fluxsync.ui.theme.FsDarkBg
import sn.kaolack.fluxsync.ui.theme.FsDarkBorderStrong
import sn.kaolack.fluxsync.ui.theme.FsDarkFg
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsMono
import sn.kaolack.fluxsync.ui.theme.FsOkSoft
import sn.kaolack.fluxsync.ui.theme.FsOnAccent
import sn.kaolack.fluxsync.ui.theme.FsRadius
import sn.kaolack.fluxsync.ui.theme.FsSans
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
    // Wire-level mutual SAS confirmation: set once we've tapped "They match"
    // and are holding for the peer's own confirmation.
    var waitingForPeer by remember { mutableStateOf(false) }
    var rejectedByPeer by remember { mutableStateOf(false) }
    var peerTimedOut by remember { mutableStateOf(false) }

    val daemonState by vm.state.collectAsStateWithLifecycle()
    val sasPhase = daemonState?.sasPhase ?: "idle"

    // Poll pair_pending: run_initiator inserts the entry once the handshake
    // completes, which races the navigation into this screen.
    LaunchedEffect(Unit) {
        // At screen entry a FRESH pair's handshake is still in flight, so the
        // link is NOT up yet — peerName is empty (or "pending"). A real,
        // non-"pending" peer name HERE means a genuine already-linked reconnect
        // with nothing to verify: short-circuit ONCE, before polling.
        val st0 = vm.state.value
        if (st0 != null && st0.peerName.isNotEmpty() && st0.peerName != "pending") {
            onConfirmed()
            return@LaunchedEffect
        }
        // Then poll ONLY for the pending SAS entry. The initiator inserts it
        // just before the link comes up, so the words PULL must NOT be
        // pre-empted by the always-on peerName PUSH — consulting peerName inside
        // the loop is exactly the race that used to throw the words away. Give
        // the entry the full window to surface.
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
        // No SAS entry surfaced in the window. Do NOT navigate to Linked here:
        // a fresh pair's pending entry always surfaces within this window, so
        // "nothing surfaced" means the handshake never completed — show the
        // reject/retry path rather than silently skipping a gate that the
        // daemon would later reap (which would kill the link).
        failed = true
    }

    // The peer can reject the words at any point up to the moment both
    // sides confirm — including before our own tap. Terminal regardless of
    // [waitingForPeer].
    LaunchedEffect(sasPhase) {
        if (sasPhase == "peer_rejected") {
            rejectedByPeer = true
        }
    }

    // After our own tap: hold on the waiting screen until the peer's
    // confirmation lands ("confirmed") or the flow dies. While waiting,
    // "idle" alone means the flow died — the 90s pairing window expired
    // (SasReset) or the peer's side dropped (PeerLost resets the waiting
    // phases ~9s in, possibly while peerName is still populated; a fresh
    // pairing would set "showing", never "idle"). Do NOT also require the
    // peer to look gone: PeerLost fires before GhostTimeout clears
    // peerName, so that window would leave the spinner up forever.
    LaunchedEffect(sasPhase, waitingForPeer) {
        if (!waitingForPeer) return@LaunchedEffect
        when (sasPhase) {
            "confirmed" -> onConfirmed()
            "idle" -> peerTimedOut = true
        }
    }

    // Give the user a beat to read the failure line before leaving.
    LaunchedEffect(rejectedByPeer, peerTimedOut) {
        if (rejectedByPeer || peerTimedOut) {
            delay(1800)
            onRejected()
        }
    }

    Column(Modifier.fillMaxSize().background(FsDarkBg)) {
        Spacer(Modifier.height(36.dp))
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Shield badge, `.m-sas .shield` in the mockup.
            Box(
                Modifier
                    .size(52.dp)
                    .background(FsOkSoft, RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Default.VerifiedUser,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = FsAccent,
                )
            }
            Spacer(Modifier.height(12.dp))
            Text(
                "Verify the code",
                color = FsDarkFg,
                fontFamily = FsSans,
                fontWeight = FontWeight.ExtraBold,
                fontSize = 14.5.sp,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "These 6 words must match the ones on the other device. If they differ, reject.",
                color = FsDarkMuted,
                fontFamily = FsSans,
                fontSize = 11.sp,
                lineHeight = 17.sp,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(20.dp))

            when {
                failed -> Text(
                    "No pending pair surfaced by the daemon. Reject and scan again.",
                    color = FsCrit,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                rejectedByPeer -> Text(
                    "The other device rejected the words. Pairing cancelled.",
                    color = FsCrit,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                peerTimedOut -> Text(
                    "The other device did not confirm in time.",
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
                else -> Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    words.chunked(3).forEach { row ->
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            row.forEach { w ->
                                Box(
                                    Modifier
                                        .weight(1f)
                                        .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(8.dp))
                                        .background(FsCard, RoundedCornerShape(8.dp))
                                        .padding(vertical = 9.dp),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(
                                        w,
                                        color = FsDarkFg,
                                        fontFamily = FsMono,
                                        fontSize = 11.sp,
                                        maxLines = 1,
                                    )
                                }
                            }
                        }
                    }
                    when {
                        waitingForPeer -> {
                            Spacer(Modifier.height(16.dp))
                            CircularProgressIndicator(
                                color = FsDarkMuted,
                                modifier = Modifier.size(20.dp).align(Alignment.CenterHorizontally),
                                strokeWidth = 2.dp,
                            )
                            Spacer(Modifier.height(10.dp))
                            Text(
                                "Waiting for the other device…",
                                color = FsDarkMuted,
                                fontFamily = FsSans,
                                fontSize = 11.sp,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        // Peer confirmed before we tapped — quiet hint only,
                        // no navigation yet (mutual confirmation required).
                        sasPhase == "peer_confirmed" -> {
                            Spacer(Modifier.height(10.dp))
                            Text(
                                "Other device confirmed",
                                color = FsDarkMuted,
                                fontFamily = FsSans,
                                fontSize = 10.5.sp,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.weight(1f))
        // Buttons hidden once we're holding for the peer or the flow already
        // ended (peer rejected / timed out) — nothing left for the user to
        // tap; the LaunchedEffects above drive navigation from here.
        if (!waitingForPeer && !rejectedByPeer && !peerTimedOut) {
            Column(Modifier.fillMaxWidth().padding(20.dp)) {
                // Accept — only once words + peer_id are loaded.
                val canAccept = !busy && peerId != null && words.isNotEmpty()
                Box(
                    Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(FsRadius.Seg))
                        .background(if (canAccept) FsAccent else FsDarkBorderStrong)
                        .clickable(enabled = canAccept) {
                            busy = true
                            peerId?.let { vm.pairConfirm(it, true) }
                            // Mutual confirmation: only the peer's own tap
                            // moves sas_phase to "confirmed". If that already
                            // happened (defensive — the wire protocol can't
                            // reach "confirmed" before our own tap in
                            // practice) skip the wait; otherwise hold on the
                            // waiting state until it lands.
                            if (sasPhase == "confirmed") {
                                onConfirmed()
                            } else {
                                waitingForPeer = true
                            }
                        }
                        .padding(vertical = 12.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        "They match",
                        color = if (canAccept) FsOnAccent else FsDarkMuted,
                        fontFamily = FsSans,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.5.sp,
                    )
                }
                Spacer(Modifier.height(8.dp))
                // Reject — always available; also the escape hatch on failure.
                Box(
                    Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(FsRadius.Seg))
                        .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(FsRadius.Seg))
                        .clickable(enabled = !busy) {
                            busy = true
                            peerId?.let { vm.pairConfirm(it, false) }
                            onRejected()
                        }
                        .padding(vertical = 11.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        "They don't match",
                        color = FsCrit,
                        fontFamily = FsSans,
                        fontWeight = FontWeight.W600,
                        fontSize = 12.sp,
                    )
                }
            }
        } else {
            Spacer(Modifier.height(20.dp))
        }
    }
}
