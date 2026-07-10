package sn.kaolack.fluxsync.ui.screens

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import sn.kaolack.fluxsync.ui.components.BatteryGlyph
import sn.kaolack.fluxsync.ui.components.LoadingState
import sn.kaolack.fluxsync.ui.components.SectionLabel
import sn.kaolack.fluxsync.ui.components.StatusDot
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.vm.DaemonState
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * Number of paired peers the daemon currently reports. FluxMesh Phase 3:
 * the daemon now reports a full mesh `peers` list, so this can exceed 1;
 * it falls back to the legacy single-peer projection for an older daemon.
 * Never counts "this device", which is not a linkable peer.
 */
internal fun pairedPeerCount(state: DaemonState): Int = when {
    state.peers.isNotEmpty() -> state.peers.size
    state.peerName.isNotEmpty() -> 1
    else -> 0
}

/**
 * Screen 02: Devices
 * Displays all paired peers and allows initiating a new pairing flow.
 */
@Composable
fun DevicesScreen(vm: FluxsyncViewModel, onAddDevice: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val s = state
    if (s == null) {
        LoadingState()
        return
    }

    // FluxMesh Phase 3: render the full mesh `peers` list. Fall back to the
    // legacy single-peer projection when talking to an older daemon that
    // doesn't send `peers`.
    val devices: List<sn.kaolack.fluxsync.vm.MeshPeer> = when {
        s.peers.isNotEmpty() -> s.peers
        s.peerName.isNotEmpty() -> listOf(
            sn.kaolack.fluxsync.vm.MeshPeer(
                peerId = "",
                name = s.peerName,
                platform = s.peerPlatform,
                battery = s.peerBattery,
                charging = s.peerCharging,
                primary = true,
            )
        )
        else -> emptyList()
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(11.dp)
    ) {
        item { SectionLabel(title = "This device") }

        item {
            OwnDeviceCard(
                battery = s.selfBattery,
                charging = s.selfCharging,
                threshold = s.threshold,
            )
        }

        item { Spacer(Modifier.height(16.dp)) }

        item {
            SectionLabel(
                title = "Paired peers",
                right = {
                    Text(
                        "${devices.size} linked",
                        color = FsDarkSubtle,
                        fontFamily = FsMono,
                        fontSize = 10.sp,
                    )
                }
            )
        }

        if (devices.isEmpty()) {
            item {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .padding(vertical = 32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text("No peers paired yet.", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            items(devices, key = { it.peerId.ifEmpty { it.name } }) { d ->
                DeviceItem(
                    name = d.name.ifEmpty { "(unknown)" },
                    platform = d.platform,
                    batt = d.battery,
                    charging = d.charging,
                    threshold = s.threshold,
                    // Only the primary link carries metrics + the Disable
                    // action. Unpair is peer-scoped for every card (daemon
                    // `revoke`) whenever a peer_id is available — it drops
                    // only that device, leaving every other paired peer
                    // linked. The legacy single-peer projection (older
                    // daemon, no peer_id) falls back to the global op, but
                    // there is only ever one peer to unpair in that case.
                    metrics = if (d.primary) s.metrics else null,
                    primary = d.primary,
                    peerId = d.peerId,
                    onDisable = { scope.launch { vm.toggle(false) } },
                    onUnpair = {
                        scope.launch {
                            if (d.peerId.isNotEmpty()) vm.revoke(d.peerId) else vm.unpair()
                        }
                    },
                )
            }
        }

        item {
            val dashShape = RoundedCornerShape(12.dp)
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(dashShape)
                    .clickable { onAddDevice() }
                    .drawBehind {
                        val stroke = androidx.compose.ui.graphics.drawscope.Stroke(
                            width = 1.dp.toPx(),
                            pathEffect = androidx.compose.ui.graphics.PathEffect.dashPathEffect(floatArrayOf(8f, 6f)),
                        )
                        drawRoundRect(
                            color = FsDarkBorderStrong,
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(13.dp.toPx()),
                            style = stroke,
                        )
                    }
                    .padding(14.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("+", color = FsAccent, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(8.dp))
                    Text("Pair new device", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                }
            }
            Text(
                "via QR code · 6-digit fallback",
                color = FsDarkSubtle,
                style = MaterialTheme.typography.labelSmall,
                fontSize = 10.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
}

@Composable
private fun DeviceItem(
    name: String,
    platform: String,
    batt: Int,
    charging: Boolean,
    threshold: Int,
    metrics: sn.kaolack.fluxsync.vm.ConnectionMetricsView?,
    primary: Boolean,
    peerId: String,
    onDisable: () -> Unit,
    onUnpair: () -> Unit,
) {
    var showUnpairConfirm by remember { mutableStateOf(false) }
    val shape = RoundedCornerShape(FsRadius.Item)
    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = shape)
            .background(FsCard, shape)
            .padding(14.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(color = FsAccent, pulse = true)
                    Spacer(Modifier.width(6.dp))
                    Text(name, color = FsDarkFg, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                }
                val linkLabel = sn.kaolack.fluxsync.vm.platformLabel(platform)
                    ?.let { "$it · linked" } ?: "linked"
                Text(linkLabel, color = FsDarkSubtle, fontFamily = FsSans, fontSize = 10.5.sp, modifier = Modifier.padding(top = 4.dp))
            }
            Column(horizontalAlignment = Alignment.End) {
                BatteryGlyph(level = batt, charging = charging, threshold = threshold, width = 30.dp)
                Text("$batt%", color = FsDarkMuted, fontFamily = FsMono, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }
        // Compact telemetry strip — RTT + reconnects, mono caption style.
        // Renders "—" placeholders before the daemon publishes metrics.
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            val rtt = metrics?.lastRttMs?.takeIf { it > 0 }?.let { "$it ms" } ?: "—"
            val reconnects = metrics?.reconnects ?: 0L
            Text(
                "rtt $rtt · $reconnects reconnects",
                color = FsDarkSubtle,
                fontFamily = FsMono,
                fontSize = 10.sp,
            )
        }
        // Disable acts on the primary link only. Unpair is peer-scoped for
        // every card — it revokes just this device, leaving every other
        // paired peer linked.
        if (primary) {
            Spacer(Modifier.height(12.dp))
            androidx.compose.material3.HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(
                    Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(8.dp))
                        .clickable { onDisable() }
                        .padding(vertical = 7.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text("Disable", color = FsDarkFg, fontFamily = FsSans, fontWeight = FontWeight.W600, fontSize = 11.sp)
                }
                Box(
                    Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(8.dp))
                        .clickable { showUnpairConfirm = true }
                        .padding(vertical = 7.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text("Unpair", color = FsCrit, fontFamily = FsSans, fontWeight = FontWeight.W600, fontSize = 11.sp)
                }
            }
        } else if (peerId.isNotEmpty()) {
            // Secondary mesh peer: a single per-peer unpair that revokes
            // just this device (the daemon `revoke` op), leaving the
            // primary and any other peers linked.
            Spacer(Modifier.height(12.dp))
            androidx.compose.material3.HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
            Spacer(Modifier.height(12.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(8.dp))
                    .clickable { showUnpairConfirm = true }
                    .padding(vertical = 7.dp),
                contentAlignment = Alignment.Center
            ) {
                Text("Unpair", color = FsCrit, fontFamily = FsSans, fontWeight = FontWeight.W600, fontSize = 11.sp)
            }
        }
    }

    if (showUnpairConfirm) {
        AlertDialog(
            onDismissRequest = { showUnpairConfirm = false },
            containerColor = FsDarkSurface,
            title = { Text("Unpair $name?", color = FsDarkFg) },
            text = {
                Text(
                    "Removes only this device. Other paired devices stay linked. This cannot be undone.",
                    color = FsDarkMuted,
                    style = MaterialTheme.typography.bodySmall,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onUnpair()
                    showUnpairConfirm = false
                }) {
                    Text("UNPAIR", color = FsCrit)
                }
            },
            dismissButton = {
                TextButton(onClick = { showUnpairConfirm = false }) {
                    Text("CANCEL", color = FsDarkMuted)
                }
            },
        )
    }
}

@Composable
private fun OwnDeviceCard(battery: Int, charging: Boolean, threshold: Int) {
    val shape = RoundedCornerShape(FsRadius.Item)
    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = shape)
            .background(FsCard, shape)
            .padding(14.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(color = FsAccent)
                    Spacer(Modifier.width(6.dp))
                    Text(Build.MODEL, color = FsDarkFg, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(6.dp))
                    Box(
                        Modifier
                            .background(FsOkSoft, RoundedCornerShape(5.dp))
                            .padding(horizontal = 5.dp, vertical = 1.dp)
                    ) {
                        Text("this", color = FsAccent, fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 9.sp)
                    }
                }
                Text("This device", color = FsDarkSubtle, fontFamily = FsSans, fontSize = 10.5.sp, modifier = Modifier.padding(top = 4.dp))
            }
            Column(horizontalAlignment = Alignment.End) {
                BatteryGlyph(level = battery, charging = charging, threshold = threshold, width = 30.dp)
                Text("$battery%", color = FsDarkMuted, fontFamily = FsMono, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}
