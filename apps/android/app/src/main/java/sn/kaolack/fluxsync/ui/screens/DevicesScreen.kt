package sn.kaolack.fluxsync.ui.screens

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
 * Number of paired peers the daemon currently reports. The daemon
 * tracks at most one peer, so this is 0 or 1 — never counts "this
 * device", which is not a peer that can be linked or unlinked.
 */
internal fun pairedPeerCount(state: DaemonState): Int =
    if (state.peerName.isNotEmpty()) 1 else 0

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

    // Currently the daemon only reports 1 peer. We'll wrap it in a list to match spec.
    val devices = if (s.peerName.isNotEmpty()) listOf(s) else emptyList()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
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
                        "${devices.size} LINKED",
                        color = FsDarkSubtle,
                        style = MaterialTheme.typography.labelSmall
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
            items(devices) { d ->
                DeviceItem(
                    name = d.peerName,
                    batt = d.peerBattery,
                    charging = d.peerCharging,
                    threshold = s.threshold,
                    metrics = d.metrics,
                    onDisable = { scope.launch { vm.toggle(false) } },
                    onUnpair = { scope.launch { vm.unpair() } }
                )
            }
        }

        item {
            Box(
                Modifier
                    .fillMaxWidth()
                    .border(width = 1.dp, color = FsDarkBorderStrong, shape = RoundedCornerShape(4.dp))
                    .clickable { onAddDevice() }
                    .padding(14.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("+", color = FsCrit, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(8.dp))
                    Text("Pair new device", color = FsDarkFg, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
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
    batt: Int,
    charging: Boolean,
    threshold: Int,
    metrics: sn.kaolack.fluxsync.vm.ConnectionMetricsView?,
    onDisable: () -> Unit,
    onUnpair: () -> Unit,
) {
    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
            .background(FsDarkSurface, RoundedCornerShape(4.dp))
            .padding(14.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(color = FsOk, pulse = true)
                    Spacer(Modifier.width(6.dp))
                    Text(name, color = FsDarkFg, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                }
                Text("REMOTELY LINKED", color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            }
            Column(horizontalAlignment = Alignment.End) {
                BatteryGlyph(level = batt, charging = charging, threshold = threshold, width = 24.dp)
                Text("$batt%", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
            }
        }
        // Compact telemetry strip — RTT + reconnects, mono caption style.
        // Renders "—" placeholders before the daemon publishes metrics.
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            val rtt = metrics?.lastRttMs?.takeIf { it > 0 }?.let { "$it MS" } ?: "—"
            val reconnects = metrics?.reconnects ?: 0L
            Text(
                "RTT $rtt · $reconnects RECONNECTS",
                color = FsDarkSubtle,
                style = MaterialTheme.typography.labelSmall,
                fontSize = 10.sp,
            )
        }
        Spacer(Modifier.height(12.dp))
        androidx.compose.material3.HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Box(
                Modifier
                    .weight(1f)
                    .border(1.dp, FsDarkBorder, RoundedCornerShape(2.dp))
                    .clickable { onDisable() }
                    .padding(vertical = 6.dp),
                contentAlignment = Alignment.Center
            ) {
                Text("DISABLE", color = FsDarkFg, style = MaterialTheme.typography.labelSmall, fontSize = 11.sp)
            }
            Box(
                Modifier
                    .weight(1f)
                    .border(1.dp, FsCrit, RoundedCornerShape(2.dp))
                    .clickable { onUnpair() }
                    .padding(vertical = 6.dp),
                contentAlignment = Alignment.Center
            ) {
                Text("UNPAIR", color = FsCrit, style = MaterialTheme.typography.labelSmall, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun OwnDeviceCard(battery: Int, charging: Boolean, threshold: Int) {
    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
            .background(FsDarkSurface, RoundedCornerShape(4.dp))
            .padding(14.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(color = FsOk)
                    Spacer(Modifier.width(6.dp))
                    Text(Build.MODEL, color = FsDarkFg, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(6.dp))
                    Box(
                        Modifier
                            .border(1.dp, FsCrit, RoundedCornerShape(2.dp))
                            .padding(horizontal = 4.dp, vertical = 1.dp)
                    ) {
                        Text("THIS", color = FsCrit, style = MaterialTheme.typography.labelSmall, fontSize = 9.sp)
                    }
                }
                Text("THIS DEVICE", color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            }
            Column(horizontalAlignment = Alignment.End) {
                BatteryGlyph(level = battery, charging = charging, threshold = threshold, width = 24.dp)
                Text("$battery%", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}
