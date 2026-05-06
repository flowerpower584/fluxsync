package sn.kaolack.fluxsync.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import sn.kaolack.fluxsync.ui.components.*
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.vm.DaemonState
import sn.kaolack.fluxsync.vm.FluxsyncViewModel
import sn.kaolack.fluxsync.vm.HistoryItem

/**
 * Screen 01: Home
 * Displays the hero status card, master toggle, peer details, and recent clipboard history.
 */
@Composable
fun HomeScreen(vm: FluxsyncViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val s = state ?: return

    // Optimistic toggle state. While set, the UI shows `pendingOn`
    // instead of the daemon-reported `s.active`, so the switch flips
    // instantly even before the IPC round-trip completes.
    var pendingOn by remember { mutableStateOf<Boolean?>(null) }
    var isIPCStalled by remember { mutableStateOf(false) }

    LaunchedEffect(s.active) {
        if (pendingOn != null && pendingOn == s.active) {
            pendingOn = null
            isIPCStalled = false
        }
    }

    LaunchedEffect(pendingOn) {
        if (pendingOn != null) {
            isIPCStalled = false
            kotlinx.coroutines.delay(2000)
            if (pendingOn != null) {
                isIPCStalled = true
            }
            // Increase safety net to 10s before giving up entirely
            kotlinx.coroutines.delay(8000)
            pendingOn = null
            isIPCStalled = false
        }
    }
    val displayedOn = pendingOn ?: s.active

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            HeroCard(
                s = s,
                displayedOn = displayedOn,
                isStalled = isIPCStalled,
                onToggle = { v ->
                    pendingOn = v
                    scope.launch { vm.toggle(v) }
                },
            )
        }
        item { DeviceRow(s) }
        item {
            SectionLabel(
                title = "Conditions",
                right = { E2EBadge() },
            )
        }
        item {
            ConditionsPanel(
                s = s,
                onThresholdChange = { v ->
                    scope.launch { vm.setBatteryThreshold(v.toUByte()) }
                },
                onChargeOverrideChange = { v ->
                    scope.launch { vm.setChargeOverride(v) }
                },
            )
        }
        item {
            SectionLabel(
                title = "Recent",
                right = {
                    Text(
                        "${s.history.size} ITEMS",
                        color = FsDarkSubtle,
                        style = MaterialTheme.typography.labelSmall,
                    )
                },
            )
        }
        if (s.history.isEmpty()) {
            item { EmptyHistory() }
        } else {
            items(s.history.take(4)) { h ->
                RecentRow(h)
            }
        }
    }
}

private data class HeroVisuals(
    val borderColor: Color,
    val bg: Color,
    val dotColor: Color,
    val statusLabel: String,
    val title: String,
    val sub: String,
)

@Composable
private fun HeroCard(
    s: DaemonState,
    displayedOn: Boolean,
    isStalled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    val on = displayedOn
    val below = s.selfBattery <= s.threshold
    val critical = s.selfBattery <= 5
    val charging = s.selfCharging
    val syncPaused = on && below && !charging

    val visuals = when {
        !on -> HeroVisuals(FsDarkBorder, FsDarkSurface, Color(0xFF52525B), "INACTIVE", "Offline", "Tap the switch to start sharing your clipboard.")
        critical -> HeroVisuals(FsCrit, FsCritSoft, FsCrit, "CRITICAL", "Halted", "Battery critical. All sync stopped.")
        syncPaused -> HeroVisuals(FsWarn, FsWarnSoft, FsWarn, "PAUSED", "On hold", "Battery below ${s.threshold}%. Resumes when you charge.")
        else -> HeroVisuals(FsOk, FsDarkSurface, FsOk, "SYNCHRONIZING", "Live", "Linked with ${s.peerName.ifEmpty { "..." }}.")
    }

    // Tween the colors so transitions between Inactive/Live/Paused/Halted
    // glide rather than snap. 220 ms feels responsive without smearing.
    val animatedBorder by animateColorAsState(visuals.borderColor, animationSpec = tween(220), label = "hero-border")
    val animatedBg by animateColorAsState(visuals.bg, animationSpec = tween(220), label = "hero-bg")
    val animatedDot by animateColorAsState(visuals.dotColor, animationSpec = tween(220), label = "hero-dot")

    Box(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = animatedBorder, shape = RoundedCornerShape(4.dp))
            .background(animatedBg, RoundedCornerShape(4.dp))
            .padding(18.dp),
    ) {
        Row(verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(color = animatedDot, pulse = on && !syncPaused && !critical)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        if (isStalled) "CONNECTING…" else visuals.statusLabel,
                        color = animatedDot,
                        style = MaterialTheme.typography.labelMedium,
                        letterSpacing = 1.sp
                    )
                }
                Spacer(Modifier.height(8.dp))
                AnimatedContent(
                    targetState = visuals.title,
                    transitionSpec = { fadeIn(tween(180)) togetherWith fadeOut(tween(120)) },
                    label = "hero-title",
                ) { title ->
                    Text(title, color = FsDarkFg, style = MaterialTheme.typography.headlineSmall)
                }
                Spacer(Modifier.height(4.dp))
                AnimatedContent(
                    targetState = visuals.sub,
                    transitionSpec = { fadeIn(tween(180)) togetherWith fadeOut(tween(120)) },
                    label = "hero-sub",
                ) { sub ->
                    Text(sub, color = FsDarkMuted, style = MaterialTheme.typography.bodySmall)
                }
            }
            FluxToggle(on = on, onChange = onToggle, size = FluxToggleSize.Md)
        }
    }
}

@Composable
private fun DeviceRow(s: DaemonState) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        DevicePill(
            label = "THIS DEVICE",
            name = android.os.Build.MODEL,
            level = s.selfBattery,
            charging = s.selfCharging,
            threshold = s.threshold,
            modifier = Modifier.weight(1f),
        )
        DevicePill(
            label = "PEER",
            name = s.peerName.ifEmpty { "..." },
            level = s.peerBattery,
            charging = s.peerCharging,
            threshold = s.threshold,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun DevicePill(
    label: String,
    name: String,
    level: Int,
    charging: Boolean,
    threshold: Int,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
            .background(FsDarkSurface, RoundedCornerShape(4.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(label, color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall)
        Spacer(Modifier.height(4.dp))
        Text(name, color = FsDarkFg, style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium), maxLines = 1)
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            BatteryGlyph(level = level, charging = charging, threshold = threshold, width = 24.dp)
            Text("$level%${if (charging) "⚡" else ""}", color = batteryToneFor(level, threshold), style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun ConditionsPanel(s: DaemonState, onThresholdChange: (Int) -> Unit, onChargeOverrideChange: (Boolean) -> Unit) {
    val below = s.selfBattery <= s.threshold
    val delta = s.selfBattery - s.threshold

    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
            .background(FsDarkSurface, RoundedCornerShape(4.dp))
            .padding(14.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Column {
                Text("PAUSE SYNC BELOW", color = FsDarkMuted, style = MaterialTheme.typography.labelMedium)
                Text("${s.threshold}%", color = FsDarkFg, style = MaterialTheme.typography.titleLarge)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("STATUS", color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall)
                Text(if (below) "${-delta}% BELOW" else "$delta% ABOVE", color = if (below) FsWarn else FsOk, style = MaterialTheme.typography.labelMedium)
            }
        }
        Spacer(Modifier.height(12.dp))
        ThresholdSlider(value = s.threshold, onChange = onThresholdChange, min = 5, max = 50)
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Resume while charging", color = FsDarkFg, style = MaterialTheme.typography.bodySmall)
                Text("Override threshold when plugged in", color = FsDarkMuted, style = MaterialTheme.typography.labelLarge)
            }
            FluxToggle(on = s.chargeOverride, onChange = onChargeOverrideChange, size = FluxToggleSize.Sm)
        }
    }
}

@Composable
private fun RecentRow(h: HistoryItem) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
            .background(FsDarkSurface, RoundedCornerShape(4.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(h.kind.uppercase(), color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall, modifier = Modifier.width(28.dp))
        Spacer(Modifier.width(10.dp))
        Text(h.preview, color = FsDarkFg, style = MaterialTheme.typography.bodySmall, maxLines = 1, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(10.dp))
        Text(h.time.ifEmpty { "—" }, color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun EmptyHistory() {
    Box(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
            .background(FsDarkSurface, RoundedCornerShape(4.dp))
            .padding(20.dp),
        contentAlignment = Alignment.Center
    ) {
        Text("No items yet — copy something on the other device.", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall)
    }
}
