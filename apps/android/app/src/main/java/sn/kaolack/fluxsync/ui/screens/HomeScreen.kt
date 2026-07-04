package sn.kaolack.fluxsync.ui.screens

import android.widget.Toast
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
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
    var showClearHistoryConfirm by remember { mutableStateOf(false) }

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
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(11.dp),
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
        item { SectionLabel(title = "Conditions") }
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
                title = "Recent clipboard",
                right = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "${s.history.size} items",
                            color = FsDarkSubtle,
                            fontFamily = FsMono,
                            fontSize = 10.sp,
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "Clear",
                            color = FsDarkSubtle,
                            fontFamily = FsSans,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.W600,
                            modifier = Modifier.clickable { showClearHistoryConfirm = true },
                        )
                    }
                },
            )
        }
        if (s.history.isEmpty()) {
            item { EmptyHistory() }
        } else {
            items(s.history) { h ->
                RecentRow(h, onToggleFavorite = { vm.setFavorite(h.hash, !h.favorite) })
            }
        }
    }

    // "Clear clipboard history" (owner-requested, local-only — never synced
    // to the peer). Favorites are always kept from this screen; dropping
    // favorites too is CLI-only (`fluxctl history clear --all`).
    if (showClearHistoryConfirm) {
        AlertDialog(
            onDismissRequest = { showClearHistoryConfirm = false },
            containerColor = FsDarkSurface,
            title = { Text("Clear clipboard history?", color = FsDarkFg) },
            text = {
                Text(
                    "Removes recent clipboard items from this device only. " +
                        "Favorites are kept. This cannot be undone.",
                    color = FsDarkMuted,
                    style = MaterialTheme.typography.bodySmall,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    vm.clearHistory()
                    showClearHistoryConfirm = false
                }) {
                    Text("CLEAR", color = FsCrit)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearHistoryConfirm = false }) {
                    Text("CANCEL", color = FsDarkMuted)
                }
            },
        )
    }
}

private data class HeroVisuals(
    val borderColor: Color,
    val dotColor: Color,
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
    // 255 = battery not read yet → never "low"; only a real 0-100 trips it.
    val known = s.selfBattery in 0..100
    val below = known && s.selfBattery <= s.threshold
    val critical = known && s.selfBattery <= 5
    val charging = s.selfCharging
    val syncPaused = on && below && !charging

    // Connection truth comes from the FSM phase, not the on-toggle: with sync
    // enabled but no live peer the hero must say "Searching", not "Active".
    val phase = s.phase.lowercase()
    val linked = phase == "linked"
    val connecting = phase in setOf("discovering", "handshaking", "reconnecting", "idle")

    val visuals = when {
        !on -> HeroVisuals(FsDarkBorder, FsDarkSubtle, "Off — tap the switch to start syncing.")
        critical -> HeroVisuals(FsCrit.copy(alpha = 0.35f), FsCrit, "Halted — battery critical, all sync stopped.")
        syncPaused -> HeroVisuals(FsWarn.copy(alpha = 0.35f), FsWarn, "On hold — battery below ${s.threshold}%.")
        linked -> HeroVisuals(FsHeroOkBorder, FsAccent, "Active — synchronizing")
        connecting -> HeroVisuals(FsWarn.copy(alpha = 0.35f), FsWarn, "Searching for your device…")
        else -> HeroVisuals(FsDarkBorder, FsDarkSubtle, "Standby — no device linked.")
    }

    // Tween so transitions between states glide rather than snap.
    val animatedBorder by animateColorAsState(visuals.borderColor, animationSpec = tween(220), label = "hero-border")
    val animatedDot by animateColorAsState(visuals.dotColor, animationSpec = tween(220), label = "hero-dot")

    val shape = RoundedCornerShape(FsRadius.Hero)
    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = animatedBorder, shape = shape)
            .background(FsCard, shape)
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Clipboard sync",
                    color = FsDarkFg,
                    fontFamily = FsSans,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.5.sp,
                )
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(color = animatedDot, size = 7.dp, pulse = linked && !syncPaused && !critical)
                    Spacer(Modifier.width(7.dp))
                    AnimatedContent(
                        targetState = if (isStalled) "Connecting…" else visuals.sub,
                        transitionSpec = { fadeIn(tween(180)) togetherWith fadeOut(tween(120)) },
                        label = "hero-sub",
                    ) { sub ->
                        Text(sub, color = FsDarkMuted, fontFamily = FsSans, fontSize = 12.sp, maxLines = 1)
                    }
                }
            }
            FluxToggle(on = on, onChange = onToggle, size = FluxToggleSize.Md)
        }
        Spacer(Modifier.height(15.dp))
        LinkDiagram(linked = linked, dimmed = syncPaused)
    }
}

/** phone — beam — computer mini-diagram, `.ph-link` in the mockup. */
@Composable
private fun LinkDiagram(linked: Boolean, dimmed: Boolean) {
    val beam = when {
        linked && !dimmed -> FsAccent
        linked -> FsWarn.copy(alpha = 0.6f)
        else -> FsDarkBorderStrong
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(9.dp)) {
        LinkNode { DeviceGlyph(phone = true, color = FsDarkMuted) }
        Box(
            Modifier
                .weight(1f)
                .height(3.dp)
                .background(beam, RoundedCornerShape(2.dp)),
        )
        LinkNode { DeviceGlyph(phone = false, color = FsDarkMuted) }
    }
}

@Composable
private fun LinkNode(content: @Composable () -> Unit) {
    Box(
        Modifier
            .size(30.dp)
            .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.IconMd))
            .background(FsCardFlat, RoundedCornerShape(FsRadius.IconMd)),
        contentAlignment = Alignment.Center,
    ) { content() }
}

/** Outline phone / computer glyph, same stroke style as TabIcon. */
@Composable
private fun DeviceGlyph(phone: Boolean, color: Color) {
    androidx.compose.foundation.Canvas(Modifier.size(14.dp)) {
        val k = size.width / 16f
        val sw = 1.2f * k
        val stroke = androidx.compose.ui.graphics.drawscope.Stroke(width = sw)
        if (phone) {
            drawRoundRect(
                color = color,
                topLeft = androidx.compose.ui.geometry.Offset(4f * k, 1f * k),
                size = androidx.compose.ui.geometry.Size(8f * k, 14f * k),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(2f * k, 2f * k),
                style = stroke,
            )
        } else {
            drawRoundRect(
                color = color,
                topLeft = androidx.compose.ui.geometry.Offset(1f * k, 2.5f * k),
                size = androidx.compose.ui.geometry.Size(14f * k, 8.5f * k),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(1.5f * k, 1.5f * k),
                style = stroke,
            )
            drawLine(color, androidx.compose.ui.geometry.Offset(5f * k, 13.5f * k), androidx.compose.ui.geometry.Offset(11f * k, 13.5f * k), strokeWidth = sw)
            drawLine(color, androidx.compose.ui.geometry.Offset(8f * k, 11f * k), androidx.compose.ui.geometry.Offset(8f * k, 13.5f * k), strokeWidth = sw)
        }
    }
}

@Composable
private fun DeviceRow(s: DaemonState) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        DevicePill(
            label = "This device",
            // Friendly name (e.g. "Samsung SM-G998B"), matching what this
            // device advertises to the peer — not the raw cryptic Build.MODEL.
            name = sn.kaolack.fluxsync.FluxsyncAccessibilityService.formatPeerName(
                android.os.Build.MANUFACTURER,
                android.os.Build.MODEL,
            ),
            level = s.selfBattery,
            charging = s.selfCharging,
            threshold = s.threshold,
            modifier = Modifier.weight(1f),
            // 255 = not read yet (boot race) → "—", never a fake "255%".
            known = s.selfBattery in 0..100,
        )
        val peerConnected = s.phase.lowercase() in setOf("linked", "paused", "halted")
        DevicePill(
            label = sn.kaolack.fluxsync.vm.platformLabel(s.peerPlatform)
                ?.let { "Peer · $it" } ?: "Peer",
            name = s.peerName.ifEmpty { "..." },
            level = s.peerBattery,
            charging = s.peerCharging,
            threshold = s.threshold,
            modifier = Modifier.weight(1f),
            // Real % only when connected AND a reading has arrived (≤100).
            known = peerConnected && s.peerBattery in 0..100,
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
    known: Boolean = true,
) {
    val shape = RoundedCornerShape(FsRadius.Pill)
    Column(
        modifier = modifier
            .border(width = 1.dp, color = FsDarkBorder, shape = shape)
            .background(FsCard, shape)
            .padding(13.dp),
    ) {
        Text(
            label,
            color = FsDarkSubtle,
            fontFamily = FsSans,
            fontWeight = FontWeight.W600,
            fontSize = 10.5.sp,
            maxLines = 1,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            name,
            color = FsDarkFg,
            fontFamily = FsSans,
            fontWeight = FontWeight.W600,
            fontSize = 12.5.sp,
            maxLines = 1,
        )
        Spacer(Modifier.height(9.dp))
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            // Until linked + first BatteryStatus arrives, peerBattery holds the
            // 100% default — show a neutral "—" so the reading is never wrong.
            BatteryGlyph(level = if (known) level else 0, charging = known && charging, threshold = threshold, width = 30.dp)
            Text(
                if (known) "$level%${if (charging) " ⚡" else ""}" else "—",
                color = FsDarkMuted,
                fontFamily = FsMono,
                fontSize = 10.5.sp,
            )
        }
    }
}

@Composable
private fun ConditionsPanel(s: DaemonState, onThresholdChange: (Int) -> Unit, onChargeOverrideChange: (Boolean) -> Unit) {
    val below = s.selfBattery <= s.threshold
    val delta = s.selfBattery - s.threshold

    val shape = RoundedCornerShape(FsRadius.Item)
    Column(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = shape)
            .background(FsCard, shape)
            .padding(14.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Column {
                Text("Pause sync below", color = FsDarkMuted, fontFamily = FsSans, fontWeight = FontWeight.W600, fontSize = 11.sp)
                Text("${s.threshold}%", color = FsDarkFg, fontFamily = FsMono, fontWeight = FontWeight.SemiBold, fontSize = 20.sp)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("Status", color = FsDarkSubtle, fontFamily = FsSans, fontWeight = FontWeight.W600, fontSize = 10.5.sp)
                Text(
                    if (below) "${-delta}% below" else "$delta% above",
                    color = if (below) FsWarn else FsAccent,
                    fontFamily = FsMono,
                    fontSize = 11.sp,
                )
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
private fun RecentRow(h: HistoryItem, onToggleFavorite: () -> Unit) {
    val shape = RoundedCornerShape(FsRadius.Item)
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    // Text rows carry their full payload in `preview`; tapping copies it back.
    // Image previews are just a size label, so those rows aren't copyable.
    val copyable = h.kind.lowercase() != "image" && h.preview.isNotEmpty()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .border(width = 1.dp, color = FsDarkBorder, shape = shape)
            .background(FsCard, shape)
            .then(
                if (copyable) {
                    Modifier.clickable {
                        clipboard.setText(AnnotatedString(h.preview))
                        Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Modifier
                }
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        KindIcon(h.kind)
        Spacer(Modifier.width(10.dp))
        Text(h.preview, color = FsDarkFg, fontFamily = FsSans, fontSize = 12.sp, maxLines = 1, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        Text(
            if (h.favorite) "★" else "☆",
            color = if (h.favorite) FsWarn else FsDarkSubtle,
            fontSize = 14.sp,
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .clickable(onClick = onToggleFavorite)
                .padding(horizontal = 4.dp, vertical = 2.dp),
        )
        Spacer(Modifier.width(8.dp))
        if (copyable) {
            Text("Copy", color = FsDarkMuted, fontFamily = FsSans, fontSize = 9.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(8.dp))
        }
        Text(h.time.ifEmpty { "—" }, color = FsDarkSubtle, fontFamily = FsMono, fontSize = 10.sp)
    }
}

/** 26dp rounded square with a per-kind glyph, `.ph-item .ic` in the mockup. */
@Composable
private fun KindIcon(kind: String) {
    val image = kind.lowercase() == "image"
    val shape = RoundedCornerShape(FsRadius.IconSm)
    val bg = if (image) Color(0xFF34506E) else FsCardFlat
    val fg = if (image) Color(0xFFA8C3E2) else FsDarkMuted
    Box(
        Modifier
            .size(26.dp)
            .then(if (image) Modifier else Modifier.border(1.dp, FsDarkBorder, shape))
            .background(bg, shape),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.foundation.Canvas(Modifier.size(11.dp)) {
            val k = size.width / 12f
            val sw = 1.2f * k
            when (kind.lowercase()) {
                "image" -> {
                    drawCircle(fg, radius = 1.2f * k, center = androidx.compose.ui.geometry.Offset(4f * k, 4.5f * k), style = androidx.compose.ui.graphics.drawscope.Stroke(sw))
                    drawPath(
                        androidx.compose.ui.graphics.vector.PathParser().parsePathString("M0 9.5l3.5-3.5L12 12").toPath().apply {},
                        color = fg,
                        style = androidx.compose.ui.graphics.drawscope.Stroke(sw),
                    )
                }
                else -> {
                    // three text lines
                    drawLine(fg, androidx.compose.ui.geometry.Offset(2f * k, 2.5f * k), androidx.compose.ui.geometry.Offset(10f * k, 2.5f * k), strokeWidth = sw)
                    drawLine(fg, androidx.compose.ui.geometry.Offset(2f * k, 6f * k), androidx.compose.ui.geometry.Offset(10f * k, 6f * k), strokeWidth = sw)
                    drawLine(fg, androidx.compose.ui.geometry.Offset(2f * k, 9.5f * k), androidx.compose.ui.geometry.Offset(7f * k, 9.5f * k), strokeWidth = sw)
                }
            }
        }
    }
}

@Composable
private fun EmptyHistory() {
    val shape = RoundedCornerShape(FsRadius.Item)
    Box(
        Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = shape)
            .background(FsCard, shape)
            .padding(20.dp),
        contentAlignment = Alignment.Center
    ) {
        Text("No items yet — copy something on the other device.", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall)
    }
}
