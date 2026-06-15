package sn.kaolack.fluxsync.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import sn.kaolack.fluxsync.ui.components.FluxToggle
import sn.kaolack.fluxsync.ui.components.FluxToggleSize
import sn.kaolack.fluxsync.ui.components.SectionLabel
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.vm.FirewallPolicyView
import sn.kaolack.fluxsync.vm.PendingItemView
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * Screen 05: Firewall.
 * Per-content-type policy (Allow / Ask / Deny) plus the pending-decisions
 * queue for items the daemon parked under an Ask rule. Without this screen an
 * Ask-held item would block forever on Android — the daemon waits for a
 * resolve that only the UI can send.
 */
@Composable
fun FirewallScreen(vm: FluxsyncViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val s = state ?: return
    val fw = s.firewall

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Pending decisions surface first — they're time-sensitive.
        if (s.pending.isNotEmpty()) {
            item {
                Column {
                    SectionLabel(title = "Pending decisions")
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        s.pending.forEach { p ->
                            PendingCard(
                                item = p,
                                onApprove = { vm.resolvePending(p.hash, true) },
                                onReject = { vm.resolvePending(p.hash, false) },
                            )
                        }
                    }
                }
            }
        }

        item {
            FwGroup(title = "Firewall") {
                FwRow(
                    label = "Clipboard firewall",
                    hint = if (fw.enabled) "Rules below are enforced"
                    else "Off — every clipboard item passes",
                    isLast = true,
                ) {
                    FluxToggle(
                        on = fw.enabled,
                        onChange = { vm.setFirewall(fw.copy(enabled = it)) },
                        size = FluxToggleSize.Sm,
                    )
                }
            }
        }

        item {
            Column(Modifier.alpha(if (fw.enabled) 1f else 0.4f)) {
                SectionLabel(title = "Rules per content type")
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.Item))
                        .background(FsCard, RoundedCornerShape(FsRadius.Item)),
                ) {
                    RuleRow("Text", "Plain text snippets", "text", fw, vm)
                    RuleRow("Links", "URLs copied to the clipboard", "url", fw, vm)
                    RuleRow("Code", "Code-shaped content", "code", fw, vm)
                    RuleRow("Images", "PNG image payloads", "image", fw, vm)
                    RuleRow(
                        "Secrets", "Detected keys, tokens & passwords",
                        "sensitive", fw, vm, isLast = true,
                    )
                }
            }
        }
    }
}

// ── Pending queue ──────────────────────────────────────────────────────────

@Composable
private fun PendingCard(item: PendingItemView, onApprove: () -> Unit, onReject: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, FsWarnSoft, RoundedCornerShape(FsRadius.Item))
            .background(FsCard, RoundedCornerShape(FsRadius.Item))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                directionLabel(item.direction) + " · " + item.kind.uppercase(),
                color = FsWarn,
                fontFamily = FsMono,
                fontSize = 9.sp,
                fontWeight = FontWeight.W600,
            )
            if (item.sensitive) {
                Text(
                    "SECRET",
                    color = FsCrit,
                    fontFamily = FsMono,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.W600,
                )
            }
        }
        Text(
            item.preview.ifEmpty { "(no preview)" },
            color = FsDarkFg,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 3,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DecisionButton("REJECT", FsCrit, FsCritSoft, Modifier.weight(1f), onReject)
            DecisionButton("APPROVE", FsOk, FsOkSoft, Modifier.weight(1f), onApprove)
        }
    }
}

@Composable
private fun DecisionButton(
    label: String,
    fg: Color,
    bg: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(FsRadius.Item))
            .background(bg)
            .border(1.dp, fg.copy(alpha = 0.4f), RoundedCornerShape(FsRadius.Item))
            .clickable(onClick = onClick)
            .padding(vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, color = fg, fontFamily = FsMono, fontSize = 11.sp, fontWeight = FontWeight.W600)
    }
}

private fun directionLabel(direction: String): String =
    if (direction == "outbound") "OUTGOING" else "INCOMING"

// ── Rule rows ──────────────────────────────────────────────────────────────

@Composable
private fun RuleRow(
    label: String,
    hint: String,
    field: String,
    fw: FirewallPolicyView,
    vm: FluxsyncViewModel,
    isLast: Boolean = false,
) {
    Column(Modifier.padding(14.dp)) {
        Text(label, color = FsDarkFg, style = MaterialTheme.typography.bodySmall)
        Text(hint, color = FsDarkMuted, style = MaterialTheme.typography.labelLarge, fontSize = 11.sp)
        Spacer(Modifier.height(10.dp))
        RuleSelector(
            current = fw.ruleFor(field),
            enabled = fw.enabled,
            onPick = { rule -> vm.setFirewall(fw.withRule(field, rule)) },
        )
    }
    if (!isLast) {
        androidx.compose.material3.HorizontalDivider(
            modifier = Modifier.padding(horizontal = 14.dp),
            thickness = 1.dp,
            color = FsDarkBorder,
        )
    }
}

@Composable
private fun RuleSelector(current: String, enabled: Boolean, onPick: (String) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(FsRadius.Pill))
            .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.Pill)),
    ) {
        RuleChip("allow", "ALLOW", current, FsOk, FsOkSoft, enabled, Modifier.weight(1f), onPick)
        RuleChip("ask", "ASK", current, FsWarn, FsWarnSoft, enabled, Modifier.weight(1f), onPick)
        RuleChip("deny", "DENY", current, FsCrit, FsCritSoft, enabled, Modifier.weight(1f), onPick)
    }
}

@Composable
private fun RuleChip(
    value: String,
    label: String,
    current: String,
    fg: Color,
    bg: Color,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    onPick: (String) -> Unit,
) {
    val active = current == value
    Box(
        modifier = modifier
            .background(if (active) bg else Color.Transparent)
            .let { if (enabled) it.clickable { onPick(value) } else it }
            .padding(vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            label,
            color = if (active) fg else FsDarkSubtle,
            fontFamily = FsMono,
            fontSize = 10.sp,
            fontWeight = FontWeight.W600,
        )
    }
}

@Composable
private fun FwGroup(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column {
        SectionLabel(title = title)
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.Item))
                .background(FsCard, RoundedCornerShape(FsRadius.Item)),
        ) { content() }
    }
}

@Composable
private fun FwRow(
    label: String,
    hint: String,
    isLast: Boolean = false,
    right: @Composable () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = FsDarkFg, style = MaterialTheme.typography.bodySmall)
            Text(hint, color = FsDarkMuted, style = MaterialTheme.typography.labelLarge, fontSize = 11.sp)
        }
        right()
    }
    if (!isLast) {
        androidx.compose.material3.HorizontalDivider(
            modifier = Modifier.padding(horizontal = 14.dp),
            thickness = 1.dp,
            color = FsDarkBorder,
        )
    }
}
