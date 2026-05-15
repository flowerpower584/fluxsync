package sn.kaolack.fluxsync.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import sn.kaolack.fluxsync.BuildConfig
import sn.kaolack.fluxsync.ui.components.FluxToggle
import sn.kaolack.fluxsync.ui.components.FluxToggleSize
import sn.kaolack.fluxsync.ui.components.SectionLabel
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * Screen 04: Settings
 * Comprehensive configuration for battery limits, security, and network discovery.
 */
@Composable
fun SettingsScreen(vm: FluxsyncViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val s = state ?: return

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)
    ) {
        item {
            SettingsGroup(title = "General") {
                SettingsItem(
                    label = "Battery threshold",
                    hint = "Pause sync below ${s.threshold}%",
                    right = { Text("${s.threshold}% ›", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall) }
                )
                SettingsItem(
                    label = "Resume on charge",
                    hint = "Override threshold when plugged in",
                    right = {
                        FluxToggle(on = s.chargeOverride, onChange = {
                            scope.launch { vm.setChargeOverride(it) }
                        }, size = FluxToggleSize.Sm)
                    },
                    isLast = true
                )
            }
        }

        item {
            SettingsGroup(title = "Security") {
                SettingsItem(
                    label = "Device fingerprint",
                    hint = "Your public key — share for verification",
                    right = { Text("1A4F·8D2C ›", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp) }
                )
                SettingsItem(
                    label = "Rotate keys",
                    hint = "Re-generate identity, requires re-pair",
                    right = { Text("ACTION ›", color = FsWarn, style = MaterialTheme.typography.labelSmall) }
                )
                SettingsItem(
                    label = "Unpair all devices",
                    hint = "Remove every linked peer",
                    right = { Text("ACTION ›", color = FsCrit, style = MaterialTheme.typography.labelSmall) },
                    isLast = true
                )
            }
        }

        item {
            SettingsGroup(title = "Network") {
                SettingsItem(
                    label = "Listen port",
                    right = { Text("7841 ›", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall) }
                )
                // Prefer-LAN is hardcoded ON in the daemon today and the
                // toggle isn't wired to any IPC op — disable it visually
                // so the UI doesn't pretend to give the user a choice.
                SettingsItem(
                    label = "Prefer LAN",
                    hint = "Direct local connection when available",
                    right = { FluxToggle(on = true, onChange = {}, size = FluxToggleSize.Sm, enabled = false) }
                )
                SettingsItem(
                    label = "Relay fallback",
                    hint = "Use STUN relay if LAN fails (v0.8)",
                    right = { FluxToggle(on = false, onChange = {}, size = FluxToggleSize.Sm, enabled = false) },
                    isLast = true
                )
            }
        }

        item {
            SettingsGroup(title = "Telemetry") {
                val m = s.metrics
                SettingsItem(
                    label = "Round-trip latency",
                    hint = "Last measured RTT to peer",
                    right = {
                        Text(
                            if (m != null && m.lastRttMs > 0) "${m.lastRttMs} MS" else "—",
                            color = FsDarkMuted,
                            style = MaterialTheme.typography.labelSmall,
                        )
                    },
                )
                SettingsItem(
                    label = "RTT p99",
                    hint = "99th percentile across the session",
                    right = {
                        Text(
                            if (m != null && m.rttP99Ms > 0) "${m.rttP99Ms} MS" else "—",
                            color = FsDarkMuted,
                            style = MaterialTheme.typography.labelSmall,
                        )
                    },
                )
                SettingsItem(
                    label = "Reconnects",
                    hint = "Transport drops since the daemon started",
                    right = {
                        Text(
                            "${m?.reconnects ?: 0L}",
                            color = FsDarkMuted,
                            style = MaterialTheme.typography.labelSmall,
                        )
                    },
                )
                SettingsItem(
                    label = "Session uptime",
                    hint = "Time since last successful handshake",
                    right = {
                        Text(
                            fmtUptime(m?.uptimeSessionSecs),
                            color = FsDarkMuted,
                            style = MaterialTheme.typography.labelSmall,
                        )
                    },
                    isLast = true,
                )
            }
        }

        item {
            var notifyOnPair by remember { mutableStateOf(true) }
            SettingsGroup(title = "Notifications") {
                SettingsItem(
                    label = "On new pair request",
                    right = {
                        FluxToggle(on = notifyOnPair, onChange = { notifyOnPair = it }, size = FluxToggleSize.Sm)
                    },
                    isLast = true
                )
            }
        }

        item {
            SettingsGroup(title = "About") {
                SettingsItem(
                    label = "Version",
                    right = { Text(s.version.ifEmpty { "0.5.0" }, color = FsDarkMuted, style = MaterialTheme.typography.labelSmall) }
                )
                SettingsItem(
                    label = "Build",
                    right = { Text(BuildConfig.GIT_SHA, color = FsDarkMuted, style = MaterialTheme.typography.labelSmall) }
                )
                SettingsItem(
                    label = "License",
                    right = { Text("MIT ›", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall) }
                )
                SettingsItem(
                    label = "Source",
                    right = { Text("github ›", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall) },
                    isLast = true
                )
            }
        }

        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("FLUXSYNC", color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall, fontSize = 9.sp)
                Spacer(Modifier.height(4.dp))
                Text("Crafted in Kaolack 🇸🇳", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun SettingsGroup(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column {
        SectionLabel(title = title)
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(4.dp))
                .background(FsDarkSurface, RoundedCornerShape(4.dp))
        ) {
            content()
        }
    }
}

@Composable
private fun SettingsItem(
    label: String,
    hint: String? = null,
    right: @Composable () -> Unit,
    isLast: Boolean = false
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = FsDarkFg, style = MaterialTheme.typography.bodySmall)
            if (hint != null) {
                Text(hint, color = FsDarkMuted, style = MaterialTheme.typography.labelLarge, fontSize = 11.sp)
            }
        }
        right()
    }
    if (!isLast) {
        androidx.compose.material3.HorizontalDivider(
            modifier = Modifier.padding(horizontal = 14.dp),
            thickness = 1.dp,
            color = FsDarkBorder
        )
    }
}

private fun fmtUptime(secs: Long?): String {
    if (secs == null || secs <= 0) return "—"
    val h = secs / 3600
    val m = (secs % 3600) / 60
    val s = secs % 60
    return when {
        h > 0 -> "${h}H ${m.toString().padStart(2, '0')}M"
        m > 0 -> "${m}M ${s.toString().padStart(2, '0')}S"
        else -> "${s}S"
    }
}
