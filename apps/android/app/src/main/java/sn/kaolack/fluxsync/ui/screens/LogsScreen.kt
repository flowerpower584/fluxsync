package sn.kaolack.fluxsync.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.vm.FluxsyncViewModel
import sn.kaolack.fluxsync.vm.LogEntryView

/**
 * Screen 03: Logs
 * Live stream of activity logs from the FluxSync daemon. The
 * `FluxsyncManager.logs` flow is fed by `FluxsyncAccessibilityService`
 * polling `FluxsyncHandle.pollLogs(since)` on the IPC `logs` channel.
 */
@Composable
fun LogsScreen(vm: FluxsyncViewModel) {
    var showRaw by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf("ALL") }
    val logs by vm.logs.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    val visible = remember(logs, filter) {
        // Newest first matches the design mock.
        val ordered = logs.asReversed()
        if (filter == "ALL") ordered else ordered.filter { it.level.equals(filter, ignoreCase = true) }
    }

    // Auto-scroll to the top as new entries land — only while the user is
    // pinned at the very top. Scrolling away even slightly pauses it until
    // they return to the top, so reading older entries isn't interrupted.
    LaunchedEffect(visible.size) {
        if (shouldAutoScrollLogs(
                listState.firstVisibleItemIndex,
                listState.firstVisibleItemScrollOffset,
            )
        ) {
            listState.animateScrollToItem(0)
        }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("ALL", "OK", "INFO", "WARN", "ERR").forEach { f ->
                    LogFilterChip(label = f, active = filter == f, onClick = { filter = f })
                }
            }
            LogFilterChip(label = "RAW", active = showRaw, onClick = { showRaw = !showRaw })
        }

        if (visible.isEmpty()) {
            Box(
                Modifier
                    .fillMaxSize()
                    .padding(20.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "Waiting for the daemon to log something…",
                    color = FsDarkMuted,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                itemsIndexed(visible) { index, log ->
                    LogItem(log, isRaw = showRaw, isLast = index == visible.size - 1)
                }
            }
        }
    }
}

/**
 * FS-023: the log list auto-scrolls to the newest entry only while the
 * user is pinned at the exact top (index 0, no pixel offset). Any scroll
 * away pauses it — the old `firstVisibleItemIndex <= 1` threshold yanked
 * a user who was deliberately reading the second entry.
 */
internal fun shouldAutoScrollLogs(
    firstVisibleItemIndex: Int,
    firstVisibleItemScrollOffset: Int,
): Boolean = firstVisibleItemIndex == 0 && firstVisibleItemScrollOffset == 0

@Composable
private fun LogFilterChip(label: String, active: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(8.dp)
    Box(
        Modifier
            .border(
                width = 1.dp,
                color = if (active) FsAccent.copy(alpha = 0.4f) else FsDarkBorder,
                shape = shape,
            )
            .background(if (active) FsOkSoft else FsCardFlat, shape)
            .clickable(onClick = onClick)
            .padding(horizontal = 9.dp, vertical = 4.dp)
    ) {
        Text(
            label,
            color = if (active) FsAccent else FsDarkMuted,
            style = MaterialTheme.typography.labelSmall,
            fontSize = 9.sp
        )
    }
}

@Composable
private fun LogItem(log: LogEntryView, isRaw: Boolean, isLast: Boolean) {
    val levelColor = when (log.level.uppercase()) {
        "OK" -> FsOk
        "SYNC", "INFO" -> FsInfo
        "WARN" -> FsWarn
        "ERR" -> FsCrit
        else -> FsDarkMuted
    }

    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(log.time, color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp)
            Text("[${log.level.uppercase()}]", color = levelColor, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(4.dp))
        Text(
            if (isRaw) log.raw else log.msg,
            color = if (isRaw) FsDarkSubtle else FsDarkFg,
            style = if (isRaw) MaterialTheme.typography.labelSmall else MaterialTheme.typography.bodySmall,
            lineHeight = 16.sp,
        )
        if (!isLast) {
            Spacer(Modifier.height(8.dp))
            HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
        }
    }
}
