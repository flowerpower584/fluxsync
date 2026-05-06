package sn.kaolack.fluxsync.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import org.json.JSONObject
import sn.kaolack.fluxsync.ui.components.E2EBadge
import sn.kaolack.fluxsync.ui.components.SectionLabel
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.ui.util.rememberQrBitmap
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

@Composable
fun PairingDashboardScreen(
    vm: FluxsyncViewModel,
    onBack: () -> Unit,
    onScan: () -> Unit,
    onSuccess: () -> Unit
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val peerName = state?.peerName ?: ""
    var mode by remember { mutableStateOf(PairMode.SHOW) }
    var showSuccess by remember { mutableStateOf(false) }

    // Auto-advance on success (Mac-inspired)
    LaunchedEffect(peerName) {
        if (peerName.isNotEmpty()) {
            showSuccess = true
            delay(2000)
            onSuccess()
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(FsDarkBg)
    ) {
        Header(onBack)

        if (showSuccess) {
            SuccessState(peerName)
        } else {
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(horizontal = 20.dp, vertical = 20.dp)
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                ModeToggle(mode = mode, onModeChange = { mode = it })
                
                Spacer(Modifier.height(24.dp))

                AnimatedContent(
                    targetState = mode,
                    transitionSpec = { fadeIn() togetherWith fadeOut() }
                ) { targetMode ->
                    if (targetMode == PairMode.SHOW) {
                        ShowFlow(vm)
                    } else {
                        ScanCTA(onScan = onScan)
                    }
                }
            }
        }
    }
}

enum class PairMode { SHOW, SCAN }

@Composable
private fun SuccessState(name: String) {
    Column(
        Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            Modifier
                .size(80.dp)
                .background(FsOk.copy(alpha = 0.1f), RoundedCornerShape(40.dp))
                .border(2.dp, FsOk, RoundedCornerShape(40.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text("✓", color = FsOk, fontSize = 40.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(24.dp))
        Text("Successfully Paired!", color = FsDarkFg, style = MaterialTheme.typography.titleLarge)
        Text("Linked with $name", color = FsDarkMuted, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ModeToggle(mode: PairMode, onModeChange: (PairMode) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .height(44.dp)
            .background(FsDarkSurface, RoundedCornerShape(8.dp))
            .padding(4.dp)
    ) {
        Box(
            Modifier
                .weight(1f)
                .fillMaxHeight()
                .clip(RoundedCornerShape(6.dp))
                .background(if (mode == PairMode.SHOW) FsDarkBorderStrong else FsDarkSurface)
                .clickable { onModeChange(PairMode.SHOW) },
            contentAlignment = Alignment.Center
        ) {
            Text("Show QR", color = if (mode == PairMode.SHOW) FsDarkFg else FsDarkMuted, style = MaterialTheme.typography.labelLarge)
        }
        Box(
            Modifier
                .weight(1f)
                .fillMaxHeight()
                .clip(RoundedCornerShape(6.dp))
                .background(if (mode == PairMode.SCAN) FsDarkBorderStrong else FsDarkSurface)
                .clickable { onModeChange(PairMode.SCAN) },
            contentAlignment = Alignment.Center
        ) {
            Text("Scan QR", color = if (mode == PairMode.SCAN) FsDarkFg else FsDarkMuted, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun ShowFlow(vm: FluxsyncViewModel) {
    var info by remember { mutableStateOf<PairInfo?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        try {
            val json = vm.pairShow()
            info = json?.let { PairInfo.parse(it) }
        } catch (t: Throwable) {
            error = t.message
        }
    }

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        if (info == null) {
            Box(Modifier.height(300.dp), contentAlignment = Alignment.Center) {
                Text(error ?: "Generating pair URI...", color = FsDarkMuted)
            }
        } else {
            QrPanel(uri = info!!.uri)
            Spacer(Modifier.height(20.dp))
            SectionLabel(title = "Fingerprint", right = { E2EBadge() })
            Spacer(Modifier.height(8.dp))
            Text(
                info!!.words.joinToString(" ").uppercase(),
                color = FsDarkFg,
                style = MaterialTheme.typography.labelLarge.copy(
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    letterSpacing = 0.05.em
                )
            )
            Spacer(Modifier.height(20.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("REACHABLE AT", color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall)
                Text(info!!.addrHint, color = FsDarkMuted, style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

@Composable
private fun ScanCTA(onScan: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .border(1.dp, FsDarkBorder, RoundedCornerShape(8.dp))
            .background(FsDarkSurface, RoundedCornerShape(8.dp))
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            Modifier
                .size(48.dp)
                .background(FsCrit.copy(alpha = 0.1f), RoundedCornerShape(24.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text("📷", fontSize = 24.sp)
        }
        Spacer(Modifier.height(16.dp))
        Text("Use Camera", color = FsDarkFg, style = MaterialTheme.typography.titleMedium)
        Text("Scan the QR code on your Mac or other phone.", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 20.dp), textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        Spacer(Modifier.height(24.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .background(FsCrit, RoundedCornerShape(4.dp))
                .clickable { onScan() }
                .padding(vertical = 12.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("LAUNCH SCANNER", color = FsLightSurface, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun QrPanel(uri: String) {
    val bitmap = rememberQrBitmap(uri, sizePx = 768)
    Box(
        Modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .border(1.dp, FsDarkBorderStrong, RoundedCornerShape(4.dp))
            .background(FsLightSurface, RoundedCornerShape(4.dp))
            .padding(20.dp),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            bitmap = bitmap,
            contentDescription = "FluxSync pair QR",
            modifier = Modifier.fillMaxSize().clip(RoundedCornerShape(2.dp)),
            contentScale = ContentScale.Fit,
        )
    }
}

@Composable
private fun Header(onBack: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 18.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(
            Modifier
                .size(32.dp)
                .border(1.dp, FsDarkBorder, RoundedCornerShape(4.dp))
                .clickable { onBack() },
            contentAlignment = Alignment.Center
        ) {
            Text("←", color = FsDarkMuted, fontSize = 18.sp)
        }
        Column {
            Text("Pair Device", color = FsDarkFg, style = MaterialTheme.typography.titleMedium)
            Text("SYNC IN SECONDS", color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall)
        }
    }
    HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
}

private data class PairInfo(val uri: String, val addrHint: String, val words: List<String>) {
    companion object {
        fun parse(json: String): PairInfo? = try {
            val o = JSONObject(json)
            val w = o.optJSONArray("fingerprint_words")
            val words = if (w == null) emptyList() else (0 until w.length()).map { w.optString(it, "") }
            PairInfo(uri = o.optString("uri", ""), addrHint = o.optString("addr_hint", ""), words = words)
        } catch (e: Exception) { null }
    }
}
