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

    // Whether a peer was ALREADY linked when this screen opened. In that
    // case the user came here deliberately to add another device
    // (multipeer), and the auto-success below must stay quiet — with a
    // live peerName at mount, LaunchedEffect's first run would otherwise
    // fire the success state immediately and bounce the user back to
    // Linked before they could show or scan a QR. A NEW device pairing
    // from here is driven by the SAS flow instead (sasPhase "showing"
    // routes to the verify screen at the app level).
    val linkedAtEntry = remember { peerName.isNotEmpty() }

    // Auto-advance on success (Mac-inspired) — first onboarding only:
    // fires when a peer appears while the screen is open and none existed
    // at entry.
    LaunchedEffect(peerName) {
        if (!linkedAtEntry && peerName.isNotEmpty()) {
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
                .size(64.dp)
                .background(FsAccent, RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text("✓", color = FsOnAccent, fontSize = 30.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(18.dp))
        Text("Devices linked", color = FsDarkFg, fontFamily = FsSans, fontWeight = FontWeight.ExtraBold, fontSize = 16.sp)
        Spacer(Modifier.height(4.dp))
        Text("Linked with $name", color = FsDarkMuted, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ModeToggle(mode: PairMode, onModeChange: (PairMode) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .height(44.dp)
            .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.Seg))
            .background(FsCardFlat, RoundedCornerShape(FsRadius.Seg))
            .padding(3.dp)
    ) {
        Segment("Show this phone", selected = mode == PairMode.SHOW, modifier = Modifier.weight(1f)) {
            onModeChange(PairMode.SHOW)
        }
        Segment("Scan", selected = mode == PairMode.SCAN, modifier = Modifier.weight(1f)) {
            onModeChange(PairMode.SCAN)
        }
    }
}

@Composable
private fun Segment(label: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Box(
        modifier
            .fillMaxHeight()
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) FsOkSoft else androidx.compose.ui.graphics.Color.Transparent)
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            color = if (selected) FsAccent else FsDarkMuted,
            fontFamily = FsSans,
            fontWeight = FontWeight.Bold,
            fontSize = 11.5.sp,
            maxLines = 1,
        )
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
            .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.Hero))
            .background(FsCard, RoundedCornerShape(FsRadius.Hero))
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            Modifier
                .size(48.dp)
                .background(FsOkSoft, RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text("📷", fontSize = 22.sp)
        }
        Spacer(Modifier.height(14.dp))
        Text("Use camera", color = FsDarkFg, fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 14.5.sp)
        Spacer(Modifier.height(4.dp))
        Text("Scan the QR code on your Mac or other phone.", color = FsDarkMuted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 20.dp), textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        Spacer(Modifier.height(20.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(FsRadius.Btn))
                .background(FsAccent)
                .clickable { onScan() }
                .padding(vertical = 12.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("Launch scanner", color = FsOnAccent, fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 13.sp)
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
            .background(FsLightSurface, RoundedCornerShape(FsRadius.Item))
            .padding(14.dp),
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
            .statusBarsPadding()
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Box(
            Modifier
                .size(30.dp)
                .clip(RoundedCornerShape(FsRadius.IconMd))
                .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.IconMd))
                .background(FsCardFlat, RoundedCornerShape(FsRadius.IconMd))
                .clickable { onBack() },
            contentAlignment = Alignment.Center
        ) {
            Text("←", color = FsDarkMuted, fontSize = 15.sp)
        }
        Text("Pair a device", color = FsDarkFg, fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 16.sp)
    }
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
