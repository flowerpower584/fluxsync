package sn.kaolack.fluxsync.ui.screens

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import sn.kaolack.fluxsync.ui.components.SectionLabel
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsCard
import sn.kaolack.fluxsync.ui.theme.FsCardFlat
import sn.kaolack.fluxsync.ui.theme.FsDarkBg
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkFg
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsInfoSoft
import sn.kaolack.fluxsync.ui.theme.FsRadius
import sn.kaolack.fluxsync.ui.theme.FsSans
import sn.kaolack.fluxsync.utils.OemGuidance

/**
 * DIR-P3-07: explains that stock Android's Doze exemption isn't always
 * enough — several OEMs run their own background-app killer on top of it —
 * and links out to dontkillmyapp.com's per-vendor workaround, defaulting to
 * this device's own manufacturer.
 */
@Composable
fun OemGuidanceScreen(onBack: () -> Unit) {
    val context = LocalContext.current

    fun openUrl(url: String) {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }

    Column(Modifier.fillMaxSize().background(FsDarkBg)) {
        Header(onBack)

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(FsInfoSoft, RoundedCornerShape(FsRadius.Item))
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(Icons.Default.Info, contentDescription = null, tint = FsAccent, modifier = Modifier.size(18.dp))
                    Text(
                        "Your phone's manufacturer may kill background services beyond what stock " +
                            "Android does, even after you've exempted FluxSync from battery " +
                            "optimization. Each vendor has its own settings to fix this.",
                        color = FsDarkFg,
                        fontFamily = FsSans,
                        fontSize = 11.5.sp,
                        lineHeight = 17.sp,
                    )
                }
            }

            item {
                val manufacturer = Build.MANUFACTURER.orEmpty()
                val deviceUrl = OemGuidance.urlFor(manufacturer)
                SectionLabel(title = "Your device")
                GuidanceGroup {
                    GuidanceRow(
                        label = manufacturer.ifBlank { "Unknown manufacturer" },
                        isLast = true,
                        onClick = { openUrl(deviceUrl) },
                    )
                }
            }

            item {
                SectionLabel(title = "Other manufacturers")
                GuidanceGroup {
                    OemGuidance.KNOWN_VENDORS.forEach { vendor ->
                        GuidanceRow(
                            label = vendor,
                            isLast = vendor == OemGuidance.KNOWN_VENDORS.last(),
                            onClick = { openUrl(OemGuidance.urlFor(vendor)) },
                        )
                    }
                }
            }

            item {
                Spacer(Modifier.height(4.dp))
                Text(
                    "Not listed? All guidance lives at dontkillmyapp.com.",
                    color = FsDarkMuted,
                    fontFamily = FsSans,
                    fontSize = 11.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { openUrl(OemGuidance.HOME_URL) }
                        .padding(vertical = 8.dp),
                )
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

/** Bordered card wrapper, matching `SettingsGroup` in SettingsScreen.kt. */
@Composable
private fun GuidanceGroup(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = FsDarkBorder, shape = RoundedCornerShape(FsRadius.Item))
            .background(FsCard, RoundedCornerShape(FsRadius.Item)),
        content = content,
    )
}

@Composable
private fun GuidanceRow(label: String, isLast: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = FsDarkFg, style = MaterialTheme.typography.bodySmall)
        Text("dontkillmyapp.com ›", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp)
    }
    if (!isLast) {
        HorizontalDivider(
            modifier = Modifier.padding(horizontal = 14.dp),
            thickness = 1.dp,
            color = FsDarkBorder,
        )
    }
}

@Composable
private fun Header(onBack: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(FsDarkBg)
            .statusBarsPadding()
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            Modifier
                .size(30.dp)
                .clip(RoundedCornerShape(FsRadius.IconMd))
                .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.IconMd))
                .background(FsCardFlat, RoundedCornerShape(FsRadius.IconMd))
                .clickable(onClick = onBack),
            contentAlignment = Alignment.Center,
        ) {
            Text("←", color = FsDarkMuted, fontSize = 15.sp)
        }
        Text("Background reliability", color = FsDarkFg, fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 16.sp)
    }
}
