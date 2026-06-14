package sn.kaolack.fluxsync.ui.screens

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Accessibility
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsCard
import sn.kaolack.fluxsync.ui.theme.FsCardFlat
import sn.kaolack.fluxsync.ui.theme.FsDarkBg
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkFg
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsOnAccent
import sn.kaolack.fluxsync.ui.theme.FsRadius
import sn.kaolack.fluxsync.ui.theme.FsSans
import sn.kaolack.fluxsync.ui.theme.FsWarn
import sn.kaolack.fluxsync.ui.theme.FsWarnSoft

@Composable
fun AccessibilityBlockingScreen() {
    val context = LocalContext.current

    Surface(modifier = Modifier.fillMaxSize(), color = FsDarkBg) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(26.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(
                Modifier
                    .size(64.dp)
                    .background(FsWarnSoft, RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Default.Accessibility,
                    contentDescription = null,
                    modifier = Modifier.size(30.dp),
                    tint = FsWarn,
                )
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text = "Accessibility service required",
                fontFamily = FsSans,
                fontWeight = FontWeight.ExtraBold,
                fontSize = 17.sp,
                color = FsDarkFg,
                textAlign = TextAlign.Center,
            )

            Spacer(Modifier.height(8.dp))

            Text(
                text = "Android blocks background clipboard reads. FluxSync uses the accessibility service to capture your copies even when the app is closed. Nothing leaves your local network.",
                fontFamily = FsSans,
                fontSize = 11.5.sp,
                lineHeight = 17.sp,
                textAlign = TextAlign.Center,
                color = FsDarkMuted,
            )

            Spacer(Modifier.height(18.dp))

            StepCard(1, "Open Settings → Accessibility")
            Spacer(Modifier.height(7.dp))
            StepCard(2, "Find FluxSync under downloaded services")
            Spacer(Modifier.height(7.dp))
            StepCard(3, "Turn it on and confirm")

            Spacer(Modifier.height(18.dp))

            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(FsRadius.Btn))
                    .background(FsAccent)
                    .clickable {
                        context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                    }
                    .padding(vertical = 13.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "Enable in settings",
                    fontFamily = FsSans,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = FsOnAccent,
                )
            }
        }
    }
}

@Composable
private fun StepCard(n: Int, label: String) {
    val shape = RoundedCornerShape(FsRadius.Item)
    Row(
        Modifier
            .fillMaxWidth()
            .border(1.dp, FsDarkBorder, shape)
            .background(FsCard, shape)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            Modifier
                .size(18.dp)
                .border(1.dp, FsDarkBorder, CircleShape)
                .background(FsCardFlat, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text("$n", fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 9.5.sp, color = FsDarkMuted)
        }
        Text(label, fontFamily = FsSans, fontSize = 11.sp, color = FsDarkFg)
    }
}
