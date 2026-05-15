@file:OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)

package sn.kaolack.fluxsync.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import sn.kaolack.fluxsync.R

// Inter Tight + JetBrains Mono, bundled as variable ttf in res/font.
private fun interTight(w: FontWeight) =
    Font(R.font.inter_tight, weight = w, variationSettings = FontVariation.Settings(FontVariation.weight(w.weight)))

private fun jetBrainsMono(w: FontWeight) =
    Font(R.font.jetbrains_mono, weight = w, variationSettings = FontVariation.Settings(FontVariation.weight(w.weight)))

val FsSans: FontFamily = FontFamily(
    interTight(FontWeight.Normal),
    interTight(FontWeight.Medium),
    interTight(FontWeight.SemiBold),
)
val FsMono: FontFamily = FontFamily(
    jetBrainsMono(FontWeight.Normal),
    jetBrainsMono(FontWeight.Medium),
    jetBrainsMono(FontWeight.SemiBold),
)

// All sizes/weights are taken verbatim from `frame-android.jsx` and the
// "Typography" section of the design tokens artboard. Letter spacing
// uses negative `em` for display sizes (matches `letterSpacing:
// '-0.02em'` in the mockup).
val FsTypography = Typography(
    // 38px display — only used on the "hero" sections (web). Kept here
    // so future web-shared composables don't have to redeclare.
    displaySmall = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 38.sp,
        letterSpacing = (-0.02).em,
    ),
    // 24px — hero card title ("Live", "Halted", etc).
    headlineSmall = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        letterSpacing = (-0.02).em,
    ),
    // 22px — threshold value display.
    titleLarge = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        letterSpacing = (-0.02).em,
    ),
    // 16px — app bar product name.
    titleMedium = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        letterSpacing = (-0.01).em,
    ),
    // 13px — body text under hero card / device names.
    bodyMedium = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
    ),
    // 12px — secondary body, recent-item previews.
    bodySmall = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
    ),
    // 11px — peer-name labels, slider sub-text.
    labelLarge = TextStyle(
        fontFamily = FsSans,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
    ),
    // 10px — section captions ("CONDITIONS"), `data-uppercase` mono.
    labelMedium = TextStyle(
        fontFamily = FsMono,
        fontWeight = FontWeight.Normal,
        fontSize = 10.sp,
        letterSpacing = 0.06.em,
    ),
    // 9px — tiniest mono captions ("THIS DEVICE", nav rail labels).
    labelSmall = TextStyle(
        fontFamily = FsMono,
        fontWeight = FontWeight.Normal,
        fontSize = 9.sp,
        letterSpacing = 0.06.em,
    ),
)
