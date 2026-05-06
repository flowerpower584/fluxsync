package sn.kaolack.fluxsync.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

// Design system asks for Inter Tight + JetBrains Mono. We use the
// system sans-serif (Roboto on most Android builds; close enough to
// Inter visually for v0.1.1) and `FontFamily.Monospace` (defaults to
// Droid Sans Mono / JetBrains Mono on newer devices). When we ship
// proper ttf bundles or wire up `androidx.compose.ui:ui-text-google-
// fonts`, replace `FontFamily.SansSerif` and `FsMono` here — every
// callsite already routes through these aliases.
val FsSans: FontFamily = FontFamily.SansSerif
val FsMono: FontFamily = FontFamily.Monospace

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
