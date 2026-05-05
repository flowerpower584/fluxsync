package sn.kaolack.fluxsync.ui.theme

import androidx.compose.ui.graphics.Color

// Tokens transposed verbatim from `design/FluxSync.html` /
// `components.jsx`. Keep these in sync — the HTML mockup is canonical.

// ── Light surface tokens ────────────────────────────────────────
val FsLightBg = Color(0xFFFAFAF9)
val FsLightSurface = Color(0xFFFFFFFF)
val FsLightFg = Color(0xFF0A0A0A)
val FsLightMuted = Color(0xFF71717A)
val FsLightSubtle = Color(0xFFA1A1AA)
val FsLightBorder = Color(0xFFE4E4E7)
val FsLightBorderStrong = Color(0xFFD4D4D8)
val FsLightHover = Color(0xFFF4F4F5)

// ── Dark surface tokens (Android default) ───────────────────────
val FsDarkBg = Color(0xFF0B0B0C)
val FsDarkSurface = Color(0xFF131316)
val FsDarkFg = Color(0xFFFAFAFA)
val FsDarkMuted = Color(0xFFA1A1AA)
val FsDarkSubtle = Color(0xFF71717A)
val FsDarkBorder = Color(0xFF1F1F22)
val FsDarkBorderStrong = Color(0xFF2A2A2E)
val FsDarkHover = Color(0xFF1A1A1D)

// ── Status (intentionally desaturated; see design notes) ────────
val FsOk = Color(0xFF3FAE5A)
val FsOkSoft = Color(0x1F3FAE5A)         // alpha 0.12 ≈ 0x1F
val FsWarn = Color(0xFFD9A441)
val FsWarnSoft = Color(0x24D9A441)        // alpha 0.14 ≈ 0x24
val FsCrit = Color(0xFFD43F3F)            // rouge sénégalais — identity + crit only
val FsCritSoft = Color(0x1FD43F3F)        // alpha 0.12
val FsInfo = Color(0xFF5B7FBF)

// Translucent halo around status dots, computed once instead of mixing
// `${color}22` at every callsite.
val FsOkHalo = FsOk.copy(alpha = 0.13f)
val FsWarnHalo = FsWarn.copy(alpha = 0.13f)
val FsCritHalo = FsCrit.copy(alpha = 0.13f)
val FsInfoHalo = FsInfo.copy(alpha = 0.13f)
