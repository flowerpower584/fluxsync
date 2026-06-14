package sn.kaolack.fluxsync.ui.theme

import androidx.compose.ui.graphics.Color

// Tokens v6 "premium calme", transposed from `design-preview.html`
// (section ANDROID) / apps/macos-tray/src/shared.css. Keep in sync —
// the HTML mockup is canonical. Flat colors only: no gradients.

// ── Light surface tokens (not wired; kept in sync for hygiene) ──
val FsLightBg = Color(0xFFF6F6F7)
val FsLightSurface = Color(0xFFFFFFFF)
val FsLightFg = Color(0xFF111114)
val FsLightMuted = Color(0xFF5F5F6B)
val FsLightSubtle = Color(0xFF9A9AA4)
val FsLightBorder = Color(0x14111114)        // black 8%
val FsLightBorderStrong = Color(0x29111114)  // black 16%
val FsLightHover = Color(0x0C111114)

// ── Dark surface tokens (Android default) ───────────────────────
val FsDarkBg = Color(0xFF09090B)
val FsDarkSurface = Color(0xFF0C0C0F)
val FsDarkFg = Color(0xFFF4F4F5)
val FsDarkMuted = Color(0xFF9D9DA8)
val FsDarkSubtle = Color(0xFF5C5C68)
val FsDarkBorder = Color(0x13FFFFFF)         // white 7.5%
val FsDarkBorderStrong = Color(0x24FFFFFF)   // white 14%
val FsDarkHover = Color(0x0FFFFFFF)          // white 6%

// Translucent card fills — composited over FsDarkBg they render the
// v6 card tone; nesting FsCardFlat inside FsCard brightens slightly
// (additive), same as the CSS.
val FsCard = Color(0x0CFFFFFF)               // white 4.5%
val FsCardFlat = Color(0x0AFFFFFF)           // white 4%

// ── Status ───────────────────────────────────────────────────────
val FsOk = Color(0xFF4CC272)
val FsOkSoft = Color(0x1F4CC272)             // alpha 0.12
val FsWarn = Color(0xFFD9A23A)
val FsWarnSoft = Color(0x21D9A23A)           // alpha 0.13
val FsCrit = Color(0xFFE0635E)               // destructive/failure only — never decorative
val FsCritSoft = Color(0x1FE0635E)           // alpha 0.12
val FsInfo = Color(0xFF5B8FD4)
val FsInfoSoft = Color(0x215B8FD4)           // alpha 0.13

// ── Accent (green; replaced the old red accent) ──────────────────
val FsAccent = FsOk
val FsAccentDeep = Color(0xFF36A35C)
val FsOnAccent = Color(0xFF052E12)           // text on solid accent fills
val FsHeroOkBorder = Color(0x474CC272)       // alpha 0.28 — hero "ok" border

// Translucent halo around status dots, computed once instead of mixing
// `${color}22` at every callsite.
val FsOkHalo = FsOk.copy(alpha = 0.13f)
val FsWarnHalo = FsWarn.copy(alpha = 0.13f)
val FsCritHalo = FsCrit.copy(alpha = 0.13f)
val FsInfoHalo = FsInfo.copy(alpha = 0.13f)
