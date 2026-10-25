package sn.kaolack.fluxsync.ui.theme

import androidx.compose.ui.graphics.Color

// Tokens v8 "Lien", transposed from apps/macos-tray/src/shared.css (the
// desktop stylesheet is canonical — keep in sync). Derived from the mark:
// coral = the two copies → what flows; green = the sync dot → the live,
// verified link; night ink surfaces. Flat colors only: no gradients.
//
// Token names are unchanged from v6 so every screen keeps compiling; only
// values moved. `FsAccent` stays the LINK colour (green) because Android
// uses it for linked/active states; the coral `FsFlux*` set is new.

// ── Light surface tokens (not wired; kept in sync for hygiene) ──
val FsLightBg = Color(0xFFE7EBF1)
val FsLightSurface = Color(0xFFF4F6F9)
val FsLightFg = Color(0xFF0C1422)
val FsLightMuted = Color(0xFF4E596B)
val FsLightSubtle = Color(0xFF737E91)
val FsLightBorder = Color(0x170C1422)        // ink 9%
val FsLightBorderStrong = Color(0x2B0C1422)  // ink 17%
val FsLightHover = Color(0x0D0C1422)

// ── Night surface tokens (Android default) ─────────────────────
val FsDarkBg = Color(0xFF080B10)
val FsDarkSurface = Color(0xFF0C1017)
val FsDarkFg = Color(0xFFE8EDF5)
val FsDarkMuted = Color(0xFF97A2B5)
val FsDarkSubtle = Color(0xFF66728A)
val FsDarkBorder = Color(0x16BED0F0)         // cool white 8.5%
val FsDarkBorderStrong = Color(0x29BED0F0)   // cool white 16%
val FsDarkHover = Color(0x0FBED0F0)          // cool white 6%

// Translucent card fills — composited over FsDarkBg they render the card
// tone; nesting FsCardFlat inside FsCard brightens slightly (additive).
val FsCard = Color(0x0CBED0F0)               // cool white 4.5%
val FsCardFlat = Color(0x0ABED0F0)           // cool white 4%

// ── Status ───────────────────────────────────────────────────────
val FsOk = Color(0xFF3DD68C)                 // the live link (logo dot)
val FsOkSoft = Color(0x1F3DD68C)             // alpha 0.12
val FsWarn = Color(0xFFF2B544)
val FsWarnSoft = Color(0x1FF2B544)           // alpha 0.12
val FsCrit = Color(0xFFF2545B)               // destructive/failure only — never decorative
val FsCritSoft = Color(0x1FF2545B)           // alpha 0.12
val FsInfo = Color(0xFF6B9BDC)
val FsInfoSoft = Color(0x246B9BDC)           // alpha 0.14

// ── Link accent (green): toggles on, linked/active states ─────────
val FsAccent = FsOk
val FsAccentDeep = Color(0xFF2BB574)
val FsOnAccent = Color(0xFF04170D)           // text on solid green fills
val FsHeroOkBorder = Color(0x613DD68C)       // alpha 0.38 — hero "linked" border

// ── Flux (coral): what moves — items in transit, primary actions ──
val FsFlux = Color(0xFFFF7452)
val FsFluxInk = Color(0xFFFF8A6C)            // coral as text on night
val FsOnFlux = Color(0xFF1C0A05)             // text on solid coral fills
val FsFluxSoft = Color(0x21FF7452)           // alpha 0.13

// Translucent halo around status dots, computed once instead of mixing
// `${color}22` at every callsite.
val FsOkHalo = FsOk.copy(alpha = 0.13f)
val FsWarnHalo = FsWarn.copy(alpha = 0.13f)
val FsCritHalo = FsCrit.copy(alpha = 0.13f)
val FsInfoHalo = FsInfo.copy(alpha = 0.13f)
