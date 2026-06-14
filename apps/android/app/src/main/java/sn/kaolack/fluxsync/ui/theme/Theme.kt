package sn.kaolack.fluxsync.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkScheme = darkColorScheme(
    // v6: accent is the green `FsAccent` (toggles, slider track,
    // active nav, CTAs). Red is reserved for destructive/critical.
    primary = FsAccent,
    onPrimary = FsOnAccent,
    primaryContainer = FsOkSoft,
    onPrimaryContainer = FsDarkFg,
    secondary = FsInfo,
    onSecondary = FsDarkBg,
    error = FsCrit,
    onError = FsLightSurface,
    background = FsDarkBg,
    onBackground = FsDarkFg,
    surface = FsDarkSurface,
    onSurface = FsDarkFg,
    surfaceVariant = FsDarkBorder,
    onSurfaceVariant = FsDarkMuted,
    outline = FsDarkBorderStrong,
    outlineVariant = FsDarkBorder,
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF19A85B),
    onPrimary = FsLightSurface,
    primaryContainer = FsOkSoft,
    onPrimaryContainer = FsLightFg,
    secondary = FsInfo,
    onSecondary = FsLightSurface,
    error = FsCrit,
    onError = FsLightSurface,
    background = FsLightBg,
    onBackground = FsLightFg,
    surface = FsLightSurface,
    onSurface = FsLightFg,
    surfaceVariant = FsLightBorder,
    onSurfaceVariant = FsLightMuted,
    outline = FsLightBorderStrong,
    outlineVariant = FsLightBorder,
)

/**
 * App-wide theme wrapper.
 *
 * The mockup is dark-only on Android (`t = FS.dark` in
 * `frame-android.jsx`). We default to dark and ignore the system
 * setting unless the caller forces it — this matches the design
 * intent and avoids a half-finished light theme until v0.1.2 ships
 * one for the desktop tray.
 */
@Composable
fun FluxsyncTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit,
) {
    val scheme = if (darkTheme) DarkScheme else LightScheme
    MaterialTheme(
        colorScheme = scheme,
        typography = FsTypography,
        content = content,
    )
}
