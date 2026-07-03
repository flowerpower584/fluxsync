package sn.kaolack.fluxsync.utils

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

/**
 * DIR-P3-07: Doze/App-Standby can throttle the AccessibilityService's
 * clipboard capture just like any other background work. Android exempts
 * an app that the user explicitly whitelists via
 * `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` — that intent is banned for
 * Play-distributed apps, but FluxSync is sideload-only, so it's fair game.
 *
 * The prompt asks once (dismissal is remembered) and stays reachable
 * manually from Settings regardless of dismissal.
 */
object BatteryOptimizationUtils {
    private const val PREFS_NAME = "fluxsync_survival_prefs"
    private const val KEY_DISMISSED = "battery_exemption_dismissed"

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return true
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    fun isDismissed(context: Context): Boolean =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_DISMISSED, false)

    fun setDismissed(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_DISMISSED, true)
            .apply()
    }

    /**
     * Pure decision so it's testable without a Context: offer the prompt
     * only while the app is NOT already exempt and the user hasn't
     * dismissed it before. Manual access from Settings bypasses this gate
     * entirely (it always shows the current state there).
     */
    fun shouldOfferExemptionPrompt(isIgnoring: Boolean, dismissed: Boolean): Boolean =
        !isIgnoring && !dismissed

    /** `package:<applicationId>` — the URI form the exemption intent requires. */
    fun exemptionIntent(packageName: String): Intent =
        Intent(
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            Uri.parse("package:$packageName"),
        )
}
