package sn.kaolack.fluxsync.utils

/**
 * DIR-P3-07: several Android OEMs run aggressive background-app killers on
 * top of stock Doze/App-Standby, which can stop the AccessibilityService
 * even with a battery-optimization exemption granted. dontkillmyapp.com
 * tracks per-vendor workarounds; this maps `Build.MANUFACTURER` to the
 * vendor's guidance page, falling back to the site's home page.
 */
object OemGuidance {
    const val HOME_URL = "https://dontkillmyapp.com"

    private val VENDOR_SLUGS = mapOf(
        "samsung" to "samsung",
        "xiaomi" to "xiaomi",
        "huawei" to "huawei",
        "oppo" to "oppo",
        "vivo" to "vivo",
        "oneplus" to "oneplus",
    )

    /** Ordered for the "other manufacturers" list in the guidance screen. */
    val KNOWN_VENDORS: List<String> = listOf(
        "Samsung", "Xiaomi", "Huawei", "OPPO", "vivo", "OnePlus",
    )

    /**
     * [manufacturer] is `Build.MANUFACTURER` at the call site — kept as a
     * plain String parameter (not read from `Build` in here) so this stays
     * testable on a plain JVM, matching
     * `FluxsyncAccessibilityService.formatPeerName`.
     */
    fun urlFor(manufacturer: String?): String {
        val key = manufacturer?.trim()?.lowercase() ?: return HOME_URL
        val slug = VENDOR_SLUGS[key] ?: return HOME_URL
        return "$HOME_URL/$slug"
    }
}
