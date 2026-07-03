package sn.kaolack.fluxsync.utils

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * DIR-P3-07: vendor -> dontkillmyapp.com URL mapping. Matching is
 * case/whitespace-insensitive since `Build.MANUFACTURER` casing varies by
 * OEM (e.g. "samsung" vs "HUAWEI").
 */
class OemGuidanceTest {

    @Test
    fun mapsKnownVendorsToTheirGuidancePage() {
        assertEquals("https://dontkillmyapp.com/samsung", OemGuidance.urlFor("samsung"))
        assertEquals("https://dontkillmyapp.com/xiaomi", OemGuidance.urlFor("Xiaomi"))
        assertEquals("https://dontkillmyapp.com/huawei", OemGuidance.urlFor("HUAWEI"))
        assertEquals("https://dontkillmyapp.com/oppo", OemGuidance.urlFor("OPPO"))
        assertEquals("https://dontkillmyapp.com/vivo", OemGuidance.urlFor("vivo"))
        assertEquals("https://dontkillmyapp.com/oneplus", OemGuidance.urlFor("OnePlus"))
    }

    @Test
    fun isCaseAndWhitespaceInsensitive() {
        assertEquals("https://dontkillmyapp.com/samsung", OemGuidance.urlFor("  Samsung  "))
    }

    @Test
    fun fallsBackToHomeForUnknownVendors() {
        assertEquals(OemGuidance.HOME_URL, OemGuidance.urlFor("Google"))
        assertEquals(OemGuidance.HOME_URL, OemGuidance.urlFor("Motorola"))
    }

    @Test
    fun fallsBackToHomeForMissingOrBlankManufacturer() {
        assertEquals(OemGuidance.HOME_URL, OemGuidance.urlFor(null))
        assertEquals(OemGuidance.HOME_URL, OemGuidance.urlFor(""))
        assertEquals(OemGuidance.HOME_URL, OemGuidance.urlFor("   "))
    }
}
