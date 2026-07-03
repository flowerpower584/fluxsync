package sn.kaolack.fluxsync.utils

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DIR-P3-07: the exemption prompt must ask once and stay quiet after
 * either a grant or a dismissal.
 */
class BatteryOptimizationUtilsTest {

    @Test
    fun offersPromptWhenNotExemptAndNotDismissed() {
        assertTrue(
            BatteryOptimizationUtils.shouldOfferExemptionPrompt(isIgnoring = false, dismissed = false),
        )
    }

    @Test
    fun staysQuietOnceAlreadyExempt() {
        assertFalse(
            BatteryOptimizationUtils.shouldOfferExemptionPrompt(isIgnoring = true, dismissed = false),
        )
    }

    @Test
    fun staysQuietAfterDismissal() {
        assertFalse(
            BatteryOptimizationUtils.shouldOfferExemptionPrompt(isIgnoring = false, dismissed = true),
        )
    }

    @Test
    fun staysQuietWhenBothExemptAndDismissed() {
        assertFalse(
            BatteryOptimizationUtils.shouldOfferExemptionPrompt(isIgnoring = true, dismissed = true),
        )
    }

    // `exemptionIntent` just wraps `Intent`/`Uri` construction — android.jar's
    // stub getters return defaults under `isReturnDefaultValues`, so (like
    // the rest of this suite) it isn't asserted on here; only the pure
    // decision logic above is JVM-testable without Robolectric.
}
