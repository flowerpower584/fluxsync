package sn.kaolack.fluxsync.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import sn.kaolack.fluxsync.ui.screens.themeAppearanceHint

/**
 * FS-024: the Settings "Theme" row must state that dark-only is a
 * deliberate choice and name the user's current system setting.
 */
class SettingsScreenTest {

    @Test
    fun hintMatchesSystemDark() {
        assertEquals(
            "Locked to dark — matches your system setting",
            themeAppearanceHint(systemInDark = true),
        )
    }

    @Test
    fun hintNamesSystemLight() {
        assertEquals(
            "Locked to dark — your system is set to light",
            themeAppearanceHint(systemInDark = false),
        )
    }
}
