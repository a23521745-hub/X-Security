package org.xsecurity.scanner.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [UpdatePreferences.shouldRun] worker kapisi: arka plan guncelleme kontrolu
 * ne zaman calisir, ne zaman sessizce atlanir?
 */
class UpdatePreferencesTest {

    @Test
    fun runsWhenEnabledOnUnmetered() {
        assertTrue(UpdatePreferences.shouldRun(autoCheckEnabled = true, allowMetered = true, metered = false))
        assertTrue(UpdatePreferences.shouldRun(autoCheckEnabled = true, allowMetered = false, metered = false))
    }

    @Test
    fun runsOnMeteredOnlyWhenAllowed() {
        assertTrue(UpdatePreferences.shouldRun(autoCheckEnabled = true, allowMetered = true, metered = true))
        assertFalse(UpdatePreferences.shouldRun(autoCheckEnabled = true, allowMetered = false, metered = true))
    }

    @Test
    fun neverRunsWhenAutoCheckDisabled() {
        assertFalse(UpdatePreferences.shouldRun(autoCheckEnabled = false, allowMetered = true, metered = false))
        assertFalse(UpdatePreferences.shouldRun(autoCheckEnabled = false, allowMetered = true, metered = true))
        assertFalse(UpdatePreferences.shouldRun(autoCheckEnabled = false, allowMetered = false, metered = false))
    }
}
