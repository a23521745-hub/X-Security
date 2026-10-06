package org.xsecurity.scanner.edr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EDR durum kartinin saf mantigi:
 *  - [EdrStatus.isEnabledService]: erisilebilirlik listesi eslesmesi,
 *  - [EdrAlertStore.prune]/[EdrAlertStore.countWithin]: 24 saat penceresi,
 *  - [EdrAlertStore] codec turu.
 */
class EdrStatusTest {

    private val pkg = "org.xsecurity.scanner"
    private val cls = "org.xsecurity.scanner.edr.AccessibilityBehaviorMonitor"

    @Test
    fun matchesFlatAndShortComponentNames() {
        assertTrue(EdrStatus.isEnabledService("$pkg/$cls", pkg, cls))
        assertTrue(EdrStatus.isEnabledService("$pkg/.edr.AccessibilityBehaviorMonitor", pkg, cls))
        assertTrue(
            EdrStatus.isEnabledService(
                "com.other/.TalkBack:$pkg/$cls:com.third/.Service",
                pkg,
                cls
            )
        )
    }

    @Test
    fun rejectsMissingOrPartialMatches() {
        assertFalse(EdrStatus.isEnabledService(null, pkg, cls))
        assertFalse(EdrStatus.isEnabledService("", pkg, cls))
        assertFalse(EdrStatus.isEnabledService("com.other/.TalkBack", pkg, cls))
        // Baska paketin ayni sinif adi eslesmemeli.
        assertFalse(EdrStatus.isEnabledService("com.evil/$cls", pkg, cls))
        assertFalse(EdrStatus.isEnabledService("$pkg/$cls", "", cls))
    }

    @Test
    fun prunesOutsideWindowAndCapsSize() {
        val now = 1_700_000_000_000L
        val cutoff = now - EdrAlertStore.WINDOW_MILLIS
        val timestamps = listOf(cutoff - 1, cutoff, cutoff + 1, now)
        assertEquals(listOf(cutoff, cutoff + 1, now), EdrAlertStore.prune(timestamps, cutoff))
        assertEquals(3, EdrAlertStore.countWithin(timestamps, cutoff))
        assertEquals(0, EdrAlertStore.countWithin(emptyList(), cutoff))

        val many = (1..(EdrAlertStore.MAX_ALERTS + 50)).map { now }
        assertEquals(EdrAlertStore.MAX_ALERTS, EdrAlertStore.prune(many, cutoff).size)
    }

    @Test
    fun codecRoundTripsAndSkipsGarbage() {
        val timestamps = listOf(1L, 2L, 1_700_000_000_000L)
        assertEquals(timestamps, EdrAlertStore.decode(EdrAlertStore.encode(timestamps)))
        assertEquals(listOf(5L), EdrAlertStore.decode("[5,\"yazi\"]"))
    }
}
