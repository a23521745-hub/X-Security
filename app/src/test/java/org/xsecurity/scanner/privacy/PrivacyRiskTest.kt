package org.xsecurity.scanner.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.privacy.PrivacyRisk.Group
import org.xsecurity.scanner.privacy.PrivacyRisk.Level

/**
 * [PrivacyRisk]: izin -> grup eslesmesi, risk puani ve siralama.
 */
class PrivacyRiskTest {

    @Test
    fun mapsPermissionsToGroups() {
        assertEquals(
            setOf(Group.CAMERA),
            PrivacyRisk.groupsFor(listOf(PrivacyRisk.PERMISSION_CAMERA))
        )
        assertEquals(
            setOf(Group.LOCATION),
            PrivacyRisk.groupsFor(
                listOf(
                    PrivacyRisk.PERMISSION_FINE_LOCATION,
                    PrivacyRisk.PERMISSION_BACKGROUND_LOCATION
                )
            )
        )
        assertEquals(
            setOf(Group.SMS, Group.CONTACTS),
            PrivacyRisk.groupsFor(
                listOf(PrivacyRisk.PERMISSION_READ_SMS, PrivacyRisk.PERMISSION_READ_CONTACTS)
            )
        )
        // Tehlikesiz/bilinmeyen izinler gruba girmez.
        assertTrue(PrivacyRisk.groupsFor(listOf("android.permission.INTERNET")).isEmpty())
        assertTrue(PrivacyRisk.groupsFor(emptyList()).isEmpty())
    }

    @Test
    fun smsAloneIsHighCameraAloneIsLow() {
        assertEquals(Level.HIGH, PrivacyRisk.levelFor(setOf(Group.SMS)))
        assertEquals(Level.MEDIUM, PrivacyRisk.levelFor(setOf(Group.LOCATION)))
        assertEquals(Level.MEDIUM, PrivacyRisk.levelFor(setOf(Group.MICROPHONE)))
        assertEquals(Level.MEDIUM, PrivacyRisk.levelFor(setOf(Group.CONTACTS)))
        assertEquals(Level.LOW, PrivacyRisk.levelFor(setOf(Group.CAMERA)))
        // Kamera + mikrofon birikti: MEDIUM; rehber + konum: HIGH.
        assertEquals(Level.MEDIUM, PrivacyRisk.levelFor(setOf(Group.CAMERA, Group.MICROPHONE)))
        assertEquals(Level.HIGH, PrivacyRisk.levelFor(setOf(Group.CONTACTS, Group.LOCATION)))
    }

    @Test
    fun sortsByScoreThenName() {
        val low = PrivacyRisk.App("com.low", "Zebra", false, setOf(Group.CAMERA))
        val highB = PrivacyRisk.App("com.high.b", "Beta", false, setOf(Group.SMS))
        val highA = PrivacyRisk.App("com.high.a", "alfa", false, setOf(Group.SMS))
        val sorted = PrivacyRisk.sort(listOf(low, highB, highA))
        assertEquals(listOf("com.high.a", "com.high.b", "com.low"), sorted.map { it.packageName })
    }

    @Test
    fun constantsMirrorFrameworkValues() {
        assertEquals("android.permission.CAMERA", PrivacyRisk.PERMISSION_CAMERA)
        assertEquals("android.permission.RECORD_AUDIO", PrivacyRisk.PERMISSION_RECORD_AUDIO)
        assertEquals("android.permission.READ_SMS", PrivacyRisk.PERMISSION_READ_SMS)
        assertEquals("android.permission.READ_CONTACTS", PrivacyRisk.PERMISSION_READ_CONTACTS)
    }
}
