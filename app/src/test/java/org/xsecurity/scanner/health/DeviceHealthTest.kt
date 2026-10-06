package org.xsecurity.scanner.health

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.health.DeviceHealth.FindingId
import org.xsecurity.scanner.health.DeviceHealth.Verdict

/**
 * [DeviceHealth]: root/test-keys/ADB sinyalleri ve hukum mantigi.
 */
class DeviceHealthTest {

    @Test
    fun findsFirstSuPath() {
        val existing = setOf("/sbin/su", "/system/xbin/su")
        // Liste sirasi: /system/xbin/su /sbin/su'dan ONCE gelir.
        assertEquals("/system/xbin/su", DeviceHealth.findSu { it in existing })
        assertNull(DeviceHealth.findSu { false })
        // `exists` patlarsa sinyal uretilmez (fail-silent).
        assertNull(DeviceHealth.findSu { throw SecurityException("denied") })
    }

    @Test
    fun detectsTestKeysBuilds() {
        assertTrue(DeviceHealth.hasTestKeys("test-keys"))
        assertTrue(DeviceHealth.hasTestKeys("release-keys,test-keys"))
        assertFalse(DeviceHealth.hasTestKeys("release-keys"))
        assertFalse(DeviceHealth.hasTestKeys("test-keys2"))
        assertFalse(DeviceHealth.hasTestKeys(null))
        assertFalse(DeviceHealth.hasTestKeys(""))
    }

    @Test
    fun verdictPriorityIsSuThenWarnings() {
        val risk = DeviceHealth.evaluate("/system/xbin/su", testKeys = true, adbEnabled = true)
        assertEquals(Verdict.AT_RISK, risk.verdict)
        assertEquals(
            listOf(FindingId.ROOT_SU, FindingId.TEST_KEYS, FindingId.ADB_ENABLED),
            risk.findings.map { it.id }
        )

        val warning = DeviceHealth.evaluate(null, testKeys = false, adbEnabled = true)
        assertEquals(Verdict.WARNING, warning.verdict)
        assertEquals(listOf(FindingId.ADB_ENABLED), warning.findings.map { it.id })

        val healthy = DeviceHealth.evaluate(null, testKeys = false, adbEnabled = false)
        assertEquals(Verdict.HEALTHY, healthy.verdict)
        assertTrue(healthy.findings.isEmpty())
    }
}
