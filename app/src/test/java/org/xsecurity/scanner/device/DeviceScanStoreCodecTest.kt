package org.xsecurity.scanner.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch

class DeviceScanStoreCodecTest {

    @Test
    fun roundTripsEntries() {
        val entries = listOf(
            AppScanEntry(
                packageName = "com.evil",
                label = "Evil",
                status = ScanStatus.THREATS_FOUND,
                threats = listOf(ThreatMatch("YARA", "Rule.X", "dex"), ThreatMatch("ClamAV-hash", "Hash.Y")),
                sha256 = "ff00",
                versionName = "2.0"
            ),
            AppScanEntry(packageName = "com.ok", label = "Ok", status = ScanStatus.CLEAN),
            AppScanEntry(packageName = "com.bad", label = "", status = ScanStatus.FAILED, errorMessage = "unreadable"),
            // P0: the system-package flag must survive the cache so the "no action" treatment
            // is not lost on a cached result.
            AppScanEntry(packageName = "com.oem.sys", label = "OEM", status = ScanStatus.THREATS_FOUND, isSystemPackage = true)
        )
        val decoded = DeviceScanStore.decodeEntries(DeviceScanStore.encodeEntries(entries))
        assertEquals(entries, decoded)
        assertNull(decoded[1].sha256)
        assertTrue(decoded[3].isSystemPackage)
    }

    @Test
    fun tolerantOfGarbageStatus() {
        val decoded = DeviceScanStore.decodeEntries("""[{"package":"a","label":"b","status":"NOPE"}]""")
        assertEquals(ScanStatus.FAILED, decoded.single().status)
    }

    @Test
    fun olderCacheWithoutTheSystemFlagDecodesAsNotSystem() {
        val decoded = DeviceScanStore.decodeEntries(
            """[{"package":"a","label":"b","status":"CLEAN","threats":[],"sha256":"","error":"","version":""}]"""
        )
        assertEquals(false, decoded.single().isSystemPackage)
    }
}
