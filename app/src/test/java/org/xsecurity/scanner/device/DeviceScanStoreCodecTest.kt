package org.xsecurity.scanner.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
            AppScanEntry(packageName = "com.bad", label = "", status = ScanStatus.FAILED, errorMessage = "unreadable")
        )
        val decoded = DeviceScanStore.decodeEntries(DeviceScanStore.encodeEntries(entries))
        assertEquals(entries, decoded)
        assertNull(decoded[1].sha256)
    }

    @Test
    fun tolerantOfGarbageStatus() {
        val decoded = DeviceScanStore.decodeEntries("""[{"package":"a","label":"b","status":"NOPE"}]""")
        assertEquals(ScanStatus.FAILED, decoded.single().status)
    }
}
