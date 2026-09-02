package org.xsecurity.scanner.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch

class DeviceScanSummaryTest {

    private val app = InstalledApp(packageName = "com.evil.spy", label = "Calculator", sourceDir = "/data/app/x/base.apk", versionName = "1.2")

    private fun clean(path: String) = ScanResult(ScanStatus.CLEAN, path, path.substringAfterLast('/'), 10L, sha256 = "abc")
    private fun infected(path: String, vararg names: String) = ScanResult(
        status = ScanStatus.THREATS_FOUND,
        filePath = path,
        fileName = path.substringAfterLast('/'),
        fileSize = 10L,
        sha256 = "def",
        threats = names.map { ThreatMatch(engine = "ClamAV-hash", name = it, detail = "sha256") }
    )

    @Test
    fun mergesSplitApkResultsIntoOneEntryAndDedupesThreats() {
        val entry = DeviceScanSummary.mergeEntry(
            app,
            listOf(infected("/a/base.apk", "Stalker.A"), infected("/a/split.apk", "Stalker.A", "Stalker.B"))
        )
        assertEquals(ScanStatus.THREATS_FOUND, entry.status)
        assertEquals(listOf("Stalker.A", "Stalker.B"), entry.threats.map { it.name })
        assertEquals("Calculator", entry.label)
        assertEquals("1.2", entry.versionName)
        assertTrue(entry.isInfected)
    }

    @Test
    fun partialFailureStillCleanWhenOneApkScanned() {
        val entry = DeviceScanSummary.mergeEntry(
            app,
            listOf(clean("/a/base.apk"), ScanResult.failed("/a/split.apk", "unreadable"))
        )
        assertEquals(ScanStatus.CLEAN, entry.status)
        assertEquals("unreadable", entry.errorMessage)
        assertFalse(entry.isFailed)
    }

    @Test
    fun allFailedOrEmptyIsFailed() {
        assertEquals(ScanStatus.FAILED, DeviceScanSummary.mergeEntry(app, emptyList()).status)
        assertEquals(
            ScanStatus.FAILED,
            DeviceScanSummary.mergeEntry(app, listOf(ScanResult.failed("/a/base.apk", "x"))).status
        )
    }

    @Test
    fun summaryResultCarriesLabelledThreats() {
        val entries = listOf(
            DeviceScanSummary.mergeEntry(app, listOf(infected("/a/base.apk", "Stalker.A"))),
            DeviceScanSummary.mergeEntry(app.copy(packageName = "com.ok", label = "Ok"), listOf(clean("/b/base.apk"))),
            DeviceScanSummary.mergeEntry(app.copy(packageName = "com.bad", label = "Bad"), emptyList())
        )
        val result = DeviceScanSummary.toScanResult(entries, durationMillis = 1234L, displayName = "Installed apps (3)")
        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertTrue(result.isComplete)
        assertEquals(1, result.threats.size)
        assertEquals("Calculator: Stalker.A", result.threats.single().name)
        assertEquals("com.evil.spy · sha256", result.threats.single().detail)
        assertEquals(1, result.engineWarnings.size)
        assertEquals(1234L, result.durationMillis)
        assertNull(result.errorMessage)
        assertEquals(1, DeviceScanSummary.infectedCount(entries))
        assertEquals(1, DeviceScanSummary.failedCount(entries))
        assertEquals(1, DeviceScanSummary.cleanCount(entries))
    }

    @Test
    fun summaryWithNothingScannableIsFailedNotClean() {
        val entries = listOf(DeviceScanSummary.mergeEntry(app, emptyList()))
        val result = DeviceScanSummary.toScanResult(entries, 1L, "x")
        assertEquals(ScanStatus.FAILED, result.status)
        assertFalse(result.isComplete)
        assertNotNull(result.errorMessage)
    }

    @Test
    fun emptyDeviceIsCleanSummary() {
        val result = DeviceScanSummary.toScanResult(emptyList(), 1L, "x")
        assertEquals(ScanStatus.CLEAN, result.status)
        assertTrue(result.isComplete)
    }
}
