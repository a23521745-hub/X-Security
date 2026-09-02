package org.xsecurity.scanner.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch
import java.io.File

/**
 * [DeviceScanCache] davranisi (saf JVM): hit/miss, parmak izi eslemesi,
 * surum/guncelleme degisikligi, bozuk dosya toleransi, prunedur.
 */
class DeviceScanCacheTest {

    private fun tempFile(): File = File.createTempFile("xsec-device-cache-", ".json").apply { deleteOnExit() }

    private fun app(
        packageName: String = "com.example.app",
        versionCode: Long = 7L,
        lastUpdateTime: Long = 1_000L
    ) = InstalledApp(
        packageName = packageName,
        label = "Example",
        sourceDir = "/data/app/$packageName/base.apk",
        versionCode = versionCode,
        lastUpdateTime = lastUpdateTime
    )

    private fun entry(
        packageName: String = "com.example.app",
        status: ScanStatus = ScanStatus.CLEAN,
        threats: List<ThreatMatch> = emptyList()
    ) = AppScanEntry(
        packageName = packageName,
        label = "Example",
        status = status,
        threats = threats,
        sha256 = "abcdef0123456789",
        versionName = "1.0",
        bytesScanned = 2048L,
        durationMillis = 42L
    )

    private fun snapshotFor(app: InstalledApp, fingerprint: String = "fp-1") = DeviceScanCache.Snapshot(
        fingerprint = fingerprint,
        apps = mapOf(app.packageName to DeviceScanCache.CachedApp(app.versionCode, app.lastUpdateTime, entry(app.packageName)))
    )

    @Test
    fun hitRequiresMatchingFingerprintVersionAndTime() {
        val file = tempFile()
        val snapshot = snapshotFor(app())
        DeviceScanCache.save(file, snapshot)
        val loaded = DeviceScanCache.load(file)
        assertNotNull(loaded)

        assertEquals(entry(), DeviceScanCache.hitFor(loaded, "fp-1", app()))
        assertNull("farkli parmak izi: tum onbellek gecerli degil", DeviceScanCache.hitFor(loaded, "fp-2", app()))
        assertNull("surum degisti: yeniden tara", DeviceScanCache.hitFor(loaded, "fp-1", app(versionCode = 8L)))
        assertNull("yerinde guncelleme: yeniden tara", DeviceScanCache.hitFor(loaded, "fp-1", app(lastUpdateTime = 2_000L)))
        assertNull("bilinmeyen paket", DeviceScanCache.hitFor(loaded, "fp-1", app(packageName = "com.other")))
        assertNull("snapshot null (dosya yok) her zaman miss", DeviceScanCache.hitFor(null, "fp-1", app()))
    }

    @Test
    fun roundTripsSnapshotWithFullEntries() {
        val file = tempFile()
        val appA = app("com.a", 1L, 10L)
        val appB = app("com.b", 2L, 20L)
        val infected = entry("com.b", ScanStatus.THREATS_FOUND, listOf(ThreatMatch("YARA", "Rule.X", "dex")))
        DeviceScanCache.save(
            file,
            DeviceScanCache.Snapshot(
                fingerprint = "fp-9",
                apps = mapOf(
                    appA.packageName to DeviceScanCache.CachedApp(appA.versionCode, appA.lastUpdateTime, entry("com.a")),
                    appB.packageName to DeviceScanCache.CachedApp(appB.versionCode, appB.lastUpdateTime, infected)
                )
            )
        )

        val loaded = DeviceScanCache.load(file)
        assertNotNull(loaded)
        assertEquals("fp-9", loaded!!.fingerprint)
        assertEquals(2, loaded.apps.size)
        assertEquals(infected, loaded.apps.getValue("com.b").entry)
        assertEquals(1L, loaded.apps.getValue("com.a").versionCode)
    }

    @Test
    fun missingOrCorruptFileYieldsNull() {
        assertNull(DeviceScanCache.load(File("definitely-missing-${System.nanoTime()}.json")))

        val file = tempFile()
        file.writeText("{ not valid json ]")
        assertNull(DeviceScanCache.load(file))

        val noFingerprint = tempFile()
        noFingerprint.writeText("""{"apps":{}}""")
        assertNull("fingerprint yoksa onbellek gecerli sayilmaz", DeviceScanCache.load(noFingerprint))
    }

    @Test
    fun saveOverwritesPreviousSnapshot() {
        val file = tempFile()
        DeviceScanCache.save(file, snapshotFor(app(), "fp-1"))
        DeviceScanCache.save(file, snapshotFor(app(), "fp-2"))

        val loaded = DeviceScanCache.load(file)
        assertNotNull(loaded)
        assertEquals("fp-2", loaded!!.fingerprint)
    }

    @Test
    fun pruneKeepsOnlyStillInstalledPackages() {
        val apps = listOf(app("com.a"), app("com.b"), app("com.c"))
        val snapshot = DeviceScanCache.Snapshot(
            fingerprint = "fp-1",
            apps = apps.associateBy(
                keySelector = { it.packageName },
                valueSelector = { DeviceScanCache.CachedApp(it.versionCode, it.lastUpdateTime, entry(it.packageName)) }
            )
        )

        val pruned = DeviceScanCache.prune(snapshot, setOf("com.a", "com.c"))

        assertEquals(setOf("com.a", "com.c"), pruned.keys)
        val prunedToNone = DeviceScanCache.prune(snapshot, emptySet())
        assertTrue(prunedToNone.isEmpty())
    }
}
