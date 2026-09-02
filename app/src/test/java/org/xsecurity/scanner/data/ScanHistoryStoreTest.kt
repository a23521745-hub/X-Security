package org.xsecurity.scanner.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * [ScanHistoryStore] codec + kalicilik testleri (saf JVM): roundtrip, ust sinir,
 * en-yeniden-once sirasi, bozuk dosya toleransi.
 *
 * Izolasyon: store, bellek-ici listeyi surec geneli singleton'da tutar ve her
 * [ScanHistoryStore.record] o listeyi dosyaya kaldirir. Bu yuzden her testten once
 * singleton bosaltilir ([ScanHistoryStore.clear]), aksi halde testler arasi
 * kacinti olurdu.
 */
class ScanHistoryStoreTest {

    private lateinit var file: File

    @Before
    fun setUp() {
        file = File.createTempFile("xsec-history-", ".json").apply { deleteOnExit() }
        // Singleton'un bellek-ici listesini (ve varsa dosyayi) testten once temizle.
        ScanHistoryStore.clear(file)
    }

    private fun entry(
        timestamp: Long,
        type: ScanHistoryType = ScanHistoryType.FILE,
        title: String = "sample.apk"
    ) = ScanHistoryEntry(
        timestamp = timestamp,
        type = type,
        trigger = "test",
        title = title,
        status = "THREATS_FOUND",
        durationMillis = 120L + timestamp,
        bytesScanned = 4096L,
        appsScanned = 2,
        appsFlagged = 1,
        appsCached = 1,
        threatCount = 2,
        threats = listOf(
            ScanHistoryThreat("YARA", "Rule.One", "dex"),
            ScanHistoryThreat("ClamAV-hash", "Hash.Two")
        ),
        flaggedApps = listOf(
            ScanHistoryFlaggedApp("com.example.app", "App", listOf("Rule.One"))
        ),
        engineCounters = mapOf(
            ScanHistoryStore.COUNTER_YARA_RULES to 10,
            ScanHistoryStore.COUNTER_YARA_PATTERNS to 20,
            ScanHistoryStore.COUNTER_CLAM_SIGNATURES to 30,
            ScanHistoryStore.COUNTER_HASH_SIGNATURES to 40
        ),
        warnings = listOf("warn one", "warn two")
    )

    @Test
    fun roundTripsAllFields() {
        val original = entry(1000L, ScanHistoryType.DEVICE)

        ScanHistoryStore.record(file, original)

        val loaded = ScanHistoryStore.load(file)
        assertEquals(1, loaded.size)
        assertEquals(original, loaded.single())
    }

    @Test
    fun newestEntryStaysFirst() {
        ScanHistoryStore.record(file, entry(100L, title = "old"))
        ScanHistoryStore.record(file, entry(200L, title = "mid"))
        ScanHistoryStore.record(file, entry(300L, title = "new"))

        val loaded = ScanHistoryStore.load(file).map { it.title }
        assertEquals(listOf("new", "mid", "old"), loaded)
    }

    @Test
    fun oldestEntriesAreDroppedBeyondCap() {
        repeat(ScanHistoryStore.MAX_ENTRIES + 5) { index ->
            ScanHistoryStore.record(file, entry(index.toLong(), title = "scan-$index"))
        }

        val loaded = ScanHistoryStore.load(file)
        assertEquals(ScanHistoryStore.MAX_ENTRIES, loaded.size)
        // En yeni ilk, en eski 5'i dusmus.
        assertEquals("scan-${ScanHistoryStore.MAX_ENTRIES + 4}", loaded.first().title)
        assertEquals("scan-5", loaded.last().title)
    }

    @Test
    fun longListsAreCappedOnEncode() {
        val original = entry(1L).copy(
            threats = (1..ScanHistoryStore.MAX_THREATS + 25).map { ScanHistoryThreat("YARA", "R$it") },
            threatCount = ScanHistoryStore.MAX_THREATS + 25,
            flaggedApps = (1..ScanHistoryStore.MAX_FLAGGED_APPS + 15)
                .map { ScanHistoryFlaggedApp("com.p.$it", "P$it") },
            warnings = (1..ScanHistoryStore.MAX_WARNINGS + 10).map { "w$it" }
        )
        ScanHistoryStore.record(file, original)

        val loaded = ScanHistoryStore.load(file).single()
        assertEquals(ScanHistoryStore.MAX_THREATS, loaded.threats.size)
        assertEquals(ScanHistoryStore.MAX_FLAGGED_APPS, loaded.flaggedApps.size)
        assertEquals(ScanHistoryStore.MAX_WARNINGS, loaded.warnings.size)
        // Sayi alani kesilmis listeden buyuk kalir: UI gercek adedi gosterir.
        assertEquals(ScanHistoryStore.MAX_THREATS + 25, loaded.threatCount)
    }

    @Test
    fun missingOrCorruptFileYieldsEmptyHistory() {
        assertTrue(ScanHistoryStore.load(File("definitely-missing-${System.nanoTime()}.json")).isEmpty())

        val corrupt = File.createTempFile("xsec-history-corrupt-", ".json").apply { deleteOnExit() }
        corrupt.writeText("this is not json at all")
        assertTrue(ScanHistoryStore.load(corrupt).isEmpty())
    }

    @Test
    fun unknownTypeFallsBackToFile() {
        file.writeText(
            """
            [{"timestamp":1,"type":"NOPE","trigger":"t","title":"x","status":"CLEAN","duration":5,"bytes":10}]
            """.trimIndent()
        )
        val loaded = ScanHistoryStore.load(file)
        assertEquals(ScanHistoryType.FILE, loaded.single().type)
    }

    @Test
    fun clearRemovesMemoryAndFile() {
        ScanHistoryStore.record(file, entry(1L))
        assertTrue(file.isFile)

        ScanHistoryStore.clear(file)

        assertTrue(ScanHistoryStore.load(file).isEmpty())
        assertTrue(!file.exists())
    }
}
