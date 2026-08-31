package org.xsecurity.scanner.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * APK icerik taramasinin (ham bayt + acilmis ZIP girdileri) regresyon kilidi.
 *
 * Bu testlerin varlik sebebi: gercek APK'larda `classes.dex`/`AndroidManifest.xml`
 * DEFLATE ile sikistirilir; ham-bayt taramasi icerdeki dizgileri goremez. msfvenom
 * ciktisinin "temiz" gorunmesinin temel sebebi buydu.
 */
class ApkContentScannerTest {

    private fun tempFile(name: String, content: ByteArray): File {
        val file = File.createTempFile("xsec-", name)
        file.deleteOnExit()
        file.writeBytes(content)
        return file
    }

    private fun yaraFile(ruleText: String): File {
        val file = File.createTempFile("xsec-", ".yar")
        file.deleteOnExit()
        file.writeText(ruleText)
        return file
    }

    private fun zipFile(name: String, builder: (ZipOutputStream) -> Unit): File {
        val file = File.createTempFile("xsec-", name)
        file.deleteOnExit()
        FileOutputStream(file).use { output ->
            ZipOutputStream(output).use { zip -> builder(zip) }
        }
        return file
    }

    private fun putDeflated(zip: ZipOutputStream, name: String, content: ByteArray) {
        val entry = ZipEntry(name)
        entry.method = ZipEntry.DEFLATED
        zip.putNextEntry(entry)
        zip.write(content)
        zip.closeEntry()
    }

    @Test
    fun deflatedEntryContentIsScanned() {
        val yara = yaraFile(
            "rule Inside_Dex { strings: ${'$'}a = \"INNER-NEEDLE\" condition: any of them }"
        )
        val payload = "padding padding padding INNER-NEEDLE padding padding".toByteArray()
        val apk = zipFile(".apk") { zip -> putDeflated(zip, "classes.dex", payload) }

        // Gecerlilik kontrolu: dizgi gercekten sikistirilmis olmali; ham baytlarda
        // gorunuyorsa bu test aslinda ham turunu test ediyor demektir.
        assertFalse(
            "test dizgisi ham baytlarda gorunmemeli",
            String(apk.readBytes(), Charsets.ISO_8859_1).contains("INNER-NEEDLE")
        )

        val engine = ApkScannerEngine.load(yara, File("absent-${System.nanoTime()}.ndb")).getOrThrow()
        val result = engine.scan(apk)

        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertEquals(listOf("Inside_Dex"), result.threats.map { it.name })
    }

    @Test
    fun wideStringInsideManifestLikeEntryIsScanned() {
        // Ikili AndroidManifest.xml dizgileri UTF-16LE kodludur; YARA 'wide' varyanti
        // bunu acilmis girdi iceriginde yakalar.
        val yara = yaraFile(
            "rule Wide_Manifest { strings: ${'$'}m = \"com.example.evil\" wide condition: any of them }"
        )
        val manifest = "com.example.evil".toByteArray(Charsets.UTF_16LE)
        val apk = zipFile(".apk") { zip -> putDeflated(zip, "AndroidManifest.xml", manifest) }
        assertFalse(
            String(apk.readBytes(), Charsets.ISO_8859_1).contains("com.example.evil")
        )

        val engine = ApkScannerEngine.load(yara, File("absent-${System.nanoTime()}.ndb")).getOrThrow()
        val result = engine.scan(apk)

        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertEquals(listOf("Wide_Manifest"), result.threats.map { it.name })
    }

    @Test
    fun clamEntryHitIsAttributedToEntry() {
        val ndb = File.createTempFile("xsec-", ".ndb")
        ndb.deleteOnExit()
        // "INNER-NEEDLE" dizgisinin hex karsiligi.
        ndb.writeText("Test.Inner:0:*:494E4E45522D4E4545444C45\n")

        val apk = zipFile(".apk") { zip ->
            putDeflated(zip, "classes.dex", "padding INNER-NEEDLE padding".toByteArray())
        }

        val engine = ApkScannerEngine.load(
            File("absent-${System.nanoTime()}.yar"),
            ndb
        ).getOrThrow()
        val result = engine.scan(apk)

        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        val threat = result.threats.single()
        assertEquals("Test.Inner", threat.name)
        assertEquals(ScanResult.ENGINE_CLAMAV, threat.engine)
        assertTrue(
            "girdi atifi eksik: ${threat.detail}",
            threat.detail.orEmpty().contains("in classes.dex")
        )
    }

    @Test
    fun nonZipFileYieldsEmptySources() {
        val plain = tempFile(".apk", "just a plain file with RAWNEEDLE".toByteArray())
        ApkContentScanner.withEntries(plain) { sources, notes ->
            assertTrue(sources.isEmpty())
            assertEquals(0, notes.entries)
            assertTrue(notes.problems.isEmpty())
        }
    }

    @Test
    fun budgetLimitSkipsEntriesWithWarning() {
        val apk = zipFile(".apk") { zip ->
            putDeflated(zip, "classes.dex", ByteArray(64 * 1024) { 'A'.code.toByte() })
            putDeflated(zip, "assets/big.bin", ByteArray(64 * 1024) { 'B'.code.toByte() })
        }
        val outcome = ApkContentScanner.withEntries(apk, budget = 1024L) { sources, notes ->
            sources to notes
        }
        val sources = outcome.first
        val notes = outcome.second
        assertTrue("butce asan girdiler atlanmali", sources.isEmpty())
        assertTrue(
            "atlama uyari olarak raporlanmali",
            notes.problems.any { it.contains("budget") }
        )
    }

    @Test
    fun entriesWithinBudgetAreProvided() {
        val apk = zipFile(".apk") { zip ->
            putDeflated(zip, "classes.dex", ByteArray(1024) { 'A'.code.toByte() })
        }
        val outcome = ApkContentScanner.withEntries(apk, budget = 64L * 1024L) { sources, notes ->
            sources to notes
        }
        assertEquals(1, outcome.first.size)
        assertEquals("classes.dex", outcome.first.single().name)
    }

    @Test
    fun corruptZipFallsBackToRawScan() {
        val corrupt = tempFile(
            ".apk",
            byteArrayOf(0x50, 0x4B, 0x03, 0x04) + "garbage garbage RAWNEEDLE garbage".toByteArray()
        )

        ApkContentScanner.withEntries(corrupt) { sources, notes ->
            assertTrue(sources.isEmpty())
            assertTrue("bozuk ZIP uyari uretmeli", notes.problems.isNotEmpty())
        }

        val yara = yaraFile("rule Raw { strings: ${'$'}a = \"RAWNEEDLE\" condition: any of them }")
        val engine = ApkScannerEngine.load(yara, File("absent-${System.nanoTime()}.ndb")).getOrThrow()
        val result = engine.scan(corrupt)

        // Bozuk ZIP motoru cokertmemeli; ham tur sonucu korumali.
        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertEquals(1, result.threats.size)
        assertTrue(result.engineWarnings.isNotEmpty())
    }
}
