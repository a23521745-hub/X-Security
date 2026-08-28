package org.xsecurity.scanner.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Motorun uctan uca davranisi. Buradaki ilk iki test, projedeki en tehlikeli hataya
 * (imza yuklenemeyince "temiz" demek) karsi regresyon kilididir.
 */
class ApkScannerEngineTest {

    private val eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"

    private fun fileWith(name: String, content: String): File {
        val file = File.createTempFile("xsec-", name)
        file.deleteOnExit()
        file.writeText(content)
        return file
    }

    @Test
    fun loadFailsWhenNoLayerCanBeLoaded() {
        val missing = File("definitely-missing-${System.nanoTime()}.yar")
        val result = ApkScannerEngine.load(missing, File("also-missing-${System.nanoTime()}.ndb"))

        assertTrue("motor bos imza ile calismayi reddetmeli", result.isFailure)
        assertNotNull(result.exceptionOrNull())
    }

    @Test
    fun corruptDatabasesAreNotSilentlyTreatedAsEmpty() {
        // Onceki surum: parse edilemeyen dosya -> bos kural listesi -> "temiz".
        val junk = fileWith(".yar", "bu bir YARA dosyasi degil")
        val result = ApkScannerEngine.load(junk, File("absent.ndb"))

        assertTrue("bozuk veritabani hata olarak yukseltilmeli", result.isFailure)
        val message = result.exceptionOrNull()?.message.orEmpty()
        assertTrue(message.contains("YARA"))
    }

    @Test
    fun missingTargetFileYieldsFailedStatus() {
        val yara = fileWith(
            ".yar",
            "rule Demo { strings: ${'$'}a = \"NEEDLE\" condition: any of them }"
        )
        val engine = ApkScannerEngine.load(yara, File("absent.ndb")).getOrThrow()
        val result = engine.scan(File("no-such-file-${System.nanoTime()}.apk"))

        assertEquals(ScanStatus.FAILED, result.status)
        assertEquals(0, result.threats.size)
        assertNotNull(result.errorMessage)
    }

    @Test
    fun yaraOnlyEngineDetectsAndReportsClamDisabled() {
        val yara = fileWith(
            ".yar",
            "rule Demo { strings: ${'$'}a = \"NEEDLE\" condition: any of them }"
        )
        val engine = ApkScannerEngine.load(yara, File("absent.ndb")).getOrThrow()

        assertEquals(1, engine.yaraRules.size)
        assertEquals(0, engine.clamAvSignatureCount)
        assertTrue(engine.warnings.any { it.contains("ClamAV") })

        val hit = engine.scan(fileWith(".apk", "junk NEEDLE junk"))
        assertEquals(ScanStatus.THREATS_FOUND, hit.status)
        assertEquals(listOf("Demo"), hit.threats.map { it.name })
        assertEquals(ScanResult.ENGINE_YARA, hit.threats.single().engine)
        assertEquals("junk NEEDLE junk".toByteArray().size.toLong(), hit.fileSize)

        val clean = engine.scan(fileWith(".apk", "nothing here"))
        assertEquals(ScanStatus.CLEAN, clean.status)
        assertTrue(clean.isComplete)
        assertEquals(0, clean.threats.size)
    }

    @Test
    fun progressIsReportedMonotonically() {
        val yara = fileWith(
            ".yar",
            "rule Pacer { strings: ${'$'}a = \"zzzTAIL\" condition: any of them }"
        )
        val engine = ApkScannerEngine.load(yara, File("absent.ndb")).getOrThrow()
        val content = ByteArray(10_000) { 'q'.code.toByte() } + "zzzTAIL".encodeToByteArray()
        val target = fileWith(".apk", String(content, Charsets.ISO_8859_1))

        val seen = ArrayList<Float>()
        engine.scan(target) { seen += it }

        assertTrue(seen.isNotEmpty())
        assertEquals(seen.sorted(), seen)
        assertEquals(1.0, seen.last().toDouble(), 0.0001)
    }

    @Test
    fun bundledSampleAssetsDetectEicar() {
        val base = listOf(
            "src/main/assets/signatures",
            "app/src/main/assets/signatures",
            "../app/src/main/assets/signatures"
        ).map { File(it) }.firstOrNull { it.isDirectory } ?: return

        val yara = File(base, "sample-rules.yar")
        val ndb = File(base, "sample-signatures.ndb")
        if (!yara.isFile || !ndb.isFile) return

        val engine = ApkScannerEngine.load(yara, ndb).getOrThrow()
        assertTrue("ornek YARA kurallari yuklenmeli", engine.yaraRules.isNotEmpty())
        assertTrue("ornek ClamAV imzalari yuklenmeli", engine.clamAvSignatureCount > 0)

        val result = engine.scan(fileWith(".eicar", eicar))
        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertTrue(result.threats.any { it.engine == ScanResult.ENGINE_YARA })
        assertTrue(result.threats.any { it.engine == ScanResult.ENGINE_CLAMAV })
    }

    @Test
    fun engineCacheIsInvalidatedWhenSignatureFileChanges() {
        val yara = fileWith(
            ".yar",
            "rule V1 { strings: ${'$'}a = \"v1needle\" condition: any of them }"
        )
        val first = ScanEngines.acquire(yara, null).getOrThrow()
        assertEquals(listOf("V1"), first.yaraRules.map { it.name })

        // Ayni yol, icerik degisti: parmak izi (boyut/mtime) fark etmeli.
        Thread.sleep(20L)
        yara.writeText(
            "rule V2 { strings: ${'$'}a = \"v2needle\" condition: any of them }\n" +
                "rule V3 { strings: ${'$'}b = \"v3needle\" condition: any of them }"
        )
        yara.setLastModified(System.currentTimeMillis() + 5_000L)

        val second = ScanEngines.acquire(yara, null).getOrThrow()
        assertEquals(listOf("V2", "V3"), second.yaraRules.map { it.name })
    }
}
