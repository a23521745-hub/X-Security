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
    fun bundledCuratedAssetsDetectEicar() {
        val base = listOf(
            "src/main/assets/signatures",
            "app/src/main/assets/signatures",
            "../app/src/main/assets/signatures"
        ).map { File(it) }.firstOrNull { it.isDirectory } ?: return

        val yara = File(base, "rules.yar")
        val ndb = File(base, "signatures.ndb")
        val hsb = File(base, "hashes.hsb")
        if (!yara.isFile || !ndb.isFile || !hsb.isFile) return

        val engine = ApkScannerEngine.load(yara, ndb, hsb).getOrThrow()
        assertTrue("paketle gelen YARA kurallari yuklenmeli", engine.yaraRules.isNotEmpty())
        assertTrue("paketle gelen ClamAV imzalari yuklenmeli", engine.clamAvSignatureCount > 0)
        assertTrue("paketle gelen hash imzalari yuklenmeli", engine.hashSignatureCount >= 30)

        val result = engine.scan(fileWith(".eicar", eicar))
        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertTrue(result.threats.any { it.engine == ScanResult.ENGINE_YARA })
        assertTrue(result.threats.any { it.engine == ScanResult.ENGINE_CLAMAV })
        // EICAR'in uc ozeti de hashes.hsb icinde: hash katmani da isabet raporlamali.
        val hashHits = result.clamHashThreats
        assertTrue("hash katmani EICAR'i bulmali: ${result.threats}", hashHits.isNotEmpty())
        assertTrue(hashHits.all { it.name == "Eicar.Test-File" })
        assertTrue(hashHits.any { it.detail?.contains("whole-file") == true })
    }

    @Test
    fun communitySourcesMergeIntoAllLayers() {
        // Topluluk YARA kaynagi: tek kural, belirgin igne.
        val communityYar = fileWith(
            ".yar",
            "rule Community_Test { strings: ${'$'}c = \"communityneedle\" condition: any of them }"
        )
        // Topluluk hash kaynagi: prob dosyasinin SHA-256 ozeti imzalanmis.
        val probeContent = "community hash layer probe communityneedle"
        val sha256 = java.security.MessageDigest.getInstance("SHA-256")
            .digest(probeContent.toByteArray())
            .joinToString("") { "%02x".format(it) }
        val communityHsb = fileWith(".hsb", "$sha256:-1:Community.Test.Signature")

        val engine = ApkScannerEngine.load(
            yaraFile = null,
            clamFile = null,
            hashFile = null,
            communityYaraFiles = listOf(communityYar),
            communityHashFiles = listOf(communityHsb)
        ).getOrThrow()

        assertEquals(listOf("Community_Test"), engine.yaraRules.map { it.name })
        assertEquals(1, engine.hashSignatureCount)
        assertTrue(engine.hasAnyPattern)

        val result = engine.scan(fileWith(".bin", probeContent))
        assertEquals(ScanStatus.THREATS_FOUND, result.status)
        assertTrue(
            "topluluk YARA kurali atlamali: " + result.threats,
            result.threats.any { it.engine == ScanResult.ENGINE_YARA && it.name == "Community_Test" }
        )
        assertTrue(
            "topluluk hash imzasi atlamali: " + result.threats,
            result.threats.any { it.engine == ScanResult.ENGINE_CLAM_HASH && it.name == "Community.Test.Signature" }
        )
    }

    @Test
    fun curatedHashWinsOverCommunityDuplicate() {
        // Ayni ozet hem kuratorluk hem topluluk dosyasinda: kuratorluk kazanmali.
        val base = listOf(
            "src/main/assets/signatures",
            "app/src/main/assets/signatures",
            "../app/src/main/assets/signatures"
        ).map { File(it) }.firstOrNull { it.isDirectory } ?: return
        val curated = File(base, "hashes.hsb")
        if (!curated.isFile) return

        val digest = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        val communityHsb = fileWith(".hsb", "$digest:-1:Community.Duplicate.Name")

        val curatedOnly = ApkScannerEngine.load(
            yaraFile = null, clamFile = null, hashFile = curated
        ).getOrThrow()
        val merged = ApkScannerEngine.load(
            yaraFile = null, clamFile = null, hashFile = curated,
            communityHashFiles = listOf(communityHsb)
        ).getOrThrow()

        assertEquals(
            "ayni ozet iki tarafta: birlesik boyut artmamali",
            curatedOnly.hashSignatureCount,
            merged.hashSignatureCount
        )
        assertEquals(
            "Eicar.Test-File",  // kuratorluk hsb'deki isim; topluluk gecersiz kilamaz
            merged.hashDatabase!!.signatures[digest]!!.name
        )
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
