package org.xsecurity.scanner.definitions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.clamav.ClamAvDatabaseParser
import org.xsecurity.scanner.clamav.ClamHashDatabaseParser
import org.xsecurity.scanner.community.ClamHashCap
import org.xsecurity.scanner.community.CommunityDownloader
import org.xsecurity.scanner.community.CommunitySource
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.engine.ApkScannerEngine
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.yara.YaraRuleParser
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Kuratorluk tanim paketinin CI kalite kapisi.
 *
 * Bu testler her `testDebugUnitTest` kosusunda calisir; kurallarin motor tarafindan
 * TAM olarak yuklenememesi (unparsable / unsupported string / approximate condition)
 * veya paketle gelen asset'lerin `definitions/` dizininden kaymasi DERLEMEYI DUSURUR.
 * Boylece "yarisini yuklenen kural seti" sessizce uretime giremez.
 */
class DefinitionsQualityTest {

    /** Unit test calisma dizini modul dizinidir (app/); depoyu yukari dogru arar. */
    private fun repoFile(path: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".")
        while (dir != null) {
            val candidate = File(dir, path)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        throw AssertionError("Depo dosyasi bulunamadi: $path (user.dir=${System.getProperty("user.dir")})")
    }

    @Test
    fun curatedYaraRulesParseWithoutAnyLoss() {
        val set = YaraRuleParser().parse(repoFile("definitions/rules.yar"))

        assertTrue("en az 5 kural bekleniyor", set.ruleCount >= 5)
        assertEquals("unparsable kural olmamali", 0, set.unparsableRules)
        assertEquals("desteklenmeyen string sozdizimi olmamali", 0, set.unsupportedStrings)
        assertEquals("approximate condition olmamali", 0, set.approximateConditions)
        assertTrue("atlanan kural olmamali", set.skippedRuleNames.isEmpty())
        assertTrue(set.problems.isEmpty())
    }

    @Test
    fun curatedNdbParsesWithoutAnyLoss() {
        val database = ClamAvDatabaseParser().parse(repoFile("definitions/signatures.ndb"))

        assertTrue("en az 5 imza bekleniyor", database.size >= 5)
        assertEquals("malformed satir olmamali", 0, database.stats.malformed)
        assertEquals("desteklenmeyen kalipli imza olmamali", 0, database.stats.unsupportedPattern)
    }

    @Test
    fun curatedHsbParsesWithoutAnyLoss() {
        val database = ClamHashDatabaseParser().parse(repoFile("definitions/hashes.hsb"))

        assertTrue("en az 30 hash imzasi bekleniyor", database.size >= 30)
        assertEquals("malformed satir olmamali", 0, database.stats.malformed)
        assertEquals("tekrar eden hash olmamali", 0, database.stats.duplicates)
        // EICAR satirlari uc algoritmayi da icermeli (motorun dogrulanabilir atif noktasi).
        assertEquals("EICAR MD5", 1, database.stats.md5)
        assertEquals("EICAR SHA-1", 1, database.stats.sha1)
        assertEquals("EICAR + stalkerware SHA-256", database.size - 2, database.stats.sha256)
        // Stalkerware satirlari kaynaktan gelirken atif yorumu korunmali (CC BY 4.0).
        val header = repoFile("definitions/hashes.hsb").readText()
        assertTrue("AssoEchap atifi korunmali", header.contains("AssoEchap"))
        assertTrue("CC BY 4.0 atifi korunmali", header.contains("CC BY 4.0"))
    }

    @Test
    fun bundledAssetsMirrorTheDefinitionsDirectory() {
        for (name in listOf("rules.yar", "signatures.ndb", "hashes.hsb", "db-version.txt")) {
            val fromRepo = repoFile("definitions/$name")
            val fromAssets = repoFile("app/src/main/assets/signatures/$name")
            assertTrue(
                "asset ile definitions/ dizini farkli: $name",
                Digest.isSameContent(fromRepo, fromAssets)
            )
        }
    }

    /**
     * Dogrudan topluluk kaynaklari kayit defterinin CI kapisi: yalnizca izinli
     * hostlara https ile baglanabilir, kimlikler tekrarsiz olmali.
     */
    @Test
    fun communitySourceRegistryIsValid() {
        val raw = repoFile("app/src/main/assets/community-sources.json").readText()
        val sources = CommunitySource.fromJson(raw)

        assertTrue("en az 2 topluluk kaynagi bekleniyor", sources.size >= 2)
        assertTrue(
            "hash + yara kaynaklarinin ikisi de tanimli olmali",
            sources.any { it.kind == CommunitySource.Kind.HSB_FROM_CSV } &&
                sources.any { it.kind == CommunitySource.Kind.YARA }
        )
        val ids = sources.map { it.id }
        assertEquals("kaynak kimlikleri tekrarsiz olmali", ids.size, ids.distinct().size)
        for (source in sources) {
            assertTrue("https zorunlu: ${source.url}", source.url.startsWith("https://"))
            val host = java.net.URI(source.url).host
            assertTrue(
                "kaynak hostu izin listesinde degil: $host",
                host in CommunityDownloader.ALLOWED_HOSTS
            )
            assertTrue("maxEntries makul aralikta olmali", source.maxEntries in 1..ClamHashCap.HARD_LIMIT)
            assertTrue("lisans beyani zorunlu", source.license.isNotBlank())
        }
    }

    @Test
    fun dbVersionIsAPositiveInteger() {
        val version = repoFile("definitions/db-version.txt").readText().trim().toIntOrNull()
        assertNotNull("db-version.txt pozitif tamsayi icermeli", version)
        assertTrue(version != null && version > 0)
    }

    /**
     * Kullanicinin yasaddigi senaryonun regresyon kilidi: msfvenom ciktisi.
     *
     * Sahte ama gercekci bir msfvenom APK'si uretilir (Rex::Zip cikis duzeni:
     * DEFLATE ile classes.dex / AndroidManifest.xml / resources.arsc /
     * META-INF/SIGNFILE.*); kuratorluk paketiyle taranir. Beklenen: hem ham ZIP
     * yapisindan (SIGNFILE) hem acilmis dex/manifest iceriginden (com/metasploit)
     * tespit.
     */
    @Test
    fun msfvenomLikeApkIsDetectedByCuratedDefinitions() {
        val apk = File.createTempFile("xsec-msfvenom-", ".apk")
        apk.deleteOnExit()
        FileOutputStream(apk).use { output ->
            ZipOutputStream(output).use { zip ->
                fun entry(name: String, content: ByteArray) {
                    zip.putNextEntry(ZipEntry(name).apply { method = ZipEntry.DEFLATED })
                    zip.write(content)
                    zip.closeEntry()
                }
                // Ikili AndroidManifest.xml dizgileri UTF-16LE kodludur.
                entry(
                    "AndroidManifest.xml",
                    "com.metasploit.stage".toByteArray(Charsets.UTF_16LE)
                )
                // classes.dex: sinif tanimlayicilari "Lcom/...;" biciminde ASCII.
                entry(
                    "classes.dex",
                    "Lcom/metasploit/stage/Payload;Lcom/metasploit/androidpayload/stage/Meterpreter;"
                        .toByteArray()
                )
                entry("resources.arsc", ByteArray(64) { 0 })
                entry("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n".toByteArray())
                entry("META-INF/SIGNFILE.SF", "Signature-Version: 1.0\r\n\r\n".toByteArray())
                entry("META-INF/SIGNFILE.RSA", ByteArray(128) { 0x11 })
            }
        }

        val engine = ApkScannerEngine.load(
            repoFile("definitions/rules.yar"),
            repoFile("definitions/signatures.ndb")
        ).getOrThrow()

        val result = engine.scan(apk)
        assertEquals(ScanStatus.THREATS_FOUND, result.status)

        val names = result.threats.map { it.name }.toSet()
        // Ham ZIP yapisindan (girdi adlari) tespit:
        assertTrue("SIGNFILE tespiti eksik: $names", "Android_Metasploit_Jar_Signfile" in names)
        assertTrue("ndb SIGNFILE tespiti eksik: $names", "Android.Tool.Metasploit.Signfile" in names)
        // Acilmis dex iceriginden tespit:
        assertTrue("dex tespiti eksik: $names", "Android_Metasploit_Stage_Payload" in names)
        assertTrue("ndb dex tespiti eksik: $names", "Android.Trojan.Metasploit.Stage" in names)
        // Acilmis manifest (UTF-16LE) iceriginden tespit:
        assertTrue("manifest tespiti eksik: $names", "Android.Trojan.Metasploit.Manifest" in names)

        // Ayni imza iki katman tarafindan iki kez raporlanmamali.
        val clamNames = result.threats.filter { it.engine == ScanResult.ENGINE_CLAMAV }.map { it.name }
        assertEquals(clamNames.size, clamNames.toSet().size)
    }
}
