package org.xsecurity.scanner.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.clamav.ClamAvDatabaseParser
import org.xsecurity.scanner.clamav.ClamAvScanner
import org.xsecurity.scanner.clamav.ClamSignature
import org.xsecurity.scanner.yara.YaraMatcher
import org.xsecurity.scanner.yara.YaraRule
import org.xsecurity.scanner.yara.YaraRuleParser
import java.io.File

class ApkScannerEngine(
    private val yaraRuleParser: YaraRuleParser = YaraRuleParser(),
    private val yaraMatcher: YaraMatcher = YaraMatcher(),
    private val clamAvDatabaseParser: ClamAvDatabaseParser = ClamAvDatabaseParser(),
    private val clamAvScanner: ClamAvScanner = ClamAvScanner()
) {

    // Kuralları bellekte tutmak için cache yapıları
    private var cachedYaraRules: List<YaraRule>? = null
    private var cachedClamSignatures: List<ClamSignature>? = null

    /**
     * Veritabanlarını belleğe tek seferde yükler.
     */
    suspend fun initEngine(yaraRuleFile: File, clamAvDbFile: File) = withContext(Dispatchers.IO) {
        if (cachedYaraRules == null) {
            cachedYaraRules = yaraRuleParser.parse(yaraRuleFile)
        }
        if (cachedClamSignatures == null) {
            cachedClamSignatures = clamAvDatabaseParser.parse(clamAvDbFile)
        }
    }

    /**
     * APK dosyasını önceden yüklenmiş kurallarla tarar.
     */
    suspend fun scan(apkFile: File): ScanResult = withContext(Dispatchers.IO) {
        require(apkFile.exists()) { "Taranacak APK dosyası bulunamadı: ${apkFile.absolutePath}" }
        
        val yaraRules = cachedYaraRules ?: emptyList()
        val clamSignatures = cachedClamSignatures ?: emptyList()

        val yaraMatches = yaraMatcher.match(apkFile, yaraRules)
        val clamMatches = clamAvScanner.scan(apkFile, clamSignatures)

        ScanResult(
            filePath = apkFile.absolutePath,
            yaraMatches = yaraMatches,
            clamAvMatches = clamMatches
        )
    }
}
