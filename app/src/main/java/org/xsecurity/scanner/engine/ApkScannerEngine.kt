package org.xsecurity.scanner.engine

import org.xsecurity.scanner.clamav.ClamAvDatabaseParser
import org.xsecurity.scanner.clamav.ClamAvScanner
import org.xsecurity.scanner.yara.YaraMatcher
import org.xsecurity.scanner.yara.YaraRuleParser
import java.io.File

class ApkScannerEngine(
    private val yaraRuleParser: YaraRuleParser = YaraRuleParser(),
    private val yaraMatcher: YaraMatcher = YaraMatcher(),
    private val clamAvDatabaseParser: ClamAvDatabaseParser = ClamAvDatabaseParser(),
    private val clamAvScanner: ClamAvScanner = ClamAvScanner()
) {
    fun scan(apkPath: String, yaraRulePath: String, clamAvDbPath: String): ScanResult {
        val apkFile = File(apkPath)
        val yaraRules = yaraRuleParser.parse(File(yaraRulePath))
        val clamSignatures = clamAvDatabaseParser.parse(File(clamAvDbPath))

        val yaraMatches = yaraMatcher.match(apkFile, yaraRules)
        val clamMatches = clamAvScanner.scan(apkFile, clamSignatures)

        return ScanResult(
            filePath = apkPath,
            yaraMatches = yaraMatches,
            clamAvMatches = clamMatches
        )
    }
}
