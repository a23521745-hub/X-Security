package org.xsecurity.scanner.engine

import org.xsecurity.scanner.clamav.ClamAvDatabaseParser
import org.xsecurity.scanner.clamav.ClamAvScanner
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.core.SignatureDatabaseException
import org.xsecurity.scanner.yara.YaraRule
import org.xsecurity.scanner.yara.YaraRuleParser
import org.xsecurity.scanner.yara.YaraRuleSet
import org.xsecurity.scanner.yara.YaraScanner
import java.io.File

/**
 * YARA + ClamAV tarama katmanlarini orkestre eden motor.
 *
 * Kurulus notlari (onceki surumdeki hatalara karsi):
 *  - Motor artik **kural/imza yuklenmeden tarama yapmiyor**; en az bir katman
 *    basarili olmali, aksi halde [SignatureDatabaseException] firlatilir. Boylece
 *    "0 imza ile temiz" raporu artik imkansiz.
 *  - Cache, veritabani dosyalarinin (yol + boyut + mtime) parmak izine gore
 *    gecersiz kiliniyor; imza guncellemesi uygulamayi yeniden baslatmadan etkili olur.
 *  - Motor singleton olarak [ScanEngines] uzerinden paylasilir; worker her taramada
 *    yeni motor kurup butun veritabanini yeniden parse etmiyor.
 */
class ApkScannerEngine private constructor(
    val yaraRules: List<YaraRule>,
    val yaraStats: YaraRuleSet,
    val clamAvDatabase: ClamAvDatabaseParser.Database?,
    val fingerprint: String,
    val warnings: List<String>
) {
    val yaraPatternCount: Int = yaraRules.sumOf { rule -> rule.strings.sumOf { it.variants().size } }
    val clamAvSignatureCount: Int = clamAvDatabase?.size ?: 0
    val hasAnyPattern: Boolean get() = yaraPatternCount > 0 || clamAvSignatureCount > 0

    fun scan(apkFile: File, onProgress: (fraction: Float) -> Unit = {}): ScanResult {
        val startedAt = System.currentTimeMillis()
        val name = apkFile.name
        if (!apkFile.isFile) {
            return ScanResult.failed(
                filePath = apkFile.absolutePath,
                message = "File to scan not found or is a directory: ${apkFile.absolutePath}",
                warnings = warnings
            )
        }
        if (!hasAnyPattern) {
            return ScanResult.failed(apkFile.absolutePath, "No signature layer was loaded", warnings)
        }

        val size = apkFile.length()
        val reportWarnings = ArrayList(warnings)
        val threats = ArrayList<ThreatMatch>()
        var scanned = 0L

        fun publish() {
            val done = if (size <= 0L) 1f else (scanned.toFloat() / size.toFloat()).coerceIn(0f, 1f)
            onProgress(done)
        }

        val yaraOutcome = YaraScanner().match(apkFile, yaraRules) { consumed ->
            scanned = consumed
            publish()
        }
        for (match in yaraOutcome.matches) {
            threats += ThreatMatch(
                engine = ScanResult.ENGINE_YARA,
                name = match.ruleName,
                detail = buildString {
                    append(match.strings.joinToString(", ") { "\$$it" })
                    if (!match.description.isNullOrBlank()) {
                        if (isNotEmpty()) append(" · ")
                        append(match.description)
                    }
                    if (match.approximate) append(" · condition approximated")
                }
            )
        }
        if (yaraOutcome.truncated) {
            reportWarnings += "YARA scan was truncated at ${yaraOutcome.scannedBytes / (1024 * 1024)} MB; the rest of the file was not scanned."
        }

        if (clamAvDatabase != null && clamAvSignatureCount > 0) {
            val clamOutcome = ClamAvScanner().scan(apkFile, clamAvDatabase) { consumed ->
                scanned = maxOf(scanned, consumed)
                publish()
            }
            for (hit in clamOutcome.hits) {
                threats += ThreatMatch(
                    engine = ScanResult.ENGINE_CLAMAV,
                    name = hit.name,
                    detail = hit.firstPosition?.let { "offset $it" },
                    position = hit.firstPosition
                )
            }
            if (clamOutcome.truncated) {
                reportWarnings += "ClamAV scan was truncated at ${clamOutcome.scannedBytes / (1024 * 1024)} MB; the rest of the file was not scanned."
            }
        }

        onProgress(1f)
        return ScanResult(
            status = if (threats.isEmpty()) ScanStatus.CLEAN else ScanStatus.THREATS_FOUND,
            filePath = apkFile.absolutePath,
            fileName = name,
            fileSize = size,
            sha256 = runCatching { Digest.sha256Hex(apkFile) }.getOrNull(),
            threats = threats,
            bytesScanned = scanned,
            durationMillis = System.currentTimeMillis() - startedAt,
            engineWarnings = reportWarnings
        )
    }

    companion object {

        /**
         * Veritabanlarini yukler. [yaraFile] ve [clamFile] `null` ya da yoksa ilgili
         * katman "devre disi" olarak raporlanir; ikisi de kullanilamazsa hata doner.
         */
        fun load(
            yaraFile: File?,
            clamFile: File?,
            yaraParser: YaraRuleParser = YaraRuleParser()
        ): Result<ApkScannerEngine> {
            val warnings = ArrayList<String>()

            val yaraResult: YaraRuleSet? = when {
                yaraFile == null -> {
                    warnings += "YARA layer disabled: no rule file selected."
                    null
                }
                !yaraFile.isFile -> {
                    warnings += "YARA layer disabled: file not found (${yaraFile.name})."
                    null
                }
                else -> runCatching { yaraParser.parse(yaraFile) }
                    .onFailure { warnings += "YARA layer failed to load: ${it.message}" }
                    .getOrNull()
            }

            val clamResult: ClamAvDatabaseParser.Database? = when {
                clamFile == null -> {
                    warnings += "ClamAV layer disabled: no database selected."
                    null
                }
                !clamFile.isFile -> {
                    warnings += "ClamAV layer disabled: file not found (${clamFile.name})."
                    null
                }
                else -> runCatching { ClamAvDatabaseParser().parse(clamFile) }
                    .onFailure { warnings += "ClamAV layer failed to load: ${it.message}" }
                    .getOrNull()
            }

            val rules = yaraResult?.rules ?: emptyList()
            val stats = yaraResult ?: YaraRuleSet.EMPTY
            if (rules.isEmpty() && clamResult == null) {
                return Result.failure(
                    SignatureDatabaseException(
                        "No signature layer could be loaded. " + warnings.joinToString(" ")
                    )
                )
            }
            if (rules.isEmpty()) {
                warnings += "YARA layer loaded with zero usable rules."
            }
            if (stats.unparsableRules > 0) {
                warnings += "YARA: ${stats.unparsableRules} rules could not be parsed" +
                    if (stats.skippedRuleNames.isNotEmpty()) " (${stats.skippedRuleNames.take(3).joinToString(", ")})" else ""
            }
            if (stats.unsupportedStrings > 0) {
                warnings += "YARA: ${stats.unsupportedStrings} string(s) skipped due to unsupported syntax (regex/xor/base64/fullword)."
            }
            if (stats.approximateConditions > 0) {
                warnings += "YARA: ${stats.approximateConditions} rule(s) had an unparsable condition; fell back to 'any of them'."
            }
            clamResult?.stats?.let { s ->
                if (s.malformed > 0) warnings += "ClamAV: ${s.malformed} malformed line(s)."
                if (s.unsupportedPattern > 0) warnings += "ClamAV: ${s.unsupportedPattern} signature(s) skipped (unsupported wildcard pattern)."
                if (s.symbolicOffsetsIgnored > 0) warnings += "ClamAV: ${s.symbolicOffsetsIgnored} signature(s) had a symbolic offset that could not be parsed (matched anywhere)."
                if (s.targetTypesIgnored > 0) warnings += "ClamAV: ${s.targetTypesIgnored} signature(s) are scanned without their target-type filter (possible false positives)."
            }

            return Result.success(
                ApkScannerEngine(
                    yaraRules = rules,
                    yaraStats = stats,
                    clamAvDatabase = clamResult,
                    fingerprint = fingerprintOf(yaraFile, clamFile),
                    warnings = warnings
                )
            )
        }

        internal fun fingerprintOf(vararg files: File?): String =
            files.joinToString("|") { file ->
                if (file == null || !file.isFile) "missing" else "${file.absolutePath}:${file.length()}:${file.lastModified()}"
            }
    }
}
