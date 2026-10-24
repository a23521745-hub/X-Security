package org.xsecurity.scanner.engine

import org.xsecurity.scanner.clamav.ClamAvDatabaseParser
import org.xsecurity.scanner.clamav.ClamAvScanner
import org.xsecurity.scanner.clamav.ClamHashDatabaseParser
import org.xsecurity.scanner.clamav.ClamHashScanner
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.core.SignatureDatabaseException
import org.xsecurity.scanner.yara.YaraRule
import org.xsecurity.scanner.yara.YaraRuleParser
import org.xsecurity.scanner.yara.YaraRuleSet
import org.xsecurity.scanner.yara.YaraScanner
import java.io.File

/**
 * YARA + ClamAV (desen) + ClamAV (hash) tarama katmanlarini orkestre eden motor.
 *
 * Ucuncu katman [ClamHashScanner]: dosyanin MD5/SHA-1/SHA-256 ozetlerini tek
 * okuma gecisinde hesaplayip `.hsb` hash veritabaninda arar. Desen katmanlari
 * her derlemede farkli dosyalari (msfvenom gibi) yakalarken, hash katmani
 * hic degismemis bilinen ornekleri (stalkerware APK'lari gibi) yanlis pozitif
 * pratikte olmadan tanir.
 *
 * Kurulus notlari (onceki surumdeki hatalara karsi):
 *  - Motor artik **kural/imza yuklenmeden tarama yapmiyor**; en az bir katman
 *    basarili olmali, aksi halde [SignatureDatabaseException] firlatilir. Boylece
 *    "0 imza ile temiz" raporu artik imkansiz.
 *  - Motor artik APK/ZIP **icerigini de taramaktadir**: ham baytlardan sonra
 *    girdiler (classes.dex, AndroidManifest.xml, assets/...) butce dahilinde
 *    acilip ayni imza setiyle taranir (bkz. [ApkContentScanner]). Boylece
 *    sikistirilmis dex icindeki dizgi kanitlari ("com/metasploit/..." gibi)
 *    ham-bayt taramasinda oldugu gibi kaybolmaz.
 *  - Cache, veritabani dosyalarinin (yol + boyut + mtime) parmak izine gore
 *    gecersiz kiliniyor; imza guncellemesi uygulamayi yeniden baslatmadan etkili olur.
 *  - Motor singleton olarak [ScanEngines] uzerinden paylasilir; worker her taramada
 *    yeni motor kurup butun veritabanini yeniden parse etmiyor.
 */
class ApkScannerEngine private constructor(
    val yaraRules: List<YaraRule>,
    val yaraStats: YaraRuleSet,
    val clamAvDatabase: ClamAvDatabaseParser.Database?,
    val hashDatabase: ClamHashDatabaseParser.Database?,
    val fingerprint: String,
    val warnings: List<String>
) {
    val yaraPatternCount: Int = yaraRules.sumOf { rule -> rule.strings.sumOf { it.variants().size } }
    val clamAvSignatureCount: Int = clamAvDatabase?.size ?: 0
    val hashSignatureCount: Int = hashDatabase?.size ?: 0
    val hasAnyPattern: Boolean
        get() = yaraPatternCount > 0 || clamAvSignatureCount > 0 || hashSignatureCount > 0

    /**
     * Derlenmis (pattern-matcher hazir) katmanlar: kural seti kalip agacina cevirmek
     * pahali oldugundan (binlerce kural/imza) her `scan()` cagrisinda DEGIL, motor
     * orneginde bir kez yapilir. Motor [ScanEngines] uzerinden parmak izi degisene
     * kadar paylasildigi icin kural/guncelleme geldiginde derleme otomatik tazelenir.
     * `by lazy` (senkron) oldugu icin birden fazla thread (paralel cihaz taramasi)
     * ayni motoru ayni anda tarayabilir.
     */
    private val yaraScanner: YaraScanner = YaraScanner()
    private val yaraCompiled: YaraScanner.Compiled by lazy { yaraScanner.compile(yaraRules) }
    private val clamScanner: ClamAvScanner = ClamAvScanner()
    private val clamCompiled: ClamAvScanner.Compiled? by lazy {
        if (clamAvDatabase != null && clamAvSignatureCount > 0) {
            clamScanner.compile(clamAvDatabase)
        } else {
            null
        }
    }
    private val hashScanner: ClamHashScanner = ClamHashScanner()

    /**
     * Tek dosya taramasi (ALI-18 #1: TOCTOU korumali).
     *
     * Garanti: raporun `sha256`'si **taranan icerigin** baslangic kimligidir ve
     * orijinal tarama sirasinda degisirse sonuc asla CLEAN/THREATS_FOUND olmaz —
     * INVALIDATED semantigiyle FAILED doner (cagiran yeniden tarar).
     *
     * @param snapshotDir verilirse ve dosya bu dizinin disindaysa, tarama
     *   app-private bir snapshot kopyasi uzerinden yapilir (paylasimli depolamada
     *   baska uygulamalarin eszamanli yazmasina karsi). `null` ise dosya
     *   dogrudan taranir ama pre/post kimlik karsilastirmasi yine uygulanir.
     */
    fun scan(
        apkFile: File,
        onProgress: (fraction: Float) -> Unit = {},
        snapshotDir: File? = null
    ): ScanResult {
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

        // Tarama kimligi basta yakalanir.
        val preSize = apkFile.length()
        val preModified = apkFile.lastModified()
        val preSha = runCatching { Digest.sha256Hex(apkFile) }.getOrNull()

        val snapshot = snapshotDir
            ?.takeIf { !isUnderDir(apkFile, it) }
            ?.let { dir ->
                stageSnapshot(apkFile, dir, preSize, preModified).getOrElse { error ->
                    return ScanResult.failed(
                        apkFile.absolutePath,
                        error.message ?: "Scan staging failed",
                        warnings
                    )
                }
            }
        val target = snapshot ?: apkFile
        try {
            val result = scanTarget(target, apkFile, preSha, onProgress)
            // Post-kontrol: orijinal tarama sirasinda degistiyse sonuc COPTUR.
            if (postChanged(apkFile, preSize, preModified, preSha)) {
                return ScanResult.failed(
                    apkFile.absolutePath,
                    "Scan invalidated: file changed during scan; result discarded.",
                    result.engineWarnings
                )
            }
            return result
        } finally {
            if (snapshot != null) runCatching { snapshot.delete() }
        }
    }

    /** Taramadan sonra orijinalin kimligi degisti mi? (boyut + mtime hizli yol, hash kesin hukum.) */
    private fun postChanged(file: File, preSize: Long, preModified: Long, preSha: String?): Boolean {
        if (file.length() != preSize || file.lastModified() != preModified) return true
        if (preSha != null) {
            val postSha = runCatching { Digest.sha256Hex(file) }.getOrNull()
            if (postSha != null && postSha != preSha) return true
        }
        return false
    }

    /**
     * [source]'u [dir] altina kopyalar; kopya penceresi sirasinda orijinal
     * degisirse yirtik kopya birakmadan hata doner.
     */
    private fun stageSnapshot(source: File, dir: File, preSize: Long, preModified: Long): Result<File> {
        return runCatching {
            dir.mkdirs()
            val copy = File.createTempFile("xsec-scan-", ".bin", dir)
            copy.deleteOnExit()
            try {
                source.inputStream().use { input -> copy.outputStream().use { output -> input.copyTo(output) } }
            } catch (error: Throwable) {
                runCatching { copy.delete() }
                throw error
            }
            if (source.length() != preSize || source.lastModified() != preModified) {
                runCatching { copy.delete() }
                throw java.io.IOException("Scan invalidated: file changed while being staged for scanning.")
            }
            copy
        }
    }

    /**
     * Gercek tarama: [target] okunur, rapor kimligi (yol/ad) [reportFile]'dan
     * alinir. Snapshot kullanildiginda ikisi farklidir; rapor her zaman
     * kullanicinin dosyasini anlatir, gecici kopyayi degil.
     */
    private fun scanTarget(
        target: File,
        reportFile: File,
        preSha256: String?,
        onProgress: (fraction: Float) -> Unit
    ): ScanResult {
        val startedAt = System.currentTimeMillis()
        val name = reportFile.name

        val size = target.length()
        val reportWarnings = ArrayList(warnings)
        val threats = ArrayList<ThreatMatch>()
        var scanned = 0L
        var totalUnits = size

        fun publish() {
            val done = if (totalUnits <= 0L) 1f else (scanned.toFloat() / totalUnits.toFloat()).coerceIn(0f, 1f)
            onProgress(done)
        }

        // Kurallar/imzalar motor seviyesinde bir kez derlenir (bkz. alan tanimlari);
        // ayni derlenmis kalip seti hem ham dosyada hem ZIP girdilerinde kullanilir
        // (bkz. ApkContentScanner) ve motorun paylastigi tum taramalar arasinda
        // yeniden derlenmez.
        var yaraOutcome = YaraScanner.Outcome(
            matches = emptyList(),
            scannedBytes = 0L,
            truncated = false,
            patterns = yaraCompiled.patterns.size,
            droppedPatterns = yaraCompiled.matcher.unusablePatternCount
        )
        var clamOutcome: ClamAvScanner.Outcome? = null

        // Iki tur: (1) ham baytlar, (2) varsa ZIP girdilerinin acilmis icerigi.
        // Girdi akislari yalnizca bu blogun icinde gecerlidir; ZipFile blok sonunda kapanir.
        var zipProblems = false
        ApkContentScanner.withEntries(target) { entrySources, notes ->
            totalUnits += notes.plannedBytes
            reportWarnings += notes.problems
            if (notes.problems.isNotEmpty()) zipProblems = true

            yaraOutcome = yaraScanner.matchBundle(
                compiled = yaraCompiled,
                file = target,
                entrySources = entrySources,
                entryBudget = ApkContentScanner.MAX_TOTAL_ENTRY_BYTES
            ) { consumed ->
                scanned = consumed
                publish()
            }

            // `by lazy` delegate'inin smart-cast gormemesi icin yerel degiskene alinir.
            val compiledClam = clamCompiled
            if (compiledClam != null) {
                clamOutcome = clamScanner.scanBundle(
                    compiled = compiledClam,
                    file = target,
                    entrySources = entrySources,
                    entryBudget = ApkContentScanner.MAX_TOTAL_ENTRY_BYTES
                ) { consumed ->
                    scanned = maxOf(scanned, consumed)
                    publish()
                }
            }
        }

        // Ucuncu katman: butun-dosya hash taramasi (MD5/SHA-1/SHA-256 tek geciste).
        // Hash imzasi APK-butunune bakar; ZIP girdilerine inilmez (icerigi desen
        // katmanlari zaten taradi). Hypatia'nin "one pass, three hashes"
        // optimizasyonunun birebir karsiligi.
        var hashOutcome: ClamHashScanner.Outcome? = null
        if (hashDatabase != null && hashSignatureCount > 0) {
            totalUnits += size
            val preHashScanned = scanned
            hashOutcome = hashScanner.scan(target, hashDatabase) { consumed ->
                scanned = maxOf(scanned, preHashScanned + consumed)
                publish()
            }
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
            reportWarnings += "YARA scan was truncated at ${yaraOutcome.scannedBytes / (1024 * 1024)} MB of scanned content; the rest was not scanned."
        }
        reportWarnings += yaraOutcome.warnings

        clamOutcome?.let { clam ->
            for (hit in clam.hits) {
                threats += ThreatMatch(
                    engine = ScanResult.ENGINE_CLAMAV,
                    name = hit.name,
                    detail = when {
                        hit.entryName != null && hit.firstPosition != null ->
                            "in ${hit.entryName} @ offset ${hit.firstPosition}"
                        hit.entryName != null -> "in ${hit.entryName}"
                        else -> hit.firstPosition?.let { "offset $it" }
                    },
                    position = hit.firstPosition
                )
            }
            if (clam.truncated) {
                reportWarnings += "ClamAV scan was truncated at ${clam.scannedBytes / (1024 * 1024)} MB of scanned content; the rest was not scanned."
            }
            reportWarnings += clam.warnings
        }

        hashOutcome?.let { hash ->
            for (hit in hash.hits) {
                threats += ThreatMatch(
                    engine = ScanResult.ENGINE_CLAM_HASH,
                    name = hit.name,
                    detail = "whole-file ${hit.algorithm.digestName} match " +
                        "(${hit.hashHex.take(12)}..., ${hit.fileSize} bytes)"
                )
            }
        }

        onProgress(1f)
        return ScanResult(
            status = if (threats.isEmpty()) ScanStatus.CLEAN else ScanStatus.THREATS_FOUND,
            filePath = reportFile.absolutePath,
            fileName = name,
            fileSize = size,
            // ALI-18 #1: rapor, sonda yeniden hesaplanan degil, basta yakalanan
            // kimligi tasir — boylece rapor her zaman taranan icerigi anlatir.
            sha256 = preSha256,
            partialScan = yaraOutcome.truncated ||
                (clamOutcome?.truncated == true) ||
                zipProblems,
            threats = threats,
            bytesScanned = scanned,
            durationMillis = System.currentTimeMillis() - startedAt,
            engineWarnings = reportWarnings
        )
    }

    companion object {

        /**
         * Veritabanlarini yukler. [yaraFile], [clamFile] ve [hashFile] `null` ya da
         * yoksa ilgili katman "devre disi" olarak raporlanir; ucunden hicbiri
         * kullanilabilir degilse hata doner.
         *
         * [communityYaraFiles] ve [communityHashFiles] dogrudan topluluk
         * kaynaklarindan (bkz. [org.xsecurity.scanner.community]) indirilen ek
         * dosyalardir; kuratorluk/OTA dosyalariyla BIRLESTIRILIR ancak asla
         * gecersiz kilamaz (ayni imza/kural varsa kuratorluk kazanir).
         */
        fun load(
            yaraFile: File?,
            clamFile: File?,
            hashFile: File? = null,
            communityYaraFiles: List<File> = emptyList(),
            communityHashFiles: List<File> = emptyList(),
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

            val hashResult: ClamHashDatabaseParser.Database? = when {
                hashFile == null -> {
                    warnings += "ClamAV hash layer disabled: no hash database selected."
                    null
                }
                !hashFile.isFile -> {
                    warnings += "ClamAV hash layer disabled: file not found (${hashFile.name})."
                    null
                }
                else -> runCatching { ClamHashDatabaseParser().parse(hashFile) }
                    .onFailure { warnings += "ClamAV hash layer failed to load: ${it.message}" }
                    .getOrNull()
            }

            // Topluluk kaynaklari: ayri dosyalar, birlesik veritabani. Kuratorluk
            // katmani once gelir; ayni hash iki tarafta varsa kuratorluk kazanir.
            val communityHashDatabases = communityHashFiles.filter { it.isFile }.mapNotNull { file ->
                runCatching { ClamHashDatabaseParser().parse(file) }
                    .onFailure { warnings += "Community hash source failed to load (${file.name}): ${it.message}" }
                    .getOrNull()
            }
            val mergedHashDatabase = when {
                hashResult != null && communityHashDatabases.isNotEmpty() ->
                    ClamHashDatabaseParser.merge(hashResult, communityHashDatabases)
                hashResult != null -> hashResult
                communityHashDatabases.isNotEmpty() ->
                    ClamHashDatabaseParser.merge(
                        ClamHashDatabaseParser().parseLines(emptyList()),
                        communityHashDatabases
                    )
                else -> null
            }
            val communityHashExtraCount = (mergedHashDatabase?.size ?: 0) - (hashResult?.size ?: 0)

            val communityYaraResults = communityYaraFiles.filter { it.isFile }.mapNotNull { file ->
                runCatching { yaraParser.parse(file) }
                    .onFailure { warnings += "Community YARA source failed to load (${file.name}): ${it.message}" }
                    .getOrNull()
            }
            val communityRuleCount = communityYaraResults.sumOf { it.ruleCount }

            val primaryRules = yaraResult?.rules ?: emptyList()
            val communityRules = communityYaraResults.flatMap { set -> set.rules }
            val rules = primaryRules + communityRules
            val stats = if (yaraResult == null && communityYaraResults.isEmpty()) {
                YaraRuleSet.EMPTY
            } else {
                YaraRuleSet(
                    rules = rules,
                    unparsableRules = (yaraResult?.unparsableRules ?: 0) +
                        communityYaraResults.sumOf { it.unparsableRules },
                    unsupportedStrings = (yaraResult?.unsupportedStrings ?: 0) +
                        communityYaraResults.sumOf { it.unsupportedStrings },
                    approximateConditions = (yaraResult?.approximateConditions ?: 0) +
                        communityYaraResults.sumOf { it.approximateConditions },
                    skippedRuleNames = (yaraResult?.skippedRuleNames ?: emptyList()) +
                        communityYaraResults.flatMap { it.skippedRuleNames },
                    problems = (yaraResult?.problems ?: emptyList()) +
                        communityYaraResults.flatMap { it.problems }
                )
            }
            if (rules.isEmpty() && clamResult == null && mergedHashDatabase == null) {
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
            mergedHashDatabase?.stats?.let { s ->
                if (s.malformed > 0) warnings += "ClamAV-hash: ${s.malformed} malformed line(s)."
                if (s.duplicates > 0) warnings += "ClamAV-hash: ${s.duplicates} duplicate line(s) skipped."
                if (s.unknownSize > 0) warnings += "ClamAV-hash: ${s.unknownSize} signature(s) have no size constraint (matched by hash alone)."
            }
            if (communityRuleCount > 0) {
                warnings += "Community YARA: +$communityRuleCount rule(s) from ${communityYaraResults.size} source(s)."
            }
            if (communityHashExtraCount > 0) {
                warnings += "Community hashes: +$communityHashExtraCount signature(s) from ${communityHashDatabases.size} source(s)."
            }

            return Result.success(
                ApkScannerEngine(
                    yaraRules = rules,
                    yaraStats = stats,
                    clamAvDatabase = clamResult,
                    hashDatabase = mergedHashDatabase,
                    fingerprint = fingerprintOf(
                        yaraFile,
                        clamFile,
                        hashFile,
                        *communityYaraFiles.toTypedArray(),
                        *communityHashFiles.toTypedArray()
                    ),
                    warnings = warnings
                )
            )
        }

        internal fun fingerprintOf(vararg files: File?): String =
            files.joinToString("|") { file ->
                if (file == null || !file.isFile) "missing" else "${file.absolutePath}:${file.length()}:${file.lastModified()}"
            }

        /**
         * [file] [dir] altinda mi? (canonical karsilastirma; symlink kacislarina
         * karsi.) Cagiranlar snapshot gerekip gerekmedigine bununla karar verir.
         */
        internal fun isUnderDir(file: File, dir: File): Boolean {
            val base = runCatching { dir.canonicalPath }.getOrNull() ?: dir.absolutePath
            val path = runCatching { file.canonicalPath }.getOrNull() ?: file.absolutePath
            val root = base.trimEnd('/')
            return path == root || path.startsWith("$root/")
        }
    }
}
