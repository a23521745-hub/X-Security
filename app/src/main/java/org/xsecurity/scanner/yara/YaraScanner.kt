package org.xsecurity.scanner.yara

import org.xsecurity.scanner.engine.ApkContentScanner
import org.xsecurity.scanner.matcher.BytePattern
import org.xsecurity.scanner.matcher.BytePatternMatcher
import java.io.File

/**
 * YARA kurallarini dosya iceriginde arar ve `condition:` bloğunu değerlendirir.
 *
 * Eski `YaraMatcher` iki sey yapiyordu: (1) dosyanin ilk 8 MB'ini belleğe alip
 * yalnizca orada ariyordu, (2) `condition:` i hiç görmeyip "TUM stringler eslesmeli"
 * diyordu. Ikincisi gercek kural tabaninda (genelde `any of them`) neredeyse hic
 * eslesme uretmez; birincisi ise 8 MB sonrasi korumasiz birakirdi.
 *
 * Bu surum ayrica **cok kaynakli** taramayi destekler: [matchBundle] ayni derlenmis
 * kural setini dosyanin ham baytlari VE ZIP girdilerinin acilmis icerigi uzerinde
 * calistirir. YARA semantiginde kosul dosya-duzeyli oldugundan, eslesen dizgi
 * kumeleri birlestirilir ve `condition:` **bir kez** degerlendirilir — boylece ham
 * baytta ve dex icinde ayri ayri eslesen dizgiler `all of them` kosulunu birlikte
 * tatmin edebilir (gercek YARA davranisiyla uyumlu).
 */
class YaraScanner(
    private val chunkSize: Int = BytePatternMatcher.DEFAULT_CHUNK_SIZE,
    private val maxBytesToScan: Long = BytePatternMatcher.DEFAULT_MAX_BYTES_TO_SCAN
) {

    class Match(
        val ruleName: String,
        val strings: List<String>,
        val approximate: Boolean,
        val description: String?
    )

    class Outcome(
        val matches: List<Match>,
        val scannedBytes: Long,
        val truncated: Boolean,
        val patterns: Int,
        val droppedPatterns: Int,
        /** Kaynak-basi (tek ZIP girdisi) okuma hatalari; rapora uyari olarak tasınır. */
        val warnings: List<String> = emptyList()
    ) {
        val isEmpty: Boolean get() = matches.isEmpty()
    }

    /**
     * Bir kural setinin taranabilir hali. Kurallar -> kalip derlemesi pahali oldugundan
     * ([ApkContentScanner] ile tek dosya icin bircok akis taranirken) bir kez yapilir.
     */
    class Compiled internal constructor(
        internal val rules: List<YaraRule>,
        internal val patterns: List<BytePattern>,
        internal val patternRule: List<Int>,
        internal val patternString: List<Int>,
        internal val matcher: BytePatternMatcher
    )

    /** Kurallari kalip matcher'ina cevirir. Bos kural listesi gecerlidir (bosa calisir). */
    fun compile(rules: List<YaraRule>): Compiled {
        val patterns = ArrayList<BytePattern>()
        val patternRule = ArrayList<Int>()
        val patternString = ArrayList<Int>()
        for (ruleIndex in rules.indices) {
            val rule = rules[ruleIndex]
            for (stringIndex in rule.strings.indices) {
                val declaration = rule.strings[stringIndex]
                for (variant in declaration.variants()) {
                    val id = patterns.size
                    patterns += BytePattern(
                        id = id,
                        bytes = variant.bytes,
                        mask = variant.mask,
                        ignoreCase = declaration.ignoreCase()
                    )
                    patternRule += ruleIndex
                    patternString += stringIndex
                }
            }
        }
        val matcher = BytePatternMatcher(patterns, chunkSize, maxBytesToScan)
        return Compiled(rules, patterns, patternRule, patternString, matcher)
    }

    /** Tek dosyayi (yalnizca ham baytlarini) tarar — geriye donusum-uyumlu kisa yol. */
    fun match(file: File, rules: List<YaraRule>, onBytes: (Long) -> Unit = {}): Outcome {
        if (rules.isEmpty() || !file.isFile) {
            return Outcome(emptyList(), 0L, truncated = false, patterns = 0, droppedPatterns = 0)
        }
        return matchBundle(compile(rules), file, emptyList(), 0L, onBytes)
    }

    /**
     * Ham dosya + ZIP girdileri icin birlesik tarama.
     *
     * @param entryBudget ZIP girdilerinin acilmis toplami icin butce (bayt). Her girdi
     *   en fazla kalan butce kadar okunur; butce biterse kalan girdiler atlanir ve
     *   `truncated` bayragi set edilir.
     */
    fun matchBundle(
        compiled: Compiled,
        file: File,
        entrySources: List<ApkContentScanner.EntrySource>,
        entryBudget: Long,
        onBytes: (Long) -> Unit = {}
    ): Outcome {
        if (compiled.rules.isEmpty() || !file.isFile) {
            return Outcome(
                emptyList(),
                0L,
                truncated = false,
                patterns = compiled.patterns.size,
                droppedPatterns = compiled.matcher.unusablePatternCount
            )
        }
        if (compiled.matcher.isEmpty) {
            return Outcome(
                matches = emptyList(),
                scannedBytes = 0L,
                truncated = false,
                patterns = 0,
                droppedPatterns = compiled.matcher.unusablePatternCount
            )
        }

        val warnings = ArrayList<String>()
        val matchedPerRule = Array(compiled.rules.size) { HashSet<String>() }
        var rawScanned = 0L
        var entriesScanned = 0L
        var truncated = false
        var budget = entryBudget.coerceAtLeast(0L)

        // Kaynak 1: dosyanin ham baytlari.
        file.inputStream().buffered().use { stream ->
            val scan = compiled.matcher.scan(
                stream,
                maxPositionsPerId = 0,
                onBytesConsumed = { consumed ->
                    rawScanned = consumed
                    onBytes(rawScanned + entriesScanned)
                }
            )
            absorb(scan.matchedIds, matchedPerRule, compiled)
            rawScanned = scan.bytesScanned
            if (scan.truncated) truncated = true
        }

        // Kaynak 2..n: ZIP girdilerinin acilmis icerigi.
        for (source in entrySources) {
            if (budget <= 0L) {
                truncated = true
                break
            }
            var sourceScanned = 0L
            try {
                source.open().use { stream ->
                    val scan = compiled.matcher.scan(
                        stream,
                        maxBytesToScan = budget,
                        maxPositionsPerId = 0,
                        onBytesConsumed = { consumed ->
                            sourceScanned = consumed
                            onBytes(rawScanned + entriesScanned + sourceScanned)
                        }
                    )
                    absorb(scan.matchedIds, matchedPerRule, compiled)
                    sourceScanned = scan.bytesScanned
                    if (scan.truncated) truncated = true
                }
            } catch (error: Exception) {
                // Tek bir bozuk girdi (CRC vb.) taramayi oldurmaz; uyari uretir.
                warnings += "ZIP entry '${source.name}' could not be scanned" +
                    " (${error.message ?: error.javaClass.simpleName})."
                sourceScanned = 0L
            }
            entriesScanned += sourceScanned
            budget = (budget - sourceScanned).coerceAtLeast(0L)
        }

        val out = ArrayList<Match>()
        for (ruleIndex in compiled.rules.indices) {
            val rule = compiled.rules[ruleIndex]
            val matched = matchedPerRule[ruleIndex]
            if (rule.condition.evaluate(matched, rule.stringIdentifiers)) {
                out += Match(
                    ruleName = rule.name,
                    strings = matched.sorted(),
                    approximate = rule.approximateCondition,
                    description = rule.description
                )
            }
        }
        return Outcome(
            matches = out,
            scannedBytes = rawScanned + entriesScanned,
            truncated = truncated,
            patterns = compiled.patterns.size,
            droppedPatterns = compiled.matcher.unusablePatternCount,
            warnings = warnings
        )
    }

    /** Bir tarama sonucundaki eslesen kalip kimliklerini kural/dizgi kumelerine isler. */
    private fun absorb(
        matchedIds: Set<Any>,
        matchedPerRule: Array<HashSet<String>>,
        compiled: Compiled
    ) {
        for (patternId in matchedIds) {
            val pid = patternId as? Int ?: continue
            val ruleIndex = compiled.patternRule[pid]
            val stringIndex = compiled.patternString[pid]
            matchedPerRule[ruleIndex] += compiled.rules[ruleIndex].strings[stringIndex].identifier
        }
    }
}
