package org.xsecurity.scanner.yara

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
        val droppedPatterns: Int
    ) {
        val isEmpty: Boolean get() = matches.isEmpty()
    }

    fun match(file: File, rules: List<YaraRule>, onBytes: (Long) -> Unit = {}): Outcome {
        if (rules.isEmpty() || !file.isFile) {
            return Outcome(emptyList(), 0L, truncated = false, patterns = 0, droppedPatterns = 0)
        }

        val patterns = ArrayList<BytePattern>()
        val patternRule = ArrayList<Int>(patterns.size)
        val patternString = ArrayList<Int>(patterns.size)
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
        if (matcher.isEmpty) {
            return Outcome(
                matches = emptyList(),
                scannedBytes = 0L,
                truncated = false,
                patterns = 0,
                droppedPatterns = matcher.unusablePatternCount
            )
        }

        val scan = matcher.scan(file, maxPositionsPerId = 0, onBytesConsumed = onBytes)
        val matchedPerRule = Array(rules.size) { HashSet<String>() }
        for (patternId in scan.matchedIds) {
            val pid = patternId as? Int ?: continue
            val ruleIndex = patternRule[pid]
            val stringIndex = patternString[pid]
            matchedPerRule[ruleIndex] += rules[ruleIndex].strings[stringIndex].identifier
        }

        val out = ArrayList<Match>()
        for (ruleIndex in rules.indices) {
            val rule = rules[ruleIndex]
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
            scannedBytes = scan.bytesScanned,
            truncated = scan.truncated,
            patterns = matcher.patternCount,
            droppedPatterns = matcher.unusablePatternCount
        )
    }
}
