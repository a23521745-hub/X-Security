package org.xsecurity.scanner.clamav

import org.xsecurity.scanner.core.SignatureDatabaseException
import org.xsecurity.scanner.matcher.HexPatternCodec
import java.io.File

/**
 * ClamAV `.ndb` veritabani okuyucu.
 *
 * Satir formati: `Name:TargetType:Offset:HexSignature[:MinSize,MaxSize]`
 *
 * Desteklenenler:
 *  - literal hex baytlari ve `??` / `A?` / `?B` nibble jokerleri,
 *  - sayisal offset formlari (`n`, `n,menzil`),
 *  - `*` / bos / `0` offset => kosul yok.
 *
 * Bilincli olarak desteklenmeyenler (sayacla raporlanir, sessiz elenmez):
 *  - degisken uzunluklu `*` hex jokeri, `|n-m|` atlama, `(a|b)` alternatifleri,
 *  - `TargetType` filtreleri (APK taramasinda hangi tipin gecerli oldugunu
 *    güvenli sekilde belirleyemiyoruz; bu yuzden tum imzalar dosyada aranir ve
 *    `targetTypesIgnored` sayaciyla "olasiz yanlis pozitif" bildirilir).
 */
class ClamAvDatabaseParser {

    class Stats(
        val totalLines: Int = 0,
        val loaded: Int = 0,
        val malformed: Int = 0,
        val unsupportedPattern: Int = 0,
        val symbolicOffsetsIgnored: Int = 0,
        val anchoredSignatures: Int = 0,
        val targetTypesIgnored: Int = 0,
        val problems: List<String> = emptyList()
    ) {
        val skipped: Int get() = malformed + unsupportedPattern
        val isPartial: Boolean
            get() = malformed > 0 || unsupportedPattern > 0 || symbolicOffsetsIgnored > 0 || targetTypesIgnored > 0
    }

    class Database(
        val signatures: List<ClamAvSignature>,
        val stats: Stats,
        val sourcePath: String?
    ) {
        val size: Int get() = signatures.size
    }

    fun parse(ndbFile: File): Database {
        if (!ndbFile.isFile) {
            throw SignatureDatabaseException("ClamAV database file not found: ${ndbFile.absolutePath}")
        }
        var totalLines = 0
        var loaded = 0
        var malformed = 0
        var unsupported = 0
        var symbolicOffsets = 0
        var anchored = 0
        var targetTypes = 0
        val problems = ArrayList<String>()
        val signatures = ArrayList<ClamAvSignature>()

        try {
            ndbFile.forEachLine { rawLine ->
                val line = rawLine.trim()
                if (line.isEmpty() || line.startsWith("#")) return@forEachLine
                totalLines++
                val parsed = parseLine(line)
                if (parsed == null) {
                    // Ayirt edilebilmesi icin tekrar bak: joker mi, format hatasi mi?
                    if (isUnsupportedHexField(line)) unsupported++ else malformed++
                    if (problems.size < MAX_PROBLEMS) problems += "atlandi: ${line.take(80)}"
                    return@forEachLine
                }
                loaded++
                if (parsed.signature.isAnchored) anchored++
                if (parsed.symbolicOffset) symbolicOffsets++
                if (parsed.signature.targetType != 0 && parsed.signature.targetType != -1) targetTypes++
                signatures += parsed.signature
            }
        } catch (error: Exception) {
            throw SignatureDatabaseException("ClamAV database could not be read: ${ndbFile.absolutePath}", error)
        }

        val stats = Stats(
            totalLines = totalLines,
            loaded = loaded,
            malformed = malformed,
            unsupportedPattern = unsupported,
            symbolicOffsetsIgnored = symbolicOffsets,
            anchoredSignatures = anchored,
            targetTypesIgnored = targetTypes,
            problems = problems
        )
        if (signatures.isEmpty() && totalLines > 0) {
            throw SignatureDatabaseException(
                "No scannable ClamAV signatures loaded (${ndbFile.name}: $totalLines lines, " +
                    "$malformed malformed lines, $unsupported unsupported patterns)" +
                    if (problems.isEmpty()) "" else " | examples: ${problems.joinToString(" / ")}"
            )
        }
        return Database(signatures, stats, ndbFile.absolutePath)
    }

    /** Test edilebilirlik icin dosya- bagimsiz giris noktasi. */
    fun parseLines(lines: List<String>): Database {
        val signatures = ArrayList<ClamAvSignature>()
        var malformed = 0
        var unsupported = 0
        var anchored = 0
        var symbolic = 0
        var targets = 0
        for (raw in lines) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val parsed = parseLine(line)
            if (parsed == null) {
                if (isUnsupportedHexField(line)) unsupported++ else malformed++
                continue
            }
            if (parsed.signature.isAnchored) anchored++
            if (parsed.symbolicOffset) symbolic++
            if (parsed.signature.targetType != 0 && parsed.signature.targetType != -1) targets++
            signatures += parsed.signature
        }
        return Database(
            signatures,
            Stats(
                totalLines = lines.size,
                loaded = signatures.size,
                malformed = malformed,
                unsupportedPattern = unsupported,
                symbolicOffsetsIgnored = symbolic,
                anchoredSignatures = anchored,
                targetTypesIgnored = targets
            ),
            sourcePath = null
        )
    }

    internal class ParsedLine(val signature: ClamAvSignature, val symbolicOffset: Boolean)

    internal fun parseLine(line: String): ParsedLine? {
        val parts = line.split(':')
        if (parts.size < 4 || parts.size > 5) return null

        val name = parts[0].trim()
        if (name.isEmpty()) return null

        val targetType = parts[1].trim().toIntOrNull() ?: -1

        val hex = parts[3].trim()
        if (hex.isEmpty() || HexPatternCodec.looksUnsupported(hex)) return null
        val decoded = HexPatternCodec.decode(hex) ?: return null
        if (decoded.length == 0) return null

        val (constraint, symbolic) = parseOffset(parts[2].trim())

        return ParsedLine(
            signature = ClamAvSignature(
                name = name,
                targetType = targetType,
                offset = constraint,
                bytes = decoded.bytes,
                mask = decoded.mask
            ),
            symbolicOffset = symbolic
        )
    }

    /**
     * `.ndb` `Offset` alani. Donusu: (kosul, sembolik-oldu-mu).
     *  - `*`, bos, `0` => kosul yok
     *  - `n` => tam konum, `n,m` => aralik
     *  - `e`, `x`, `le`, `be`, `"str"#n` gibi sembolik formlar => kosul yok + sayaç
     */
    internal fun parseOffset(field: String): Pair<ClamAvSignature.OffsetConstraint, Boolean> {
        if (field.isEmpty() || field == "*" || field == "-") {
            return ClamAvSignature.OffsetConstraint.Any to false
        }
        if (field.contains(',')) {
            val bits = field.split(',')
            if (bits.size == 2) {
                val from = bits[0].trim().toLongOrNull()
                val length = bits[1].trim().toLongOrNull()
                if (from != null && length != null && length >= 0) {
                    return ClamAvSignature.OffsetConstraint.Range(from, from + length) to false
                }
            }
            return ClamAvSignature.OffsetConstraint.Any to true
        }
        if (field == "0") return ClamAvSignature.OffsetConstraint.Any to false
        val position = field.toLongOrNull()
        if (position != null && position >= 0) {
            return ClamAvSignature.OffsetConstraint.Exact(position) to false
        }
        return ClamAvSignature.OffsetConstraint.Any to true
    }

    private fun isUnsupportedHexField(line: String): Boolean {
        val parts = line.split(':')
        if (parts.size < 4) return false
        return HexPatternCodec.looksUnsupported(parts[3].trim())
    }

    private companion object {
        const val MAX_PROBLEMS = 20
    }
}
