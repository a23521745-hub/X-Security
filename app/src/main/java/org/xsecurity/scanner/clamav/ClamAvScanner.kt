package org.xsecurity.scanner.clamav

import org.xsecurity.scanner.matcher.BytePattern
import org.xsecurity.scanner.matcher.BytePatternMatcher
import java.io.File

/**
 * ClamAV `.ndb` imzalarini dosya iceriginde arar.
 *
 * Tarama mantigi [BytePatternMatcher] ile paylasilir: dosyanin tamamı, sabit boyutlu
 * chunk'larla ve parca sinirini asan kaliplar icin "carry" tasiyarak taranir.
 * `.ndb` `Offset` alanindan gelen konum kosullari [positionFilter] olarak uygulanir.
 */
class ClamAvScanner(
    private val chunkSize: Int = BytePatternMatcher.DEFAULT_CHUNK_SIZE,
    private val maxBytesToScan: Long = BytePatternMatcher.DEFAULT_MAX_BYTES_TO_SCAN
) {

    class Hit(val name: String, val firstPosition: Long?)

    class Outcome(
        val hits: List<Hit>,
        val scannedBytes: Long,
        val truncated: Boolean,
        val evaluatedPatterns: Int,
        val droppedPatterns: Int
    ) {
        val names: List<String> get() = hits.map { it.name }
        val isEmpty: Boolean get() = hits.isEmpty()
    }

    fun scan(file: File, database: ClamAvDatabaseParser.Database, onBytes: (Long) -> Unit = {}): Outcome {
        val signatures = database.signatures
        if (signatures.isEmpty() || !file.isFile) {
            return Outcome(
                hits = emptyList(),
                scannedBytes = 0L,
                truncated = false,
                evaluatedPatterns = 0,
                droppedPatterns = 0
            )
        }

        val patterns = ArrayList<BytePattern>(signatures.size)
        for (index in signatures.indices) {
            val signature = signatures[index]
            patterns += BytePattern(
                id = index,
                bytes = signature.bytes,
                mask = signature.mask,
                ignoreCase = false
            )
        }

        val matcher = BytePatternMatcher(patterns, chunkSize, maxBytesToScan)
        if (matcher.isEmpty) {
            return Outcome(
                hits = emptyList(),
                scannedBytes = 0L,
                truncated = false,
                evaluatedPatterns = 0,
                droppedPatterns = matcher.unusablePatternCount
            )
        }

        val scan = matcher.scan(
            file = file,
            positionFilter = { id, position -> signatures[id].offset.accepts(position) },
            maxPositionsPerId = 1,
            onBytesConsumed = onBytes
        )

        val hits = scan.matchedIds.sorted().map { id ->
            Hit(name = signatures[id].name, firstPosition = scan.positions[id]?.firstOrNull())
        }
        return Outcome(
            hits = hits,
            scannedBytes = scan.bytesScanned,
            truncated = scan.truncated,
            evaluatedPatterns = matcher.patternCount,
            droppedPatterns = matcher.unusablePatternCount
        )
    }
}
