package org.xsecurity.scanner.clamav

import org.xsecurity.scanner.engine.ApkContentScanner
import org.xsecurity.scanner.matcher.BytePattern
import org.xsecurity.scanner.matcher.BytePatternMatcher
import java.io.File

/**
 * ClamAV `.ndb` imzalarini dosya iceriginde arar.
 *
 * Tarama mantigi [BytePatternMatcher] ile paylasilir: dosyanin tamamı, sabit boyutlu
 * chunk'larla ve parca sinirini asan kaliplar icin "carry" tasiyarak taranir.
 * `.ndb` `Offset` alanindan gelen konum kosullari [positionFilter] olarak uygulanir.
 *
 * Bu surum **cok kaynakli** taramayi da destekler (bkz. [scanBundle]): imzalar dosyanin
 * ham baytlarinda VE ZIP girdilerinin acilmis iceriginde aranir. Iki kural:
 *  1. Konum-kosulu (anchored) imzalar yalnizca **ham dosyada** gecerlidir; girdi
 *     akislarindaki konum, `.ndb`'nin kastettigi konumla iliskisiz oldugundan girdi
 *     icinde uygulanmazlar.
 *  2. Ayni imza hem ham dosyada hem girdide eslesirse tekrar etmez; imza basina tek
 *     [Hit] uretilir (girdi kaynakli eslesme ayrica `entryName` tasir).
 */
class ClamAvScanner(
    private val chunkSize: Int = BytePatternMatcher.DEFAULT_CHUNK_SIZE,
    private val maxBytesToScan: Long = BytePatternMatcher.DEFAULT_MAX_BYTES_TO_SCAN
) {

    class Hit(
        val name: String,
        val firstPosition: Long?,
        /** Eslesme ZIP girdisinin acilmis iceriginde bulunduysa girdi adi; ham dosyadaysa `null`. */
        val entryName: String? = null
    )

    class Outcome(
        val hits: List<Hit>,
        val scannedBytes: Long,
        val truncated: Boolean,
        val evaluatedPatterns: Int,
        val droppedPatterns: Int,
        /** Kaynak-basi (tek ZIP girdisi) okuma hatalari; rapora uyari olarak tasınır. */
        val warnings: List<String> = emptyList()
    ) {
        val names: List<String> get() = hits.map { it.name }
        val isEmpty: Boolean get() = hits.isEmpty()
    }

    /** Bir `.ndb` veritabaninin taranabilir hali; girdi akislari arasinda yeniden kullanilir. */
    class Compiled internal constructor(
        internal val signatures: List<ClamAvSignature>,
        internal val matcher: BytePatternMatcher
    )

    fun compile(database: ClamAvDatabaseParser.Database): Compiled {
        val signatures = database.signatures
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
        return Compiled(signatures, BytePatternMatcher(patterns, chunkSize, maxBytesToScan))
    }

    /** Tek dosyayi (yalnizca ham baytlarini) tarar — geriye donusum-uyumlu kisa yol. */
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
        return scanBundle(compile(database), file, emptyList(), 0L, onBytes)
    }

    /**
     * Ham dosya + ZIP girdileri icin birlesik tarama.
     *
     * @param entryBudget ZIP girdilerinin acilmis toplami icin butce (bayt).
     */
    fun scanBundle(
        compiled: Compiled,
        file: File,
        entrySources: List<ApkContentScanner.EntrySource>,
        entryBudget: Long,
        onBytes: (Long) -> Unit = {}
    ): Outcome {
        if (compiled.signatures.isEmpty() || !file.isFile) {
            return Outcome(
                hits = emptyList(),
                scannedBytes = 0L,
                truncated = false,
                evaluatedPatterns = 0,
                droppedPatterns = 0
            )
        }
        if (compiled.matcher.isEmpty) {
            return Outcome(
                hits = emptyList(),
                scannedBytes = 0L,
                truncated = false,
                evaluatedPatterns = 0,
                droppedPatterns = compiled.matcher.unusablePatternCount
            )
        }

        val warnings = ArrayList<String>()
        val hitsByName = LinkedHashMap<String, Hit>()
        var rawScanned = 0L
        var entriesScanned = 0L
        var truncated = false
        var budget = entryBudget.coerceAtLeast(0L)

        // Kaynak 1: ham dosya; konum kosullari burada tam anlamiyla gecerlidir.
        file.inputStream().buffered().use { stream ->
            val scan = compiled.matcher.scan(
                stream,
                positionFilter = { id, position ->
                    // Kalip kimligi bu tarayicida imza listesinin indeksidir.
                    (id as? Int)?.let { compiled.signatures[it].offset.accepts(position) } ?: false
                },
                maxPositionsPerId = 1,
                onBytesConsumed = { consumed ->
                    rawScanned = consumed
                    onBytes(rawScanned + entriesScanned)
                }
            )
            for (id in scan.matchedIds.mapNotNull { it as? Int }.sorted()) {
                val signature = compiled.signatures[id]
                hitsByName[signature.name] = Hit(signature.name, scan.positions[id]?.firstOrNull(), null)
            }
            rawScanned = scan.bytesScanned
            if (scan.truncated) truncated = true
        }

        // Kaynak 2..n: ZIP girdileri; yalnizca konum-kosulsuz (Any) imzalar uygulanir.
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
                        positionFilter = { id, _ ->
                            (id as? Int)
                                ?.let { compiled.signatures[it].offset is ClamAvSignature.OffsetConstraint.Any }
                                ?: false
                        },
                        maxPositionsPerId = 1,
                        onBytesConsumed = { consumed ->
                            sourceScanned = consumed
                            onBytes(rawScanned + entriesScanned + sourceScanned)
                        }
                    )
                    for (id in scan.matchedIds.mapNotNull { it as? Int }.sorted()) {
                        val signature = compiled.signatures[id]
                        if (signature.name !in hitsByName) {
                            hitsByName[signature.name] = Hit(
                                signature.name,
                                scan.positions[id]?.firstOrNull(),
                                source.name
                            )
                        }
                    }
                    sourceScanned = scan.bytesScanned
                    if (scan.truncated) truncated = true
                }
            } catch (error: Exception) {
                warnings += "ZIP entry '${source.name}' could not be scanned" +
                    " (${error.message ?: error.javaClass.simpleName})."
                sourceScanned = 0L
            }
            entriesScanned += sourceScanned
            budget = (budget - sourceScanned).coerceAtLeast(0L)
        }

        return Outcome(
            hits = hitsByName.values.toList(),
            scannedBytes = rawScanned + entriesScanned,
            truncated = truncated,
            evaluatedPatterns = compiled.matcher.patternCount,
            droppedPatterns = compiled.matcher.unusablePatternCount,
            warnings = warnings
        )
    }
}
