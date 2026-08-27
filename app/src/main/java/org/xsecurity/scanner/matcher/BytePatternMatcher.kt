package org.xsecurity.scanner.matcher

import java.io.File
import java.io.InputStream

/**
 * Dosyanin TAMAMINI tek geciste tarayan, bellek-sinirli (chunk + carry) kalip eslestirici.
 *
 * Eski YARA tarayicisinda:
 *  - dosyanin yalnizca ilk 8 MB'i okaniyordu (sessiz tespit boslugu),
 *  - tek `InputStream.read()` kisa donebilirdi (veri kaybi),
 *  - 8 MB tampon + `copyOf` kopyasi => ~16 MB anlik bellek.
 *
 * Burada:
 *  - tampon `readFullyInto` ile **dolduruluncaya** kadar okunur,
 *  - en uzun kalip uzunlugu kadar "carry" parca sinirinda tasinir (siniri asan
 *    kalip da bulunur; kalip chunk'tan uzunsa carry birikerek buyur, siniri
 *    `carryOverlap + chunkSize`'dir),
 *  - taranan bayt sayisi ve limit asimi (`truncated`) sonucla birlikte dondurulur.
 */
class BytePatternMatcher(
    patterns: List<BytePattern>,
    private val chunkSize: Int = DEFAULT_CHUNK_SIZE,
    private val maxBytesToScan: Long = DEFAULT_MAX_BYTES_TO_SCAN
) {
    private val literalBuckets: Map<Byte, List<BytePattern>>
    private val foldedBuckets: Map<Byte, List<BytePattern>>
    private val longestPattern: Int

    /** Kullanilabilir (anchor'i olan) kalip sayisi. */
    val patternCount: Int

    /** Anchor bulamadigi icin taranamiyan kalip sayisi (UI'da raporlanir). */
    val unusablePatternCount: Int

    init {
        require(chunkSize > 0) { "chunkSize must be positive" }
        require(maxBytesToScan > 0) { "maxBytesToScan must be positive" }
        val usable = patterns.filter { it.isUsable }
        unusablePatternCount = patterns.size - usable.size
        patternCount = usable.size
        literalBuckets = usable.filter { !it.ignoreCase }.groupBy { it.anchorByte }
        foldedBuckets = usable.filter { it.ignoreCase }.groupBy { it.anchorByte }
        longestPattern = usable.maxOfOrNull { it.length } ?: 0
    }

    val isEmpty: Boolean get() = patternCount == 0

    class Result(
        val matchedIds: Set<Int>,
        val positions: Map<Int, List<Long>>,
        val bytesScanned: Long,
        val truncated: Boolean
    ) {
        val isEmpty: Boolean get() = matchedIds.isEmpty()
    }

    /**
     * @param positionFilter aday eslemenin mutlak dosya ofseti icin ek kosul
     *   (ClamAV `.ndb` `Offset` alani burada uygulanir). `false` => bu pozisyon sayilmaz.
     * @param maxPositionsPerId id basina saklanacak azami pozisyon; varlik-yokluguyla
     *   ilgilenen YARA icin 1 yeterlidir.
     */
    fun scan(
        file: File,
        positionFilter: (id: Int, absoluteStart: Long) -> Boolean = { _, _ -> true },
        maxPositionsPerId: Int = 1,
        onBytesConsumed: (Long) -> Unit = {}
    ): Result {
        if (isEmpty || !file.isFile) return Result(emptySet(), emptyMap(), 0L, truncated = false)
        return file.inputStream().buffered(chunkSize).use { input ->
            scan(input, positionFilter, maxPositionsPerId, onBytesConsumed)
        }
    }

    fun scan(
        input: InputStream,
        positionFilter: (id: Int, absoluteStart: Long) -> Boolean = { _, _ -> true },
        maxPositionsPerId: Int = 1,
        onBytesConsumed: (Long) -> Unit = {}
    ): Result {
        if (isEmpty) return Result(emptySet(), emptyMap(), 0L, truncated = false)

        val matched = linkedSetOf<Int>()
        val positions = HashMap<Int, MutableList<Long>>()
        val carryOverlap = (longestPattern - 1).coerceAtLeast(0)
        val buffer = ByteArray(chunkSize)

        var carry = ByteArray(0)
        var carryStart = 0L
        var totalRead = 0L
        var truncated = false

        while (true) {
            val budget = maxBytesToScan - totalRead
            if (budget <= 0L) {
                truncated = true
                break
            }
            val wanted = if (budget >= chunkSize.toLong()) chunkSize else budget.toInt()
            val read = input.readFullyInto(buffer, wanted)
            if (read <= 0) break
            totalRead += read

            val data = ByteArray(carry.size + read)
            System.arraycopy(carry, 0, data, 0, carry.size)
            System.arraycopy(buffer, 0, data, carry.size, read)
            val dataStart = carryStart

            var i = 0
            while (i < data.size) {
                val rawByte = data[i]
                val literalCandidates = literalBuckets[rawByte]
                if (literalCandidates != null) {
                    for (candidate in literalCandidates) {
                        val start = i - candidate.anchorIndex
                        if (candidate.matchesAt(data, start)) {
                            record(candidate, dataStart + start, matched, positions, positionFilter, maxPositionsPerId)
                        }
                    }
                }
                if (foldedBuckets.isNotEmpty()) {
                    val foldedCandidates = foldedBuckets[ByteFold.lower(rawByte)]
                    if (foldedCandidates != null) {
                        for (candidate in foldedCandidates) {
                            val start = i - candidate.anchorIndex
                            if (candidate.matchesAt(data, start)) {
                                record(candidate, dataStart + start, matched, positions, positionFilter, maxPositionsPerId)
                            }
                        }
                    }
                }
                i++
            }

            val keep = carryOverlap.coerceAtMost(data.size)
            carryStart = dataStart + data.size - keep
            carry = if (keep > 0) data.copyOfRange(data.size - keep, data.size) else ByteArray(0)
            onBytesConsumed(totalRead)
        }

        return Result(matched, positions, totalRead, truncated)
    }

    private fun record(
        pattern: BytePattern,
        absoluteStart: Long,
        matched: MutableSet<Int>,
        positions: HashMap<Int, MutableList<Long>>,
        positionFilter: (id: Int, absoluteStart: Long) -> Boolean,
        maxPositionsPerId: Int
    ) {
        if (!positionFilter(pattern.id, absoluteStart)) return
        matched += pattern.id
        if (maxPositionsPerId <= 0) return
        val list = positions.getOrPut(pattern.id) { ArrayList(4) }
        if (list.size < maxPositionsPerId) list += absoluteStart
    }

    companion object {
        const val DEFAULT_CHUNK_SIZE: Int = 64 * 1024

        /** Asiri buyuk dosyalarda sinirsiz calismayi onlemek icin varsayilan ust sinir. */
        const val DEFAULT_MAX_BYTES_TO_SCAN: Long = 512L * 1024L * 1024L
    }
}

internal object ByteFold {
    fun lower(value: Byte): Byte {
        val i = value.toInt() and 0xFF
        return (if (i in 0x41..0x5A) i + 0x20 else i).toByte()
    }
}

/**
 * [InputStream.read] cagrisisi tamponu doldurmak zorunda degildir; kalip taramasinin
 * dogru calismasi icin istenen bayt sayisini zorunlu kiliyoruz.
 */
internal fun InputStream.readFullyInto(target: ByteArray, length: Int): Int {
    var total = 0
    while (total < length) {
        val n = read(target, total, length - total)
        if (n < 0) break
        total += n
    }
    return total
}
