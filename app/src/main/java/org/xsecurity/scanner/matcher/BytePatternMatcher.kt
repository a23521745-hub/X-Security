package org.xsecurity.scanner.matcher

import java.io.File
import java.io.InputStream

/**
 * Bellek-bagimsiz, akis temelli kalip eslestirici.
 *
 *  - Dosya sabit boyutlu chunk'lar halinde okunur; chunk sinirini asan kaliplar
 *    icin onceki pencerenin son `enUzunKalip - 1` bayti ("carry") tasinir.
 *  - Ilk bayt kovalama (bucketing) ile cogu bayt tek hash aramasiyla elenir.
 *  - [maxBytesToScan] siniri asilirsa sonuc `truncated` olarak isaretlenir;
 *    sessizce eksik tarama yapilmaz.
 */
class BytePatternMatcher(
    val patterns: List<BytePattern>,
    val chunkSize: Int = DEFAULT_CHUNK_SIZE,
    val maxBytesToScan: Long = DEFAULT_MAX_BYTES_TO_SCAN
) {
    companion object {
        const val DEFAULT_CHUNK_SIZE: Int = 128 * 1024
        const val DEFAULT_MAX_BYTES_TO_SCAN: Long = 512L * 1024 * 1024
    }

    val patternCount: Int get() = patterns.size
    val unusablePatternCount: Int
    val usablePatternCount: Int
    val isEmpty: Boolean get() = usablePatternCount == 0
    val isNotEmpty: Boolean get() = !isEmpty

    private class Candidate(
        val pattern: BytePattern,
        val anchorIndex: Int,
        val anchorless: Boolean,
        val effLen: Int
    ) {
        var consumed: Boolean = false
    }

    private val buckets: Array<MutableList<Candidate>?> = arrayOfNulls(256)
    private val anchorlessCandidates = ArrayList<Candidate>()
    private val maxPatternLength: Int

    init {
        var unusable = 0
        var usable = 0
        var maxLength = 0

        for (p in patterns) {
            if (!p.isValid) {
                unusable++
                continue
            }
            usable++
            val len = p.matchLength
            if (len > maxLength) maxLength = len

            val ancIdx = p.anchorIndex
            if (ancIdx < 0) {
                anchorlessCandidates.add(Candidate(p, ancIdx, true, len))
            } else {
                val ancByte = p.anchorByte.toInt() and 0xFF
                val cand = Candidate(p, ancIdx, false, len)

                if (p.ignoreCase && BytePattern.isAsciiLetter(ancByte)) {
                    val lower = BytePattern.lowerAsciiInt(ancByte)
                    val upper = BytePattern.upperAsciiInt(ancByte)
                    addBucket(lower, cand)
                    addBucket(upper, cand)
                } else {
                    addBucket(ancByte, cand)
                }
            }
        }
        unusablePatternCount = unusable
        usablePatternCount = usable
        maxPatternLength = maxLength
    }

    private fun addBucket(key: Int, cand: Candidate) {
        var list = buckets[key]
        if (list == null) {
            list = ArrayList()
            buckets[key] = list
        }
        list.add(cand)
    }

    class Result(
        val matchedIds: Set<Any>,
        val positions: Map<Any, List<Long>>,
        val bytesScanned: Long,
        val truncated: Boolean,
        val patternCount: Int = 0,
        val unusablePatternCount: Int = 0
    ) {
        val hasMatches: Boolean get() = matchedIds.isNotEmpty()
    }

    fun scan(
        file: File,
        maxBytesToScan: Long = this.maxBytesToScan,
        chunkSize: Int = this.chunkSize,
        positionFilter: ((Any, Long) -> Boolean)? = null,
        maxPositionsPerId: Int = 1,
        onBytesConsumed: ((Long) -> Unit)? = null
    ): Result {
        return file.inputStream().buffered().use { stream ->
            scan(stream, maxBytesToScan, chunkSize, positionFilter, maxPositionsPerId, onBytesConsumed)
        }
    }

    fun scan(
        data: ByteArray,
        maxBytesToScan: Long = this.maxBytesToScan,
        chunkSize: Int = this.chunkSize,
        positionFilter: ((Any, Long) -> Boolean)? = null,
        maxPositionsPerId: Int = 1,
        onBytesConsumed: ((Long) -> Unit)? = null
    ): Result {
        return java.io.ByteArrayInputStream(data).use { stream ->
            scan(stream, maxBytesToScan, chunkSize, positionFilter, maxPositionsPerId, onBytesConsumed)
        }
    }

    fun scan(
        stream: InputStream,
        maxBytesToScan: Long = this.maxBytesToScan,
        chunkSize: Int = this.chunkSize,
        positionFilter: ((Any, Long) -> Boolean)? = null,
        maxPositionsPerId: Int = 1,
        onBytesConsumed: ((Long) -> Unit)? = null
    ): Result {
        val matchedIds = mutableSetOf<Any>()
        val positionsMap = mutableMapOf<Any, MutableList<Long>>()

        if (isEmpty) {
            return Result(matchedIds, positionsMap, 0L, false, patternCount, unusablePatternCount)
        }

        // "consumed" durumu tarama-basi bir optimizasyondur: ayni matcher ile yapilan
        // ikinci bir tarama (kullanicinin ayni kurallarla yeni bir dosya taramasi gibi)
        // bayat durumdan etkilenmemeli. Her tarama oncesi sifirlanir.
        resetCandidates()

        val overlap = (maxPatternLength - 1).coerceAtLeast(0)
        val window = ByteArray(overlap + chunkSize)
        var carryLen = 0
        var total = 0L
        var eof = false
        var truncatedByLimit = false

        while (!eof) {
            var chunkLen = 0
            val limit = if (maxBytesToScan > 0) {
                minOf(chunkSize.toLong(), maxBytesToScan - total).toInt()
            } else {
                chunkSize
            }

            if (limit <= 0) {
                truncatedByLimit = true
                break
            }

            while (chunkLen < limit) {
                val r = stream.read(window, carryLen + chunkLen, limit - chunkLen)
                if (r < 0) {
                    eof = true
                    break
                }
                if (r == 0) continue
                chunkLen += r
            }

            if (chunkLen == 0 && carryLen == 0) break

            val windowSize = carryLen + chunkLen
            val dataStart = total - carryLen

            scanWindow(
                window, windowSize, carryLen, dataStart,
                matchedIds, positionsMap, positionFilter, maxPositionsPerId
            )

            total += chunkLen
            onBytesConsumed?.invoke(total)

            val newCarry = minOf(overlap, windowSize)
            if (newCarry > 0 && windowSize >= newCarry) {
                System.arraycopy(window, windowSize - newCarry, window, 0, newCarry)
            }
            carryLen = newCarry

            if (eof) break
        }

        val truncated = truncatedByLimit || (maxBytesToScan > 0 && total >= maxBytesToScan && stream.read() != -1)

        return Result(
            matchedIds = matchedIds,
            positions = positionsMap,
            bytesScanned = total,
            truncated = truncated,
            patternCount = patternCount,
            unusablePatternCount = unusablePatternCount
        )
    }

    private fun resetCandidates() {
        for (list in buckets) {
            list?.forEach { it.consumed = false }
        }
        anchorlessCandidates.forEach { it.consumed = false }
    }

    private fun scanWindow(
        window: ByteArray,
        windowSize: Int,
        carryLen: Int,
        dataStart: Long,
        matchedIds: MutableSet<Any>,
        positionsMap: MutableMap<Any, MutableList<Long>>,
        positionFilter: ((Any, Long) -> Boolean)?,
        maxPositionsPerId: Int
    ) {
        for (i in 0 until windowSize) {
            val b = window[i].toInt() and 0xFF

            val bucket = buckets[b]
            if (bucket != null) {
                for (cand in bucket) {
                    if (cand.consumed) continue
                    evaluateCandidate(cand, i, window, windowSize, carryLen, dataStart, matchedIds, positionsMap, positionFilter, maxPositionsPerId)
                }
            }

            if (anchorlessCandidates.isNotEmpty()) {
                for (cand in anchorlessCandidates) {
                    if (cand.consumed) continue
                    evaluateCandidate(cand, i, window, windowSize, carryLen, dataStart, matchedIds, positionsMap, positionFilter, maxPositionsPerId)
                }
            }
        }
    }

    private fun evaluateCandidate(
        cand: Candidate,
        currentIndex: Int,
        window: ByteArray,
        windowSize: Int,
        carryLen: Int,
        dataStart: Long,
        matchedIds: MutableSet<Any>,
        positionsMap: MutableMap<Any, MutableList<Long>>,
        positionFilter: ((Any, Long) -> Boolean)?,
        maxPositionsPerId: Int
    ) {
        val start = if (cand.anchorless) currentIndex else currentIndex - cand.anchorIndex
        if (start < 0) return
        if (start + cand.effLen > windowSize) return
        if (start + cand.effLen <= carryLen) return

        if (cand.pattern.matchesAt(window, start)) {
            val absolutePos = dataStart + start
            cand.consumed = true

            val shouldRecord = positionFilter == null || positionFilter(cand.pattern.id, absolutePos)
            if (shouldRecord) {
                val id = cand.pattern.id
                matchedIds.add(id)
                val list = positionsMap.getOrPut(id) { ArrayList() }
                if (list.size < maxPositionsPerId) {
                    list.add(absolutePos)
                }
            }
        }
    }
}
