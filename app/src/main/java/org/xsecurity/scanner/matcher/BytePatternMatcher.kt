package org.xsecurity.scanner.matcher

import java.io.InputStream
import kotlin.math.max
import kotlin.math.min

class BytePatternMatcher(
    val patterns: List<BytePattern>
) {
    companion object {
        const val DEFAULT_CHUNK_SIZE = 128 * 1024
        const val DEFAULT_MAX_BYTES_TO_SCAN = 100 * 1024 * 1024L
    }

    val patternCount: Int = patterns.size
    val unusablePatternCount: Int = patterns.count { !it.isValid }

    private val literalCandidatesByAnchor = HashMap<Byte, MutableList<BytePattern>>()
    private val foldedCandidatesByAnchor = HashMap<Byte, MutableList<BytePattern>>()
    private val maxPatternLength: Int

    init {
        var maxLen = 0
        for (p in patterns) {
            if (!p.isValid) continue
            maxLen = max(maxLen, p.length)
            val anchorByte = p.anchorByte
            if (p.isPureLiteral) {
                literalCandidatesByAnchor.getOrPut(anchorByte) { ArrayList() }.add(p)
            } else {
                foldedCandidatesByAnchor.getOrPut(anchorByte) { ArrayList() }.add(p)
            }
        }
        maxPatternLength = maxLen
    }

    class Result(
        val matchedIds: Set<String>,
        val positions: Map<String, List<Long>>,
        val bytesScanned: Long,
        val truncated: Boolean,
        val patternCount: Int,
        val unusablePatternCount: Int
    )

    fun scan(
        stream: InputStream,
        maxBytesToScan: Long = DEFAULT_MAX_BYTES_TO_SCAN,
        chunkSize: Int = DEFAULT_CHUNK_SIZE,
        positionFilter: ((BytePattern, Long) -> Boolean)? = null,
        maxPositionsPerId: Int = 1,
        onBytesConsumed: ((Long) -> Unit)? = null
    ): Result {
        val matchedIds = HashSet<String>()
        val positions = HashMap<String, MutableList<Long>>()

        val overlap = max(0, maxPatternLength - 1)
        val carry = ByteArray(overlap)
        var carryLen = 0
        var totalRead = 0L
        var truncated = false

        val buffer = ByteArray(chunkSize)

        while (true) {
            val bytesToRead = if (maxBytesToScan > 0) {
                min(buffer.size.toLong(), maxBytesToScan - totalRead).toInt()
            } else {
                buffer.size
            }

            if (bytesToRead <= 0) {
                if (maxBytesToScan > 0 && totalRead >= maxBytesToScan) {
                    truncated = true
                }
                break
            }

            val bytesRead = stream.read(buffer, 0, bytesToRead)
            if (bytesRead <= 0) break

            val windowSize = carryLen + bytesRead
            val data = ByteArray(windowSize)
            System.arraycopy(carry, 0, data, 0, carryLen)
            System.arraycopy(buffer, 0, data, carryLen, bytesRead)

            val dataStart = totalRead - carryLen

            for (i in 0 until windowSize) {
                val b = data[i]
                val literalCandidates = literalCandidatesByAnchor[b]
                if (literalCandidates != null) {
                    for (candidate in literalCandidates) {
                        val start = i - candidate.anchorIndex
                        if (candidate.touchesNewBytes(start, carryLen) && candidate.matchesAt(data, start)) {
                            record(candidate, dataStart + start, matchedIds, positions, positionFilter, maxPositionsPerId)
                        }
                    }
                }
                val foldedCandidates = foldedCandidatesByAnchor[b]
                if (foldedCandidates != null) {
                    for (candidate in foldedCandidates) {
                        val start = i - candidate.anchorIndex
                        if (candidate.touchesNewBytes(start, carryLen) && candidate.matchesAt(data, start)) {
                            record(candidate, dataStart + start, matchedIds, positions, positionFilter, maxPositionsPerId)
                        }
                    }
                }
            }

            totalRead += bytesRead
            onBytesConsumed?.invoke(totalRead)

            val newCarryLen = min(overlap, windowSize)
            val newCarryStart = windowSize - newCarryLen
            System.arraycopy(data, newCarryStart, carry, 0, newCarryLen)
            carryLen = newCarryLen
        }

        return Result(matchedIds, positions, totalRead, truncated, patternCount, unusablePatternCount)
    }

    private fun BytePattern.touchesNewBytes(start: Int, carrySize: Int): Boolean =
        start >= 0 && start + length > carrySize

    private fun record(
        pattern: BytePattern,
        absoluteStart: Long,
        matchedIds: MutableSet<String>,
        positions: MutableMap<String, MutableList<Long>>,
        positionFilter: ((BytePattern, Long) -> Boolean)?,
        maxPositionsPerId: Int
    ) {
        if (positionFilter != null && !positionFilter(pattern, absoluteStart)) return
        matchedIds.add(pattern.id)
        val list = positions.getOrPut(pattern.id) { ArrayList() }
        if (list.size < maxPositionsPerId) {
            list.add(absoluteStart)
        }
    }
}
