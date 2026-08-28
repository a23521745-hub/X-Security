package org.xsecurity.scanner.matcher

import java.io.InputStream
import kotlin.math.max
import kotlin.math.min

/**
 * Coklu bayt dizisini (Aho-Corasick benzeri anchor + linear match) tek bir akista (stream) arar.
 */
class BytePatternMatcher(
    patterns: List<BytePattern>,
    val bufferCapacity: Int = 128 * 1024
) {
    val totalPatterns: Int = patterns.size

    private val literalCandidatesByAnchor = HashMap<Byte, MutableList<BytePattern>>()
    private val foldedCandidatesByAnchor = HashMap<Byte, MutableList<BytePattern>>()
    private val maxPatternLength: Int

    init {
        var maxLen = 0
        for (p in patterns) {
            maxLen = max(maxLen, p.length)
            val anchorByte = p.anchorByte
            val isLiteral = p.isPureLiteral

            if (isLiteral) {
                literalCandidatesByAnchor.getOrPut(anchorByte) { ArrayList() }.add(p)
            } else {
                foldedCandidatesByAnchor.getOrPut(anchorByte) { ArrayList() }.add(p)
            }
        }
        maxPatternLength = maxLen
    }

    class Result(
        val matchedPatterns: Set<BytePattern>,
        val positions: Map<String, List<Long>>,
        val totalBytesProcessed: Long,
        val isTruncated: Boolean
    )

    fun scan(
        stream: InputStream,
        fileSizeHint: Long = -1L,
        positionFilter: ((BytePattern, Long) -> Boolean)? = null,
        maxPositionsPerId: Int = 1,
        progressCallback: ((Float) -> Unit)? = null
    ): Result {
        val matched = HashSet<BytePattern>()
        val positions = HashMap<String, MutableList<Long>>()

        val overlap = max(0, maxPatternLength - 1)
        val carry = ByteArray(overlap)
        var carryLen = 0
        var totalRead = 0L

        val chunkSize = bufferCapacity
        val buffer = ByteArray(chunkSize)

        while (true) {
            val bytesRead = stream.read(buffer, 0, chunkSize)
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
                            record(candidate, dataStart + start, matched, positions, positionFilter, maxPositionsPerId)
                        }
                    }
                }
                val foldedCandidates = foldedCandidatesByAnchor[b]
                if (foldedCandidates != null) {
                    for (candidate in foldedCandidates) {
                        val start = i - candidate.anchorIndex
                        if (candidate.touchesNewBytes(start, carryLen) && candidate.matchesAt(data, start)) {
                            record(candidate, dataStart + start, matched, positions, positionFilter, maxPositionsPerId)
                        }
                    }
                }
            }

            totalRead += bytesRead
            if (fileSizeHint > 0L && progressCallback != null) {
                val p = min(1.0f, totalRead.toFloat() / fileSizeHint.toFloat())
                progressCallback(p)
            }

            val newCarryLen = min(overlap, windowSize)
            val newCarryStart = windowSize - newCarryLen
            System.arraycopy(data, newCarryStart, carry, 0, newCarryLen)
            carryLen = newCarryLen
        }

        progressCallback?.invoke(1.0f)
        return Result(matched, positions, totalRead, false)
    }

    private fun BytePattern.touchesNewBytes(start: Int, carrySize: Int): Boolean =
        start >= 0 && start + length > carrySize

    private fun record(
        pattern: BytePattern,
        absoluteStart: Long,
        matched: MutableSet<BytePattern>,
        positions: MutableMap<String, MutableList<Long>>,
        positionFilter: ((BytePattern, Long) -> Boolean)?,
        maxPositionsPerId: Int
    ) {
        if (positionFilter != null && !positionFilter(pattern, absoluteStart)) return
        matched.add(pattern)
        val list = positions.getOrPut(pattern.id) { ArrayList() }
        if (list.size < maxPositionsPerId) {
            list.add(absoluteStart)
        }
    }
}
