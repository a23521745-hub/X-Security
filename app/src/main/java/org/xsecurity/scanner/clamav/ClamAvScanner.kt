package org.xsecurity.scanner.clamav

import java.io.File

class ClamAvScanner(
    private val chunkSize: Int = DEFAULT_CHUNK_SIZE
) {
    fun scan(apkFile: File, signatures: List<ClamAvSignature>): List<String> {
        if (!apkFile.exists() || signatures.isEmpty()) return emptyList()

        val byFirstByte = signatures
            .filter { it.pattern.isNotEmpty() }
            .groupBy { it.pattern[0] }

        if (byFirstByte.isEmpty()) return emptyList()

        val maxPattern = signatures.maxOf { it.pattern.size }
        val matches = linkedSetOf<String>()

        apkFile.inputStream().buffered(chunkSize).use { input ->
            var carry = ByteArray(0)
            val chunk = ByteArray(chunkSize)

            while (true) {
                val read = input.read(chunk)
                if (read <= 0) break

                val data = ByteArray(carry.size + read)
                System.arraycopy(carry, 0, data, 0, carry.size)
                System.arraycopy(chunk, 0, data, carry.size, read)

                var i = 0
                while (i < data.size) {
                    val candidates = byFirstByte[data[i]] ?: emptyList()
                    for (candidate in candidates) {
                        if (i + candidate.pattern.size > data.size) continue
                        if (matchesPatternAt(data, i, candidate.pattern)) {
                            matches += candidate.name
                        }
                    }
                    i++
                }

                val boundaryCarryLength = (maxPattern - 1).coerceAtMost(data.size)
                carry = if (boundaryCarryLength > 0) {
                    data.copyOfRange(data.size - boundaryCarryLength, data.size)
                } else {
                    ByteArray(0)
                }
            }
        }

        return matches.toList()
    }

    private fun matchesPatternAt(data: ByteArray, start: Int, pattern: ByteArray): Boolean {
        for (offset in pattern.indices) {
            if (data[start + offset] != pattern[offset]) return false
        }
        return true
    }

    companion object {
        private const val DEFAULT_CHUNK_SIZE: Int = 32 * 1024
    }
}
