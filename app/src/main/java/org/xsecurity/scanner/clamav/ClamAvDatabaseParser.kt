package org.xsecurity.scanner.clamav

import java.io.File

class ClamAvDatabaseParser {
    fun parse(ndbFile: File): List<ClamAvSignature> {
        if (!ndbFile.exists()) return emptyList()

        return ndbFile.useLines { lines ->
            lines.mapNotNull { line -> parseLine(line.trim()) }.toList()
        }
    }

    private fun parseLine(line: String): ClamAvSignature? {
        if (line.isBlank() || line.startsWith("#")) return null

        val parts = line.split(':')
        if (parts.size < 4) return null

        val name = parts[0].trim()
        val hexSignature = parts[3].trim()
        if (name.isEmpty() || hexSignature.length % 2 != 0 || hexSignature.contains('*')) return null

        val bytes = hexToBytes(hexSignature) ?: return null
        return ClamAvSignature(name = name, pattern = bytes)
    }

    private fun hexToBytes(hex: String): ByteArray? {
        val out = ByteArray(hex.length / 2)
        var idx = 0
        while (idx < hex.length) {
            val hi = hexCharToInt(hex[idx])
            val lo = hexCharToInt(hex[idx + 1])
            if (hi < 0 || lo < 0) return null
            out[idx / 2] = ((hi shl 4) or lo).toByte()
            idx += 2
        }
        return out
    }

    private fun hexCharToInt(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
}
