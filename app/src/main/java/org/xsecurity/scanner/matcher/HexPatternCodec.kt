package org.xsecurity.scanner.matcher

object HexPatternCodec {

    class Decoded(
        val bytes: ByteArray,
        val mask: ByteArray?
    )

    fun decode(hex: String): Decoded? {
        val compact = buildString(hex.length) {
            for (ch in hex) {
                if (!ch.isWhitespace()) append(ch)
            }
        }
        if (compact.isEmpty() || compact.length % 2 != 0) return null

        val byteCount = compact.length / 2
        val bytes = ByteArray(byteCount)
        val mask = ByteArray(byteCount)
        var anyWildcard = false
        var index = 0
        while (index < byteCount) {
            val tokenIndex = index * 2
            val hiChar = compact[tokenIndex]
            val loChar = compact[tokenIndex + 1]
            val hi = nibble(hiChar) ?: return null
            val lo = nibble(loChar) ?: return null
            val hiMask = if (hiChar == '?') 0x00 else 0xF0
            val loMask = if (loChar == '?') 0x00 else 0x0F
            val value = ((hi shl 4) or lo) and 0xFF
            val m = hiMask or loMask
            bytes[index] = value.toByte()
            mask[index] = m.toByte()
            if (m != 0xFF) anyWildcard = true
            index++
        }
        return if (anyWildcard) Decoded(bytes, mask) else Decoded(bytes, null)
    }

    private fun nibble(ch: Char): Int? = when (ch) {
        in '0'..'9' -> ch - '0'
        in 'a'..'f' -> ch - 'a' + 10
        in 'A'..'F' -> ch - 'A' + 10
        '?' -> 0
        else -> null
    }
}
