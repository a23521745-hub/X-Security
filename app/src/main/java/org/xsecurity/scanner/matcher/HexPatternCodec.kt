package org.xsecurity.scanner.matcher

/**
 * Hex imza metnini (YARA `{ 41 42 ?? }` / ClamAV `.ndb` hex alani) cozumler.
 *
 * Desteklenen sozdizimi:
 *  - iki hex karakteri (`4f`) ya da yarim-bayt joker (`??`, `4?`, `?f`),
 *  - beyaz bosluk yoksayilir.
 *
 * Bilincli olarak **desteklenmeyen** ve [looksUnsupported] ile ayirt edilen
 * sozdizimi (cagrilar tarafindan sayacla raporlanir, sessizce atilmaz):
 *  - degisken uzunluklu `*` jokeri (`41*42`),
 *  - `|n-m|` atlamalari / `(41|42)` alternatifleri (ClamAV),
 *  - `[n-m]` atlamalari ve ic ice `{ }` bolumleri (YARA hex).
 */
object HexPatternCodec {

    class Decoded(
        val bytes: ByteArray,
        val mask: ByteArray?
    ) {
        /** Cozulmus bayt sayisi (mask jokerleri dahil). */
        val length: Int get() = bytes.size
    }

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

    /**
     * Bu hex alani desteklenmeyen bir sozdizimi mi tasiyor? Boylece cagiran taraf
     * "cozulmedi" (bozuk) ile "bilincli olarak desteklenmiyor" (yapilandirilmis
     * sinir) arasindaki ayrimi sayacla raporlayabilir.
     */
    fun looksUnsupported(hex: String): Boolean {
        for (ch in hex) {
            when (ch) {
                '*', '|', '(', ')', '[', ']', '{', '}' -> return true
            }
        }
        return false
    }

    private fun nibble(ch: Char): Int? = when (ch) {
        in '0'..'9' -> ch - '0'
        in 'a'..'f' -> ch - 'a' + 10
        in 'A'..'F' -> ch - 'A' + 10
        '?' -> 0
        else -> null
    }
}
