package org.xsecurity.scanner.matcher

/**
 * YARA hex kalibi (`{ 41 42 ?? 6A }`) ve ClamAV `.ndb` hex imzasi icin ortak cozumleyici.
 *
 * Desteklenenler:
 *  - hex rakamlari (buyuk/kucuk harf duyarsiz),
 *  - `??` (tam joker bayt), `A?` / `?B` (nibble joker).
 *
 * Desteklenmeyen (null dondurur, cagiran sayacla raporlar):
 *  - `*` degisken uzunluklu joker,
 *  - `|min-max|` atlama,
 *  - `(A|B)` alternatifleri,
 *  - `~` hizalama isaretleri.
 *   Bunlar parca sinirlarini asan açgözlü eslestirme gerektirir; yanlis/kayip sonuc
 *  - üretmemek icin bilincli olarak desteklenmiyor.
 */
object HexPatternCodec {

    class Decoded(val bytes: ByteArray, val mask: ByteArray?) {
        val length: Int get() = bytes.size
    }

    /** `null` => gecerli degil. `anyOfThem` bos string de gecersiz sayilir. */
    fun decode(hex: String): Decoded? {
        val tokens = ArrayList<String>()
        val sb = StringBuilder()
        for (ch in hex) {
            when {
                ch.isWhitespace() -> if (sb.isNotEmpty()) { tokens += sb.toString(); sb.setLength(0) }
                else -> sb.append(ch)
            }
        }
        if (sb.isNotEmpty()) tokens += sb.toString()
        if (tokens.isEmpty()) return null

        val bytes = ByteArray(tokens.size)
        val mask = ByteArray(tokens.size)
        var anyWildcard = false
        for (index in tokens.indices) {
            val token = tokens[index]
            if (token.length != 2) return null
            val hi = nibble(token[0]) ?: return null
            val lo = nibble(token[1]) ?: return null
            val hiMask = if (token[0] == '?') 0x00 else 0xF0
            val loMask = if (token[1] == '?') 0x00 else 0x0F
            val value = ((hi shl 4) or lo) and 0xFF
            val m = hiMask or loMask
            bytes[index] = value.toByte()
            mask[index] = m.toByte()
            if (m != 0xFF) anyWildcard = true
        }
        return if (anyWildcard) Decoded(bytes, mask) else Decoded(bytes, null)
    }

    /** Tek hex rakami veya `?`; gecersiz karakterde null. */
    private fun nibble(c: Char): Int? = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        '?' -> 0
        else -> null
    }

    /** Hex tokenlarinda (`A?`, `??`) gorulebilecek joker/hizalama karakterlerini hizli eleme. */
    fun looksUnsupported(raw: String): Boolean = raw.contains('*') ||
        raw.contains('|') ||
        raw.contains('(') ||
        raw.contains('~')
}
