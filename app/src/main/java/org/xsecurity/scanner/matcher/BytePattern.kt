package org.xsecurity.scanner.matcher

/**
 * Tek bir bayt kalibi.
 *
 * [mask] `null` ise tum baytlar literaldir. Aksi halde bayt basina bit maskesi tasir
 * (ClamAV `A?` / `??` jokerleri icin): `(gözlenen xor beklenen) and mask == 0` ise
 * bayt eslesir; `mask[i] == 0` => o bayt tamamen serbesttir.
 *
 * NOT: Buradaki joker anlami "herhangi TEK bayt"dir. ClamAV `.ndb` formatindaki
 * degisken uzunluklu `*` jokeri bilerek desteklenmez (parser bunu sayacla raporlar);
 * parca sinirlarini asan açgözlü eslestirme anlamica hatali sonuçlar üretirdi.
 */
class BytePattern(
    val id: Int,
    val bytes: ByteArray,
    val mask: ByteArray? = null,
    val ignoreCase: Boolean = false
) {
    val length: Int = bytes.size

    /**
     * Ilk-eleme (anchor) icin kullanilacak bayt indeksi.
     *
     * - Case-sensitive kalipta: maskesi sifir olmayan ilk bayt.
     * - `nocase` kalipta: tam literal (mask == 0xFF) olan ilk bayt. Kismi maskeli
     *   baytlarda kucuk-harfe indirme gecerli olmayacagi icin anchor olarak kullanilamaz;
     *   hic uygun bayt yoksa kalip kullanilamaz isareti alir (anchorIndex = -1).
     */
    val anchorIndex: Int = run {
        var found = -1
        var i = 0
        while (i < length && found < 0) {
            val m = if (mask == null) 0xFF else mask[i].toInt() and 0xFF
            val acceptable = if (ignoreCase) m == 0xFF else m != 0
            if (acceptable) found = i
            i++
        }
        found
    }

    /** Bucket anahtari: anchor baytinin (gerekirse kucuk harfe indirgenmis) degeri. */
    val anchorByte: Byte = if (anchorIndex < 0) {
        0
    } else {
        val raw = bytes[anchorIndex].toInt() and 0xFF
        (if (ignoreCase) lowerAscii(raw) else raw).toByte()
    }

    val isUsable: Boolean get() = length > 0 && anchorIndex >= 0

    fun matchesAt(data: ByteArray, start: Int): Boolean {
        if (start < 0 || start + length > data.size) return false
        val localMask = mask
        var i = 0
        while (i < length) {
            val m = if (localMask == null) 0xFF else localMask[i].toInt() and 0xFF
            if (m != 0) {
                val expected = bytes[i].toInt() and 0xFF
                val actual = data[start + i].toInt() and 0xFF
                if (ignoreCase && m == 0xFF) {
                    if (lowerAscii(expected) != lowerAscii(actual)) return false
                } else if ((expected xor actual) and m != 0) {
                    return false
                }
            }
            i++
        }
        return true
    }

    companion object {
        fun lowerAscii(value: Int): Int = if (value in 0x41..0x5A) value + 0x20 else value

        /** ASCII metni YARA `wide` semantics'e uygun UTF-16LE kaliciga cevirir. */
        fun widen(bytes: ByteArray): ByteArray {
            val out = ByteArray(bytes.size * 2)
            var i = 0
            while (i < bytes.size) {
                out[i * 2] = bytes[i]
                out[i * 2 + 1] = 0
                i++
            }
            return out
        }

        fun widenMask(mask: ByteArray?): ByteArray? {
            if (mask == null) return null
            val out = ByteArray(mask.size * 2)
            var i = 0
            while (i < mask.size) {
                out[i * 2] = mask[i]
                out[i * 2 + 1] = 0xFF.toByte()
                i++
            }
            return out
        }
    }
}
