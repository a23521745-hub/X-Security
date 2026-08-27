package org.xsecurity.scanner.yara

import org.xsecurity.scanner.matcher.BytePattern

/**
 * YARA kuralindaki tek string tanimi.
 *
 * Desteklenen alt kume:
 *  - `"metin"` stringleri (`ascii`, `wide`, `nocase`),
 *  - `{ hex }` stringleri (nibble jokerleri dahil),
 *  - `/regex/`, `xor(...)`, `base64...`, `fullword` => DESTEKLENMIYOR; parser sayar ve
 *    raporlar (onceki surum bunleri sessizce, hic iz birakmadan atiyordu).
 *
 * YARA semantigi geregi `wide` yalnizca UTF-16LE kalicini, `ascii` yalnizca ham kalicini
 * eslestirir; hic modifier yoksa `ascii` varsayilir.
 */
class YaraString(
    /** `$` isareti olmadan tanimlayici adi, or. `a` (`$a`). */
    val identifier: String,
    val bytes: ByteArray,
    /** Bayt basina bit maskesi; `null` => her bayt literal. */
    val mask: ByteArray? = null,
    /** Metin stringi mi (yoksa hex bloğu mu)? `wide`/`nocase` yalnizca metinde anlamlidir. */
    val isText: Boolean = true,
    val ascii: Boolean = true,
    val wide: Boolean = false,
    val nocase: Boolean = false
) {
    /** Bu string icin taranacak kalip varyantlari (ascii ve/veya wide). */
    fun variants(): List<Variant> {
        if (!isText) return listOf(Variant(bytes, mask))
        val out = ArrayList<Variant>(2)
        if (ascii) out += Variant(bytes, mask)
        if (wide) out += Variant(BytePattern.widen(bytes), BytePattern.widenMask(mask))
        return out
    }

    class Variant(val bytes: ByteArray, val mask: ByteArray?)

    /** `nocase` yalnizca metin stringlerinde anlam tasir. */
    fun ignoreCase(): Boolean = nocase && isText

    fun describe(): String = buildString {
        append('$').append(identifier).append(" [")
        if (!isText) append("hex") else {
            if (ascii) append("ascii")
            if (wide) append(if (ascii) "+wide" else "wide")
            if (nocase) append("+nocase")
        }
        append(']')
    }
}
