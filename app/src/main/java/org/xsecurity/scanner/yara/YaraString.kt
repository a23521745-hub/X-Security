package org.xsecurity.scanner.yara

/**
 * Tek bir YARA `strings:` bildirimi.
 *
 * Parser (bkz. [YaraRuleParser]) bu sinifi doldurur; tarayici (bkz. [YaraScanner])
 * [variants] listesini [org.xsecurity.scanner.matcher.BytePattern] listesine cevirir.
 *
 * YARA semantigi:
 *  - `ascii` (yoksa ve `wide` da yoksa varsayilan) -> literal baytlar,
 *  - `wide` -> ayni baytlarin UTF-16LE (araya 00 gecirilmis) kopyasi,
 *  - ikisi birden -> iki ayri varyant,
 *  - `nocase` -> eslesme ASCII harf kucultmesiyle yapilir ([ignoreCase]).
 */
class YaraString(
    val identifier: String,
    val bytes: ByteArray,
    val mask: ByteArray? = null,
    val isText: Boolean = false,
    val ascii: Boolean = false,
    val wide: Boolean = false,
    val nocase: Boolean = false
) {
    /** Bayt ciftinin genisletilmis (UTF-16LE benzeri) kopyasi. */
    fun widen(): ByteArray {
        val widened = ByteArray(bytes.size * 2)
        for (i in bytes.indices) {
            widened[i * 2] = bytes[i]
            widened[i * 2 + 1] = 0
        }
        return widened
    }

    /** Maskenin genisletilmis kopyasi: aradaki 00 baytlari kesin (0xFF) eslesir. */
    val widenMask: ByteArray?
        get() {
            if (mask == null) return null
            val widened = ByteArray(mask.size * 2)
            for (i in mask.indices) {
                widened[i * 2] = mask[i]
                widened[i * 2 + 1] = 0xFF.toByte()
            }
            return widened
        }

    class Variant(val bytes: ByteArray, val mask: ByteArray?)

    /**
     * Bu bildirimin taranabilir bayt varyantlari:
     *  - yalnizca `ascii` (veya hicbir sey) -> 1 literal varyant,
     *  - yalnizca `wide` -> 1 genisletilmis varyant,
     *  - `ascii wide` -> 2 varyant.
     */
    fun variants(): List<Variant> {
        val out = ArrayList<Variant>(2)
        if (ascii || !wide) out += Variant(bytes, mask)
        if (wide) out += Variant(widen(), widenMask)
        return out
    }

    /** `nocase` bayragi: tarayici bunu BytePattern'e tasir. */
    fun ignoreCase(): Boolean = nocase
}
