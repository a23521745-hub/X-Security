package org.xsecurity.scanner.matcher

import java.util.Locale

/**
 * Tek bir byte imzasını, maskesini, alternatiflerini ve tarama meta verilerini temsil eden sınıf.
 */
class BytePattern(
    val id: Any,
    val bytes: ByteArray? = null,
    val mask: ByteArray? = null,
    val ignoreCase: Boolean = false,
    val rawPattern: String = describe(bytes, mask, ignoreCase),
    val length: Int = bytes?.size ?: 0,
    val anchorIndex: Int = findAnchorIndex(bytes, mask),
    val anchorByte: Byte = pickAnchorByte(bytes, anchorIndex),
    val looksUnsupported: Boolean = false,
    val variants: List<ByteArray> = bytes?.let { listOf(it) } ?: emptyList(),
    val isPureLiteral: Boolean = bytes != null && mask == null && !ignoreCase,
    val isValid: Boolean = isStructurallyValid(bytes, mask, looksUnsupported),
    // Eski ayrıştırıcıların (YaraRuleParser vb.) kullandığı ek alanlar
    val value: String? = null,
    val isText: Boolean = false
) {
    val matchLength: Int = computeMatchLength(bytes, variants)
    val idAsString: String get() = id.toString()

    // Eski constructor çağrıları (named arguments desteği için)
    constructor(
        id: Any,
        bytes: ByteArray?,
        mask: ByteArray? = null,
        ignoreCase: Boolean = false,
        isText: Boolean = false,
        value: String? = null,
        looksUnsupported: Boolean = false
    ) : this(
        id = id,
        bytes = bytes,
        mask = mask,
        ignoreCase = ignoreCase,
        rawPattern = describe(bytes, mask, ignoreCase),
        length = bytes?.size ?: 0,
        anchorIndex = findAnchorIndex(bytes, mask),
        anchorByte = pickAnchorByte(bytes, findAnchorIndex(bytes, mask)),
        looksUnsupported = looksUnsupported,
        variants = bytes?.let { listOf(it) } ?: emptyList(),
        isPureLiteral = bytes != null && mask == null && !ignoreCase,
        isValid = isStructurallyValid(bytes, mask, looksUnsupported),
        value = value,
        isText = isText
    )

    fun matchesAt(data: ByteArray, start: Int): Boolean {
        val primary = bytes ?: return false
        if (start < 0 || start + primary.size > data.size) return false
        if (matchesBytesAt(data, start, primary, mask)) return true
        if (variants.size > 1) {
            for (i in 1 until variants.size) {
                val option = variants[i]
                if (start + option.size <= data.size && matchesBytesAt(data, start, option, null)) return true
            }
        }
        return false
    }

    private fun matchesBytesAt(data: ByteArray, start: Int, expected: ByteArray, expectedMask: ByteArray?): Boolean {
        val len = expected.size
        if (expectedMask == null) {
            if (!ignoreCase) {
                for (i in 0 until len) {
                    if (data[start + i] != expected[i]) return false
                }
            } else {
                for (i in 0 until len) {
                    if (toLowerAscii(data[start + i]) != toLowerAscii(expected[i])) return false
                }
            }
            return true
        }

        for (i in 0 until len) {
            val m = if (i < expectedMask.size) expectedMask[i].toInt() and 0xFF else 0xFF
            if (m == 0) continue
            var actual = data[start + i].toInt() and 0xFF
            var want = expected[i].toInt() and 0xFF
            if ((actual and m) != (want and m)) {
                if (!ignoreCase) return false
                actual = lowerAsciiInt(actual)
                want = lowerAsciiInt(want)
                if ((actual and m) != (want and m)) return false
            }
        }
        return true
    }

    override fun equals(other: Any?): kotlin.Boolean {
        if (this === other) return true
        if (other !is BytePattern) return false
        if (id != other.id) return false
        if (ignoreCase != other.ignoreCase) return false
        if (looksUnsupported != other.looksUnsupported) return false
        if (bytes != null && other.bytes != null) {
            if (!bytes.contentEquals(other.bytes)) return false
        } else if (bytes != other.bytes) return false
        if (mask != null && other.mask != null) {
            if (!mask.contentEquals(other.mask)) return false
        } else if (mask != other.mask) return false
        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + (bytes?.contentHashCode() ?: 0)
        result = 31 * result + (mask?.contentHashCode() ?: 0)
        result = 31 * result + ignoreCase.hashCode()
        result = 31 * result + looksUnsupported.hashCode()
        return result
    }

    override fun toString(): String {
        return "BytePattern(id=" + id + ", length=" + length + ", raw=" + rawPattern + ")"
    }

    companion object {
        fun widen(narrow: ByteArray): ByteArray {
            val out = ByteArray(narrow.size * 2)
            for (i in narrow.indices) {
                out[i * 2] = narrow[i]
                out[i * 2 + 1] = 0
            }
            return out
        }

        fun widen(text: String): ByteArray = widen(text.toByteArray(Charsets.US_ASCII))

        fun ascii(id: Any, text: String, ignoreCase: Boolean = false, wide: Boolean = false): BytePattern {
            val base = text.toByteArray(Charsets.US_ASCII)
            return BytePattern(id = id, bytes = if (wide) widen(base) else base, ignoreCase = ignoreCase, isText = true, value = text)
        }

        internal fun toLowerAscii(b: Byte): Byte {
            val v = b.toInt() and 0xFF
            return if (v in 65..90) (v + 32).toByte() else b
        }

        internal fun lowerAsciiInt(v: Int): Int = if (v in 65..90) v + 32 else v
        internal fun upperAsciiInt(v: Int): Int = if (v in 97..122) v - 32 else v
        internal fun isAsciiLetter(v: Int): Boolean = v in 65..90 || v in 97..122

        private fun findAnchorIndex(bytes: ByteArray?, mask: ByteArray?): Int {
            if (bytes == null) return -1
            for (i in bytes.indices) {
                val m = if (mask != null && i < mask.size) mask[i].toInt() and 0xFF else 0xFF
                if (m == 0xFF) return i
            }
            return -1
        }

        private fun pickAnchorByte(bytes: ByteArray?, anchorIndex: Int): Byte {
            if (bytes == null || anchorIndex < 0 || anchorIndex >= bytes.size) return 0
            return bytes[anchorIndex]
        }

        private fun isStructurallyValid(bytes: ByteArray?, mask: ByteArray?, looksUnsupported: Boolean): Boolean {
            if (looksUnsupported) return false
            if (bytes == null || bytes.isEmpty()) return false
            if (mask != null) {
                var anyFixed = false
                for (i in bytes.indices) {
                    val m = if (i < mask.size) mask[i].toInt() and 0xFF else 0xFF
                    if (m != 0) {
                        anyFixed = true
                        break
                    }
                }
                if (!anyFixed) return false
            }
            return true
        }

        private fun computeMatchLength(bytes: ByteArray?, variants: List<ByteArray>): Int {
            var max = bytes?.size ?: 0
            for (v in variants) if (v.size > max) max = v.size
            return max
        }

        private fun describe(bytes: ByteArray?, mask: ByteArray?, ignoreCase: Boolean): String {
            if (bytes == null) return "<unsupported>"
            if (mask == null && bytes.isNotEmpty()) {
                var printable = true
                for (b in bytes) {
                    val v = b.toInt() and 0xFF
                    if (v < 0x20 || v > 0x7E || v == 34) {
                        printable = false
                        break
                    }
                }
                if (printable) {
                    val sb = StringBuilder()
                    sb.append('"')
                    for (b in bytes) sb.append((b.toInt() and 0xFF).toChar())
                    sb.append('"')
                    if (ignoreCase) sb.append(" nocase")
                    return sb.toString()
                }
            }
            val sb = StringBuilder()
            for (i in bytes.indices) {
                if (i > 0) sb.append(' ')
                val m = if (mask != null && i < mask.size) mask[i].toInt() and 0xFF else 0xFF
                if (m == 0) sb.append("??") else sb.append(String.format(Locale.US, "%02X", bytes[i].toInt() and 0xFF))
            }
            if (ignoreCase) sb.append(" (nocase)")
            return sb.toString()
        }
    }
}
