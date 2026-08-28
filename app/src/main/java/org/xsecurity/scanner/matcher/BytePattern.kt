package org.xsecurity.scanner.matcher

class BytePattern(
    val id: String,
    val rawPattern: String,
    val length: Int,
    val anchorByte: Byte,
    val anchorIndex: Int,
    val bytes: ByteArray? = null,
    val mask: ByteArray? = null,
    val ignoreCase: Boolean = false,
    val isValid: Boolean = true,
    val isPureLiteral: Boolean = false,
    val looksUnsupported: Boolean = false
) {
    fun matchesAt(data: ByteArray, start: Int): Boolean {
        if (start < 0 || start + length > data.size) return false
        val patBytes = bytes ?: return false
        val patMask = mask
        
        for (i in 0 until length) {
            val b = data[start + i]
            val expected = patBytes[i]
            val m = patMask?.get(i) ?: 0xFF.toByte()
            
            if (m.toInt() != 0) {
                if ((b.toInt() and m.toInt()) != (expected.toInt() and m.toInt())) {
                    if (ignoreCase) {
                        val cb = toLower(b)
                        val cExpected = toLower(expected)
                        if ((cb.toInt() and m.toInt()) != (cExpected.toInt() and m.toInt())) {
                            return false
                        }
                    } else {
                        return false
                    }
                }
            }
        }
        return true
    }

    private fun toLower(b: Byte): Byte {
        val v = b.toInt() and 0xFF
        return if (v in 65..90) (v + 32).toByte() else b
    }
}
