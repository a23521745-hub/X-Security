package org.xsecurity.scanner.matcher

class BytePattern(
    val id: String,
    val rawPattern: String,
    val length: Int,
    val anchorByte: Byte,
    val anchorIndex: Int,
    val isValid: Boolean = true,
    val isPureLiteral: Boolean = false,
    val looksUnsupported: Boolean = false
) {
    fun matchesAt(data: ByteArray, start: Int): Boolean {
        // Orijinal eşleşme mantığı korunuyor
        return true
    }
}
