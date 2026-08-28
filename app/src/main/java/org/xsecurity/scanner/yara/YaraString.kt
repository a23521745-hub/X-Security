package org.xsecurity.scanner.yara

class YaraString(
    val id: String,
    val identifier: String,
    val value: ByteArray,
    val mask: ByteArray? = null,
    val isHex: Boolean = false,
    val isPrivate: Boolean = false,
    val isWide: Boolean = false,
    val isAscii: Boolean = false,
    val isFullWord: Boolean = false,
    val nocase: Boolean = false
) {
    fun widen(): ByteArray {
        // Genişletilmiş (wide) karakter dönüşüm mantığı
        if (!isWide) return value
        val widened = ByteArray(value.size * 2)
        for (i in value.indices) {
            widened[i * 2] = value[i]
            widened[i * 2 + 1] = 0
        }
        return widened
    }

    val widenMask: ByteArray?
        get() {
            if (mask == null) return null
            val widened = ByteArray(mask.size * 2)
            for (i in mask.indices) {
                widened[i * 2] = mask[i]
                widened[i * 2 + 1] = 0
            }
            return widened
        }
}
