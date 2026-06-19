package org.xsecurity.scanner.yara

import java.io.File

class YaraMatcher(
    private val maxBytesToRead: Int = 8 * 1024 * 1024
) {
    fun match(apkFile: File, rules: List<YaraRule>): List<String> {
        if (!apkFile.exists() || rules.isEmpty()) return emptyList()

        val bytes = apkFile.inputStream().use { input ->
            val buffer = ByteArray(maxBytesToRead)
            val read = input.read(buffer)
            if (read <= 0) ByteArray(0) else buffer.copyOf(read)
        }
        if (bytes.isEmpty()) return emptyList()

        return rules.asSequence()
            .filter { rule ->
                rule.stringLiterals.all { signature -> containsIndexed(bytes, signature) }
            }
            .map { it.name }
            .toList()
    }

    private fun containsIndexed(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false

        val firstByte = needle[0]
        val lastStart = haystack.size - needle.size
        var start = 0
        while (start <= lastStart) {
            while (start <= lastStart && haystack[start] != firstByte) {
                start++
            }
            if (start > lastStart) return false

            var matched = true
            for (offset in 1 until needle.size) {
                if (haystack[start + offset] != needle[offset]) {
                    matched = false
                    break
                }
            }
            if (matched) return true
            start++
        }
        return false
    }
}
