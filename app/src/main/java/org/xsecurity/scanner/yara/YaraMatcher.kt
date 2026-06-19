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
                rule.stringLiterals.all { signature -> contains(bytes, signature) }
            }
            .map { it.name }
            .toList()
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false

        val lastStart = haystack.size - needle.size
        for (start in 0..lastStart) {
            var matched = true
            for (offset in needle.indices) {
                if (haystack[start + offset] != needle[offset]) {
                    matched = false
                    break
                }
            }
            if (matched) return true
        }
        return false
    }
}
