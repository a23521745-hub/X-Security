package org.xsecurity.scanner.yara

data class YaraRule(
    val name: String,
    val stringLiterals: List<ByteArray>
)
