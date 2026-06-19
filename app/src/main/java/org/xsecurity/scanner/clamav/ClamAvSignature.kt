package org.xsecurity.scanner.clamav

data class ClamAvSignature(
    val name: String,
    val pattern: ByteArray
)
