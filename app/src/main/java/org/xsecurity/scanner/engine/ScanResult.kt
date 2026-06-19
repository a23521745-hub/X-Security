package org.xsecurity.scanner.engine

data class ScanResult(
    val filePath: String,
    val yaraMatches: List<String>,
    val clamAvMatches: List<String>
) {
    val isInfected: Boolean = yaraMatches.isNotEmpty() || clamAvMatches.isNotEmpty()
}
