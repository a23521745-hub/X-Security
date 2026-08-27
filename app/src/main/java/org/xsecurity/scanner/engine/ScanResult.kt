package org.xsecurity.scanner.engine

/** Tek bir tespit kaydi (YARA kurali veya ClamAV imzasi). */
data class ThreatMatch(
    val engine: String,
    val name: String,
    val detail: String? = null,
    val position: Long? = null
)

enum class ScanStatus {
    /** Tarama tamamlandi, hicbir imza eslesmedi. */
    CLEAN,

    /** En az bir imza/kural eslesti. */
    THREATS_FOUND,

    /** Dosya okunamadi veya tarama tamamlanamadi. */
    FAILED;

    val isComplete: Boolean get() = this == CLEAN || this == THREATS_FOUND
}

/**
 * Tarama sonucu.
 *
 * Onceki surumde `isInfected` tek basina her seyi ifade ediyordu ve motor hic kural
 * yukleyememisken `false` donuyordu ("temiz"). Artik sonuc `status` ve motor uyarilari
 * (engineWarnings) ile birlikte tasinir; arayüz yalnizca `isComplete` ise "temiz" der.
 */
data class ScanResult(
    val status: ScanStatus,
    val filePath: String,
    val fileName: String,
    val fileSize: Long,
    val sha256: String? = null,
    val threats: List<ThreatMatch> = emptyList(),
    val bytesScanned: Long = 0L,
    val durationMillis: Long = 0L,
    val engineWarnings: List<String> = emptyList(),
    val errorMessage: String? = null
) {
    val isInfected: Boolean get() = threats.isNotEmpty()
    val isComplete: Boolean get() = status.isComplete && errorMessage == null
    val yaraThreats: List<ThreatMatch> get() = threats.filter { it.engine == ENGINE_YARA }
    val clamAvThreats: List<ThreatMatch> get() = threats.filter { it.engine == ENGINE_CLAMAV }

    companion object {
        const val ENGINE_YARA = "YARA"
        const val ENGINE_CLAMAV = "ClamAV"

        fun failed(filePath: String, message: String, warnings: List<String> = emptyList()): ScanResult =
            ScanResult(
                status = ScanStatus.FAILED,
                filePath = filePath,
                fileName = filePath.substringAfterLast('/'),
                fileSize = 0L,
                engineWarnings = warnings,
                errorMessage = message
            )
    }
}
