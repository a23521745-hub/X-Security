package org.xsecurity.scanner.device

import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch

/**
 * Tek bir kurulu uygulamanin tarama sonucu (UI + kalicilama modeli).
 *
 * [bytesScanned]/[durationMillis] (temel + split APK sonuclarinin toplami) tarama
 * gecmisi ve onbellek kayitlarina gercek veri tasir.
 */
data class AppScanEntry(
    val packageName: String,
    val label: String,
    val status: ScanStatus,
    val threats: List<ThreatMatch> = emptyList(),
    val sha256: String? = null,
    val errorMessage: String? = null,
    val versionName: String? = null,
    val bytesScanned: Long = 0L,
    val durationMillis: Long = 0L
) {
    val isInfected: Boolean get() = threats.isNotEmpty()
    val isFailed: Boolean get() = status == ScanStatus.FAILED
}

/**
 * Cihaz taramasinin **saf** ozet/birlestirme mantigi.
 *
 * Birden fazla APK (temel + split) tek uygulamaya aittir; sonuclar tek girdide
 * birlesir. Tum girdiler de mevcut [ScanStore]/gecmis kartinin anladigi tek bir
 * [ScanResult]'a indirgenir — boylece "Son tarama" karti cihaz taramasini da gosterir.
 */
object DeviceScanSummary {

    /** Ayni uygulamanin birden fazla APK sonucunu tek girdiye indirger. */
    fun mergeEntry(app: InstalledApp, results: List<ScanResult>): AppScanEntry {
        val threats = LinkedHashMap<String, ThreatMatch>()
        results.flatMap { it.threats }.forEach { threats.putIfAbsent("${it.engine}:${it.name}", it) }
        val failed = results.filter { !it.isComplete }
        val status = when {
            threats.isNotEmpty() -> ScanStatus.THREATS_FOUND
            results.isEmpty() || failed.size == results.size -> ScanStatus.FAILED
            else -> ScanStatus.CLEAN
        }
        return AppScanEntry(
            packageName = app.packageName,
            label = app.displayName,
            status = status,
            threats = threats.values.toList(),
            sha256 = results.firstOrNull()?.sha256,
            errorMessage = failed.firstNotNullOfOrNull { it.errorMessage },
            versionName = app.versionName,
            bytesScanned = results.sumOf { it.bytesScanned },
            durationMillis = results.sumOf { it.durationMillis }
        )
    }

    /**
     * Tum uygulama sonuclarini gecmis kartinin anladigi tek [ScanResult]'a cevirir.
     * Tehdit adi `Etiket (paket): imza` bicimindedir ki liste tek basina anlasilsin.
     */
    fun toScanResult(entries: List<AppScanEntry>, durationMillis: Long, displayName: String): ScanResult {
        val threats = entries.filter { it.isInfected }.flatMap { entry ->
            entry.threats.map { threat ->
                threat.copy(
                    name = "${entry.label}: ${threat.name}",
                    detail = listOfNotNull(entry.packageName, threat.detail).joinToString(" · ")
                )
            }
        }
        val failed = entries.count { it.isFailed }
        val warnings = if (failed > 0) listOf("$failed app(s) could not be scanned") else emptyList()
        val status = when {
            threats.isNotEmpty() -> ScanStatus.THREATS_FOUND
            entries.isNotEmpty() && failed == entries.size -> ScanStatus.FAILED
            else -> ScanStatus.CLEAN
        }
        return ScanResult(
            status = status,
            filePath = "device://installed-apps",
            fileName = displayName,
            fileSize = 0L,
            sha256 = null,
            threats = threats,
            bytesScanned = 0L,
            durationMillis = durationMillis,
            engineWarnings = warnings,
            errorMessage = if (status == ScanStatus.FAILED) "No installed app could be scanned" else null
        )
    }

    fun infectedCount(entries: List<AppScanEntry>): Int = entries.count { it.isInfected }
    fun failedCount(entries: List<AppScanEntry>): Int = entries.count { it.isFailed }
    fun cleanCount(entries: List<AppScanEntry>): Int = entries.count { it.status == ScanStatus.CLEAN }
}
