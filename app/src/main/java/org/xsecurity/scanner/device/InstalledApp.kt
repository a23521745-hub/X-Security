package org.xsecurity.scanner.device

/**
 * PackageManager'dan okunan tek bir kurulu uygulama (saf model; Android tipi tasimaz,
 * boylece filtreleme mantigi JVM testinde calisir).
 *
 * [flags] `ApplicationInfo.flags` degeridir; sabitler bilerek burada tekrarlanir
 * (android.jar stub'una bagimlilik olmadan test edilebilsin).
 */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val sourceDir: String,
    val splitSourceDirs: List<String> = emptyList(),
    val versionName: String? = null,
    val versionCode: Long = 0L,
    val flags: Int = 0,
    val firstInstallTime: Long = 0L,
    val lastUpdateTime: Long = 0L
) {
    val isSystem: Boolean get() = (flags and FLAG_SYSTEM) != 0
    val isUpdatedSystem: Boolean get() = (flags and FLAG_UPDATED_SYSTEM_APP) != 0

    /** Kullaniciya gosterilecek ad; etiket bossa paket adi. */
    val displayName: String get() = label.ifBlank { packageName }

    /** Taranacak tum APK dosyalari: temel APK + (varsa) split APK'lar. */
    val apkPaths: List<String>
        get() = (listOf(sourceDir) + splitSourceDirs).filter { it.isNotBlank() }.distinct()

    companion object {
        /** `ApplicationInfo.FLAG_SYSTEM` */
        const val FLAG_SYSTEM = 1
        /** `ApplicationInfo.FLAG_UPDATED_SYSTEM_APP` */
        const val FLAG_UPDATED_SYSTEM_APP = 1 shl 7
    }
}
