package org.xsecurity.scanner.device

/**
 * Kurulu uygulama taramasinin **saf** karar mantigi (Android API'si yok; JVM testi var).
 *
 *  - Hangi paketler taranir? Kendi paketimiz asla; sistem uygulamalari yalnizca
 *    kullanici acikca isterse (varsayilan: yalnizca kullanici uygulamalari +
 *    guncellenmis sistem uygulamalari — stalkerware pratikte hep kullanici
 *    tarafinda ya da "guncellenmis sistem" kiliginda gelir).
 *  - APK yolu okunabilir mi? `/data/app/...` ve `/system/...` altinda olmayan yollar
 *    (ornegin bos `sourceDir`) atlanir; hata yerine atlama kaydi dusulur.
 *  - Siralama: kullanici uygulamalari once, sonra son guncellenen en ustte; boylece
 *    tarama iptal edilse bile en supheli adaylar once gecmis olur.
 */
object InstalledAppPolicy {

    data class Options(
        val includeSystemApps: Boolean = false,
        val selfPackage: String
    )

    /** Taranacak uygulamalarin siralanmis listesi. */
    fun selectTargets(apps: List<InstalledApp>, options: Options): List<InstalledApp> =
        apps.asSequence()
            .filter { shouldScan(it, options) }
            .distinctBy { it.packageName }
            .sortedWith(
                compareBy<InstalledApp> { it.isSystem && !it.isUpdatedSystem }
                    .thenByDescending { it.lastUpdateTime }
                    .thenBy { it.packageName }
            )
            .toList()

    fun shouldScan(app: InstalledApp, options: Options): Boolean {
        if (app.packageName.isBlank()) return false
        if (app.packageName == options.selfPackage) return false
        if (!hasScannablePath(app)) return false
        if (app.isSystem && !app.isUpdatedSystem && !options.includeSystemApps) return false
        return true
    }

    /** `sourceDir` bos ya da bariz gecersizse tarama denemesi bile yapilmaz. */
    fun hasScannablePath(app: InstalledApp): Boolean {
        val path = app.sourceDir
        if (path.isBlank()) return false
        if (!path.startsWith("/")) return false
        return path.endsWith(".apk", ignoreCase = true) || path.contains("/app/") || path.contains("/priv-app/")
    }
}
