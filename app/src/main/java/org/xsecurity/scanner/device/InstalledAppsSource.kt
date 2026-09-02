package org.xsecurity.scanner.device

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * PackageManager -> [InstalledApp] donusumu (ince Android sarmalayici; mantik yok).
 *
 * `QUERY_ALL_PACKAGES` izni manifestte bildirilmistir: guvenlik tarayicisinin
 * gorevi cihazdaki **tum** paketleri gorebilmektir; `<queries>` filtresi bilinmeyen
 * stalkerware paketlerini gizlerdi.
 */
object InstalledAppsSource {

    fun load(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val packages: List<PackageInfo> = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
        } catch (_: Throwable) {
            emptyList()
        }
        return packages.mapNotNull { info -> toInstalledApp(pm, info) }
    }

    /** Tek paketin bilgisi (kurulum ani kalkani icin); paket yoksa null. */
    fun loadOne(context: Context, packageName: String): InstalledApp? {
        val pm = context.packageManager
        val info: PackageInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
        } catch (_: Throwable) {
            return null
        }
        return toInstalledApp(pm, info)
    }

    private fun toInstalledApp(pm: PackageManager, info: PackageInfo): InstalledApp? {
        val appInfo = info.applicationInfo ?: return null
        val label = try {
            appInfo.loadLabel(pm).toString()
        } catch (_: Throwable) {
            ""
        }
        val versionCode: Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }
        return InstalledApp(
            packageName = info.packageName.orEmpty(),
            label = label,
            sourceDir = appInfo.sourceDir.orEmpty(),
            splitSourceDirs = appInfo.splitSourceDirs?.toList().orEmpty(),
            versionName = info.versionName,
            versionCode = versionCode,
            flags = appInfo.flags,
            firstInstallTime = info.firstInstallTime,
            lastUpdateTime = info.lastUpdateTime
        )
    }
}
