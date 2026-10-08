package org.xsecurity.scanner.privacy

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import org.xsecurity.scanner.autopilot.SystemPackageSafelist

/**
 * PackageManager -> verilmis hassas izinler (ince Android sarmalayici).
 *
 *  - Yeni izin YOK: `GET_PERMISSIONS` ile okuma her uygulamaya aciktir.
 *  - Yalnizca VERILMIS izinlere bakilir (`requestedPermissionsFlags &
 *    REQUESTED_PERMISSION_GRANTED`); bildirilen ama verilmeyen izinler rapora
 *    girmez.
 *  - Kendi paketimiz liste disi (X-Security hassas izin istemez).
 *  - Ag yok, veri cihazdan cikmaz.
 */
object PrivacyScanner {

    data class GrantedApp(
        val packageName: String,
        val label: String,
        val isSystem: Boolean,
        val grantedPermissions: Set<String>
    )

    /**
     * Tum paketleri tarar; hassas grup tasimayanlar elenir. Paket basina bir
     * IPC gerektirir (~yuzlerce paket), bu yuzden IO baglaminda cagrilmalidir.
     */
    fun scan(context: Context): List<GrantedApp> {
        val pm = context.packageManager
        val self = context.packageName
        val packages: List<PackageInfo> = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
        } catch (_: Throwable) {
            return emptyList()
        }
        val out = ArrayList<GrantedApp>()
        for (info in packages) {
            val packageName = info.packageName ?: continue
            if (packageName.isEmpty() || packageName == self) continue
            val granted = queryGranted(pm, packageName)
            if (PrivacyRisk.groupsFor(granted).isEmpty()) continue
            val appInfo = info.applicationInfo ?: continue
            val label = try {
                appInfo.loadLabel(pm).toString()
            } catch (_: Throwable) {
                ""
            }
            out += GrantedApp(
                packageName = packageName,
                label = label,
                // P0: tek ortak kural — sistem VE guncellenmis sistem paketleri ayni
                // "islem yok" muamelesini gorur (bkz. SystemPackageSafelist).
                isSystem = SystemPackageSafelist.isSystemFlags(appInfo.flags),
                grantedPermissions = granted
            )
        }
        return out
    }

    private fun queryGranted(pm: PackageManager, packageName: String): Set<String> {
        val info: PackageInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }
        } catch (_: Throwable) {
            return emptySet()
        }
        val requested = info.requestedPermissions ?: return emptySet()
        val flags = info.requestedPermissionsFlags ?: return emptySet()
        val out = LinkedHashSet<String>()
        for (index in requested.indices) {
            if (index >= flags.size) break
            if ((flags[index] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                out += requested[index]
            }
        }
        return out
    }
}
