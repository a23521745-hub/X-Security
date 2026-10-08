package org.xsecurity.scanner.autopilot

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/** Shared system-package guard. Updated-system apps are included in the safelist. */
object SystemPackageSafelist {
    fun isSystemPackage(context: Context, packageName: String): Boolean = try {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getApplicationInfo(packageName, 0)
        }
        isSystemFlags(info.flags)
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (_: RuntimeException) {
        // Metadata lookup failure must fail closed: do not auto-contain a package we cannot classify.
        true
    }

    /** Pure helper for JVM tests; mirrors FLAG_SYSTEM | FLAG_UPDATED_SYSTEM_APP. */
    fun isSystemFlags(flags: Int): Boolean =
        (flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
}
