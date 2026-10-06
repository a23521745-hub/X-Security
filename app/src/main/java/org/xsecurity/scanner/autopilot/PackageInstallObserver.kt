package org.xsecurity.scanner.autopilot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

/** Receives package install/update events and queues a scan/policy evaluation. */
class PackageInstallObserver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return
        val packageName = intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
        if (packageName == context.packageName || !AutopilotSettings.isEnabled(context)) return
        val system = SystemPackageSafelist.isSystemPackage(context, packageName)
        val installer = installerOf(context, packageName)
        AutopilotRuntime.enqueue(
            context,
            SecurityEvent.PackageInstalled(
                packageName = packageName,
                isSystemPackage = system,
                installerPackageName = installer
            )
        )
    }

    private fun installerOf(context: Context, packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(packageName)
        }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: RuntimeException) {
        null
    }
}

/** Boot sensor; periodic scheduling remains owned by the existing WorkManager controllers. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        AutopilotScheduler.schedule(context)
        AutopilotRuntime.enqueue(context, SecurityEvent.Boot())
    }
}
