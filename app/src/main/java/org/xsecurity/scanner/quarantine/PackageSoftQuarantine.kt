package org.xsecurity.scanner.quarantine

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import org.xsecurity.scanner.autopilot.SystemPackageSafelist

/** Explicit result: callers must never imply containment succeeded after a failed OEM/rootless action. */
data class SoftQuarantineResult(
    val state: QuarantineState,
    val methodCode: String,
    val failureCode: String? = null
)

/**
 * Rootless, reversible package containment. It attempts an OS disable where allowed,
 * then a best-effort background-process stop. OEM restrictions are surfaced as
 * PENDING/FAILED; this class never uninstalls, deletes, or requests Device Admin.
 */
object PackageSoftQuarantine {
    fun apply(context: Context, packageName: String, recordId: String): SoftQuarantineResult {
        if (packageName.isBlank()) return failed("package_name_missing")
        if (SystemPackageSafelist.isSystemPackage(context, packageName)) return failed("system_package_safelisted")

        val pm = context.packageManager
        try {
            // Normal apps generally cannot disable peer packages; the OEM/system denial is caught below.
            pm.setApplicationEnabledSetting(
                packageName,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                PackageManager.DONT_KILL_APP
            )
            return SoftQuarantineResult(QuarantineState.QUARANTINED, "package_disabled_by_platform")
        } catch (_: SecurityException) {
            // Expected on stock Android for a non-privileged scanner. Continue with reversible fallback.
        } catch (_: IllegalArgumentException) {
            return failed("package_not_installed")
        } catch (_: RuntimeException) {
            // OEM behavior varies; try the process-stop / accessibility path.
        }

        try {
            val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
                ?: return accessibilityOrFail(context, packageName, recordId)
            activityManager.killBackgroundProcesses(packageName)
            return SoftQuarantineResult(QuarantineState.QUARANTINED, "background_process_stop_best_effort")
        } catch (_: SecurityException) {
            return accessibilityOrFail(context, packageName, recordId)
        } catch (_: RuntimeException) {
            return accessibilityOrFail(context, packageName, recordId)
        }
    }

    /** Explicit user-requested restore; never called automatically by the decision loop. */
    fun restore(context: Context, packageName: String): SoftQuarantineResult {
        if (packageName.isBlank()) return failed("package_name_missing")
        if (SystemPackageSafelist.isSystemPackage(context, packageName)) return failed("system_package_safelisted")
        return try {
            context.packageManager.setApplicationEnabledSetting(
                packageName,
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                PackageManager.DONT_KILL_APP
            )
            SoftQuarantineResult(QuarantineState.RESTORED, "platform_enable_state_restored")
        } catch (_: SecurityException) {
            val launch = context.packageManager.getLaunchIntentForPackage(packageName)
                ?: return failed("oem_restore_not_supported")
            try {
                launch.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(launch)
                SoftQuarantineResult(QuarantineState.RESTORED, "user_requested_app_relaunch")
            } catch (_: RuntimeException) {
                failed("oem_restore_not_supported")
            }
        } catch (_: RuntimeException) {
            failed("oem_restore_not_supported")
        }
    }

    private fun accessibilityOrFail(context: Context, packageName: String, recordId: String): SoftQuarantineResult {
        return if (QuarantineAccessibilityService.requestForceStopAssist(context, packageName, recordId)) {
            SoftQuarantineResult(QuarantineState.PENDING, "accessibility_force_stop_assist_pending")
        } else {
            failed("rootless_force_stop_unavailable")
        }
    }

    private fun failed(code: String) = SoftQuarantineResult(QuarantineState.FAILED, "failed", code)
}
