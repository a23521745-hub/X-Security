package org.xsecurity.scanner.autopilot

import android.content.Context
import android.os.PowerManager
import android.provider.Settings
import org.xsecurity.scanner.quarantine.PackageSoftQuarantine
import org.xsecurity.scanner.quarantine.QuarantineAccessibilityService
import org.xsecurity.scanner.quarantine.SoftQuarantineResult

/** Capabilities are queried at use time because special-access grants can change in Settings. */
enum class Capability { SOFT_QUARANTINE, OVERLAY_WARNING, USAGE_STATS, ACCESSIBILITY_ASSIST, BATTERY_EXEMPTION, ROOT }

interface CapabilityProvider {
    fun hasCapability(context: Context, capability: Capability): Boolean

    /** Reversible/rootless best-effort containment only. This API has no delete operation. */
    fun quarantine(context: Context, packageName: String, recordId: String): SoftQuarantineResult
}

/** Normal Android application implementation: no root, Device Admin, or silent uninstall. */
class RootlessCapabilityProvider : CapabilityProvider {
    override fun hasCapability(context: Context, capability: Capability): Boolean = when (capability) {
        Capability.SOFT_QUARANTINE -> true
        Capability.OVERLAY_WARNING -> runCatching {
            android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.M || Settings.canDrawOverlays(context)
        }.getOrDefault(false)
        Capability.USAGE_STATS -> ForegroundAppObserver.hasUsageAccess(context)
        Capability.ACCESSIBILITY_ASSIST -> QuarantineAccessibilityService.isEnabled(context)
        Capability.BATTERY_EXEMPTION -> runCatching {
            val power = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            power?.isIgnoringBatteryOptimizations(context.packageName) == true
        }.getOrDefault(false)
        Capability.ROOT -> false
    }

    override fun quarantine(context: Context, packageName: String, recordId: String): SoftQuarantineResult =
        PackageSoftQuarantine.apply(context.applicationContext, packageName, recordId)
}
