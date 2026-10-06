package org.xsecurity.scanner.edr

import android.content.Context
import android.os.Build
import android.provider.Settings
import org.xsecurity.scanner.device.ProtectionMode
import org.xsecurity.scanner.device.ProtectionSettings

/**
 * Davranisal EDR'nin dashboard'da gosterilen salt-okunur ozeti.
 *
 *  - [behaviorExpected]: koruma modu ALWAYS mu (izleyici bu modda calisir)?
 *  - [behaviorRunning]: [BehavioralEdrService] su an ayakta mi?
 *  - [detailedWatching]: AppOps aktif-izleme bu cihazda calisiyor mu (API 30+)?
 *  - [accessibilityEnabled]: overlay izleyici sistem ayarlarindan acilmis mi?
 *  - [alertsLast24h]: son 24 saatteki EDR uyarilari ([EdrAlertStore]).
 */
data class EdrStatusSnapshot(
    val behaviorExpected: Boolean,
    val behaviorRunning: Boolean,
    val detailedWatching: Boolean,
    val accessibilityEnabled: Boolean,
    val alertsLast24h: Int
)

object EdrStatus {

    /** AppOps `startWatchingActive` icin gereken minimum API (servisle ayni kapi). */
    fun detailedWatchingSupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    fun snapshot(context: Context): EdrStatusSnapshot {
        val appContext = context.applicationContext
        return EdrStatusSnapshot(
            behaviorExpected = ProtectionSettings.mode(appContext) == ProtectionMode.ALWAYS,
            behaviorRunning = BehavioralEdrService.running,
            detailedWatching = detailedWatchingSupported(),
            accessibilityEnabled = isAccessibilityMonitorEnabled(appContext),
            alertsLast24h = EdrAlertStore.count24h.value
        )
    }

    /** Ince sarmalayici: overlay izleyici sistemde etkin mi? */
    fun isAccessibilityMonitorEnabled(context: Context): Boolean = try {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        )
        isEnabledService(
            enabledServices = enabled,
            packageName = context.packageName,
            serviceClass = AccessibilityBehaviorMonitor::class.java.name
        )
    } catch (_: Throwable) {
        false
    }

    /**
     * Saf: `ENABLED_ACCESSIBILITY_SERVICES` iki-nokta-ayracli duzlestirilmis bilesen
     * listesidir (`paket/Sinif` ya da kisa `paket/.Sinif` bicimi). Hedef servis
     * listede tam eslesiyorsa true.
     */
    fun isEnabledService(enabledServices: String?, packageName: String, serviceClass: String): Boolean {
        if (enabledServices.isNullOrBlank()) return false
        if (packageName.isEmpty() || serviceClass.isEmpty()) return false
        val flat = "$packageName/$serviceClass"
        val short = if (serviceClass.startsWith("$packageName.")) {
            packageName + "/" + serviceClass.substring(packageName.length)
        } else {
            flat
        }
        return enabledServices.split(':').any { entry ->
            val clean = entry.trim()
            clean == flat || clean == short
        }
    }
}
