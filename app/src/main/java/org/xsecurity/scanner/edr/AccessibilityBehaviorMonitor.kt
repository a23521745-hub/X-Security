package org.xsecurity.scanner.edr

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.util.Log
import android.view.accessibility.AccessibilityEvent

/**
 * Erişilebilirlik tabanlı davranış izleyici: pencere değişimlerini dinleyip
 * olası overlay (tap-jacking) / yetkisiz arayüz kazıma girişimlerini loglar.
 *
 *  - Yalnızca `TYPE_WINDOW_STATE_CHANGED` dinlenir (pil dostu, olay-güdümlü).
 *  - Pencere içeriği okunmaz (`canRetrieveWindowContent=false`); karar sadece
 *    paket + sınıf adıyla verilir — ekran verisi cihazdışı dahil hiçbir yere
 *    yazılmaz, depolanmaz.
 *  - Sezgisel ([OverlayPolicy]): hassas bir paket (kurulum, izin denetleyici,
 *    ayarlar, X-Security kendisi) ön plana geldikten kısa süre sonra **farklı**
 *    bir üçüncü parti pakete ait diyalog/popup/overlay benzeri pencere
 *    belirirse `Log.w("XSecurityEDR", ...)` ile işaretlenir.
 *
 * Not: Android zorunluluğu olarak bu servis kullanıcı sistem ayarlarından
 * (Erişilebilirlik) elle açmadan çalışmaz; uygulama içinden açılamaz. Manifest
 * kaydı + `@xml/edr_accessibility_config` yapılandırması gerekir.
 */
class AccessibilityBehaviorMonitor : AccessibilityService() {

    @Volatile
    private var lastSensitivePackage: String? = null

    @Volatile
    private var lastSensitiveAt: Long = 0L

    override fun onServiceConnected() {
        // XML yapılandırması birincildir; burada programatik olarak da garanti
        // altına alınır (yalnızca pencere-durumu olayları).
        val info = serviceInfo ?: AccessibilityServiceInfo()
        info.eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
        serviceInfo = info
        Log.i(EdrTriggerPolicy.TAG, "Accessibility behavior monitor connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || event.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        // Yerel ad `Context.packageName`'i gölgelemesin diye event paketi ayrı adlandırılır.
        val eventPackage = event.packageName?.toString()?.takeIf { it.isNotEmpty() } ?: return
        val className = event.className?.toString()
        val now = System.currentTimeMillis()
        val ownPackage = this@AccessibilityBehaviorMonitor.packageName

        if (OverlayPolicy.isSensitivePackage(eventPackage, ownPackage)) {
            lastSensitivePackage = eventPackage
            lastSensitiveAt = now
            Log.i(EdrTriggerPolicy.TAG, "Sensitive foreground: $eventPackage/${className ?: "?"}")
            return
        }
        if (
            OverlayPolicy.shouldFlag(
                eventPackage = eventPackage,
                eventClass = className,
                lastSensitivePackage = lastSensitivePackage,
                elapsedSinceSensitiveMillis = now - lastSensitiveAt,
                ownPackage = ownPackage
            )
        ) {
            Log.w(
                EdrTriggerPolicy.TAG,
                "Possible overlay/scraping over $lastSensitivePackage by $eventPackage/${className ?: "?"}"
            )
        }
    }

    override fun onInterrupt() {
        Log.i(EdrTriggerPolicy.TAG, "Accessibility behavior monitor interrupted")
    }
}

/**
 * Overlay sezgiselinin **saf** kısmı (Android bağımlılığı yok, test edilebilir).
 */
object OverlayPolicy {

    /** Hassas ön plan sonrası şüpheli pencere penceresi (10 sn). */
    const val WINDOW_MILLIS = 10_000L

    /**
     * Hedef hassas paketler: paket kurucu, izin denetleyici, sistem arayüzü ve
     * ayarlar. Kendi paketimiz ayrıca [isSensitivePackage]'e parametre verilir
     * (sabit kodlanmaz).
     */
    val KNOWN_SENSITIVE_PACKAGES: Set<String> = setOf(
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.android.systemui",
        "com.android.settings"
    )

    private val OVERLAY_LIKE_TOKENS = listOf("dialog", "popup", "overlay", "alertdialog")

    fun isSensitivePackage(packageName: String?, ownPackage: String?): Boolean {
        if (packageName.isNullOrEmpty()) return false
        if (ownPackage != null && packageName == ownPackage) return true
        return KNOWN_SENSITIVE_PACKAGES.contains(packageName)
    }

    /** Sınıf adı diyalog/popup/overlay benzeri mi? (null-güvenli, küçük harf). */
    fun isOverlayLikeClass(className: String?): Boolean {
        if (className.isNullOrEmpty()) return false
        val lower = className.lowercase()
        return OVERLAY_LIKE_TOKENS.any { lower.contains(it) }
    }

    /**
     * İşaretleme kararı: hassas paket ön plandayken (pencere içinde), farklı bir
     * üçüncü parti paketten overlay-benzeri pencere gelirse true.
     */
    fun shouldFlag(
        eventPackage: String?,
        eventClass: String?,
        lastSensitivePackage: String?,
        elapsedSinceSensitiveMillis: Long,
        ownPackage: String?
    ): Boolean {
        if (eventPackage.isNullOrEmpty()) return false
        if (ownPackage != null && eventPackage == ownPackage) return false
        if (lastSensitivePackage == null) return false
        if (elapsedSinceSensitiveMillis < 0L || elapsedSinceSensitiveMillis > WINDOW_MILLIS) return false
        if (eventPackage == lastSensitivePackage) return false
        if (KNOWN_SENSITIVE_PACKAGES.contains(eventPackage)) return false
        return isOverlayLikeClass(eventClass)
    }
}
