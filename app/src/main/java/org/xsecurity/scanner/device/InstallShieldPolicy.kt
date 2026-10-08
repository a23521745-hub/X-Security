package org.xsecurity.scanner.device

/**
 * Kurulum ani kalkaninin **saf** karar mantigi (BroadcastReceiver ince kalir).
 *
 *  - Hangi yayinlar tetikler? `PACKAGE_ADDED` ve `PACKAGE_REPLACED`; ancak
 *    `PACKAGE_ADDED` bir guncellemenin parcasiysa (`EXTRA_REPLACING=true`) atlanir,
 *    cunku hemen ardindan `PACKAGE_REPLACED` gelir (aksi halde ayni APK iki kez taranir).
 *  - Kendi paketimiz (OTA guncellemesi sonrasi gelen `PACKAGE_REPLACED`) taranmaz.
 *  - Bildirim karari: tehdit varsa yuksek oncelik + kaldir + parola tavsiyesi;
 *    temizse ve kullanici "sessiz" modu sectiyse hic bildirim yok; hata durumunda
 *    dusuk oncelikli bilgi.
 */
object InstallShieldPolicy {

    const val ACTION_PACKAGE_ADDED = "android.intent.action.PACKAGE_ADDED"
    const val ACTION_PACKAGE_REPLACED = "android.intent.action.PACKAGE_REPLACED"

    enum class Verdict { SCAN, SKIP_REPLACING_DUPLICATE, SKIP_SELF, SKIP_UNKNOWN_ACTION, SKIP_NO_PACKAGE }

    fun decide(action: String?, packageName: String?, replacing: Boolean, selfPackage: String): Verdict {
        if (action != ACTION_PACKAGE_ADDED && action != ACTION_PACKAGE_REPLACED) return Verdict.SKIP_UNKNOWN_ACTION
        if (packageName.isNullOrBlank()) return Verdict.SKIP_NO_PACKAGE
        if (packageName == selfPackage) return Verdict.SKIP_SELF
        if (action == ACTION_PACKAGE_ADDED && replacing) return Verdict.SKIP_REPLACING_DUPLICATE
        return Verdict.SCAN
    }

    /** `package:com.example` bicimindeki intent verisinden paket adini cikarir. */
    fun packageNameFromData(data: String?): String? {
        if (data.isNullOrBlank()) return null
        val name = data.removePrefix("package:").trim()
        return name.ifBlank { null }
    }

    enum class Alert { THREAT, CLEAN_INFO, FAILED_INFO, NONE }

    /**
     * Tarama sonucuna gore bildirim karari.
     * @param quietWhenClean kullanici temiz kurulumlar icin bildirim istemiyorsa true.
     */
    fun alertFor(entry: AppScanEntry, quietWhenClean: Boolean): Alert = when {
        entry.isInfected -> Alert.THREAT
        entry.isFailed -> Alert.FAILED_INFO
        quietWhenClean -> Alert.NONE
        else -> Alert.CLEAN_INFO
    }
}
