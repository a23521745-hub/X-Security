package org.xsecurity.scanner.edr

/**
 * Davranışsal EDR'nin **saf** karar mantığı (saf JVM'de test edilir).
 *
 * [BehavioralEdrService] ince kalır: AppOps geri çağrısı + ön/arka plan çözümü
 * serviste, "uyarı verilsin mi?" kararı burada. Sabitler framework değerlerinin
 * birebir aynasıdır (`AppOpsManager.OPSTR_*`, `RunningAppProcessInfo`
 * `IMPORTANCE_*`) ki android.jar olmadan birim testler çalışabilsin:
 *  - `OP_CAMERA = "android:camera"`
 *  - `OP_RECORD_AUDIO = "android:record_audio"`
 *  - `IMPORTANCE_FOREGROUND = 100`
 */
object EdrTriggerPolicy {

    const val TAG = "XSecurityEDR"

    /** `AppOpsManager.OPSTR_CAMERA` aynası. */
    const val OP_CAMERA = "android:camera"

    /** `AppOpsManager.OPSTR_RECORD_AUDIO` aynası. */
    const val OP_RECORD_AUDIO = "android:record_audio"

    /** İzlenen donanım işlemleri (kamera + mikrofon). */
    val WATCHED_OPS: Set<String> = setOf(OP_CAMERA, OP_RECORD_AUDIO)

    /** `RunningAppProcessInfo.IMPORTANCE_FOREGROUND` aynası (100). */
    const val IMPORTANCE_FOREGROUND = 100

    /**
     * `ActivityManager.getRunningAppProcesses()` paketi bulamadığında kullanılan
     * duyarlı değer. API 26+ bu liste üçüncü parti süreçleri içermez; bilinmeyen
     * durum bir güvenlik ürününde arka plan sayılır (fail-closed).
     */
    const val IMPORTANCE_UNKNOWN = -1

    /** Bildirim başlığı (şartname metni, aynen). */
    const val ALERT_TITLE = "\uD83D\uDEA8 Şüpheli Arka Plan Erişimi Tespit Edildi"

    /** Bu işlem izleniyor mu? */
    fun isWatchedOp(op: String?): Boolean = op != null && WATCHED_OPS.contains(op)

    /** Bu önem seviyesi "ön plan değil" mi? */
    fun isBackground(importance: Int): Boolean = importance != IMPORTANCE_FOREGROUND

    /**
     * Uyarı kararı: izlenen işlem aktifken paket ön planda değilse **veya**
     * ekran etkileşimsizse (kapalı/kilitli) uyar.
     *
     *  - `active == false` (işlem bitti) → asla uyarma.
     *  - İzlenmeyen işlem → asla uyarma.
     *  - Bilinmeyen önem → uyar (fail-closed, bkz. [IMPORTANCE_UNKNOWN]).
     *  - Ön plan + ekran açık → uyarma (meşru kullanım).
     */
    fun shouldAlert(op: String?, active: Boolean, importance: Int, screenInteractive: Boolean): Boolean {
        if (!active) return false
        if (!isWatchedOp(op)) return false
        if (importance == IMPORTANCE_UNKNOWN) return true
        return importance != IMPORTANCE_FOREGROUND || !screenInteractive
    }

    /** Bildirim gövdesindeki sensör adı (şartname: "Camera"/"Microphone"). */
    fun sensorLabel(op: String?): String = when (op) {
        OP_CAMERA -> "Camera"
        OP_RECORD_AUDIO -> "Microphone"
        else -> op ?: "Sensor"
    }

    /** Bildirim gövdesindeki bağlam sözcüğü ("ekran kapalıyken / arka plandayken"). */
    fun contextWord(screenInteractive: Boolean): String =
        if (screenInteractive) "arka plandayken" else "ekran kapalıyken"

    /**
     * Bildirim gövdesi (şartname kalıbı):
     * "[PackageName] uygulaması ekran kapalıyken / arka plandayken
     * [Camera/Microphone] erişimi sağladı!"
     */
    fun alertBody(packageName: String, op: String?, screenInteractive: Boolean): String =
        "$packageName uygulaması ${contextWord(screenInteractive)} ${sensorLabel(op)} erişimi sağladı!"

    /**
     * Kısa süreli tekrar engelleyici: aynı paket+işlem uyarısı pencere içinde
     * bir kez gösterilir (bildirim seli ve pil tüketimi engellenir).
     */
    class Deduplicator(private val windowMillis: Long = 60_000L) {
        private val seen = LinkedHashMap<String, Long>()

        @Synchronized
        fun accept(key: String, now: Long): Boolean {
            val iterator = seen.entries.iterator()
            while (iterator.hasNext()) {
                if (now - iterator.next().value > windowMillis) iterator.remove() else break
            }
            if (seen.containsKey(key)) return false
            seen[key] = now
            return true
        }
    }
}
