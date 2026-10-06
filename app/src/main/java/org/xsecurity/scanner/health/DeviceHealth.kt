package org.xsecurity.scanner.health

/**
 * Cihaz butunlugunun basit, tamamen cihaz-ici gostergesi.
 *
 * Play Integrity API (ag + Google bagimliligi) YOKTUR; bunun yerine herkesin
 * denetleyebilecegi acik sinyaller kullanilir:
 *  - root ikilisi (`su`) bilinen yollarda var mi?
 *  - derleme `test-keys` ile mi imzalanmis (ozel/koklu ROM isareti)?
 *  - USB hata ayiklama (ADB) acik mi?
 *
 * Karar mantigi saf ([evaluate]/[findSu]/[hasTestKeys], test edilir); okuma
 * [HealthStore]'dadir. Ag yok, veri cihazdan cikmaz.
 */
object DeviceHealth {

    enum class Verdict { HEALTHY, WARNING, AT_RISK }

    object FindingId {
        const val ROOT_SU = "root_su"
        const val TEST_KEYS = "test_keys"
        const val ADB_ENABLED = "adb_enabled"
    }

    data class Finding(val id: String, val detail: String? = null)

    data class Snapshot(
        val verdict: Verdict = Verdict.HEALTHY,
        val findings: List<Finding> = emptyList()
    )

    /**
     * Klasik `su` konumlari. Varlik kontrolu dosya okumaz, yalnizca `exists`
     * sorar (izin hatasi "yok" sayilir — fail-open DEGIL, fail-silent: sinyal
     * uretilmez ama yanlis "saglikli" iddiasi da guclenmez cunku rozet
     * "algilanmadi" dilini kullanir).
     */
    val SU_PATHS: List<String> = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/bin/failsafe/su",
        "/su/bin/su",
        "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon"
    )

    /** Saf: ilk bulunan `su` yolu (yoksa null). `exists` enjekte edilir. */
    fun findSu(exists: (String) -> Boolean): String? =
        SU_PATHS.firstOrNull { path -> runCatching { exists(path) }.getOrDefault(false) }

    /** Saf: derleme etiketleri `test-keys` iceriyor mu? */
    fun hasTestKeys(buildTags: String?): Boolean =
        buildTags?.split(',', ' ', ';')?.any { it.trim() == "test-keys" } == true

    /**
     * Saf: sinyallerden hukum. `su` varsa AT_RISK; yalnizca test-keys/ADB
     * varsa WARNING (mesru gelistirici cihazi olabilir); aksi halde HEALTHY.
     */
    fun evaluate(suPath: String?, testKeys: Boolean, adbEnabled: Boolean): Snapshot {
        val findings = ArrayList<Finding>(3)
        if (suPath != null) findings += Finding(FindingId.ROOT_SU, suPath)
        if (testKeys) findings += Finding(FindingId.TEST_KEYS)
        if (adbEnabled) findings += Finding(FindingId.ADB_ENABLED)
        val verdict = when {
            suPath != null -> Verdict.AT_RISK
            findings.isNotEmpty() -> Verdict.WARNING
            else -> Verdict.HEALTHY
        }
        return Snapshot(verdict, findings)
    }
}
