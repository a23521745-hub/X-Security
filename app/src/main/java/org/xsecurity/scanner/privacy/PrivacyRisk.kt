package org.xsecurity.scanner.privacy

/**
 * Gizlilik riskinin **saf** mantigi (JVM'de test edilir).
 *
 * Izin adlari framework degerlerinin birebir aynasidir
 * (`Manifest.permission.*`); Android'e deginmeden eslesme yapilir:
 *  - kamera: `android.permission.CAMERA`
 *  - mikrofon: `android.permission.RECORD_AUDIO`
 *  - konum: `ACCESS_FINE_LOCATION` / `ACCESS_COARSE_LOCATION` /
 *    `ACCESS_BACKGROUND_LOCATION`
 *  - SMS: `READ_SMS` / `RECEIVE_SMS` / `SEND_SMS`
 *  - rehber: `READ_CONTACTS`
 *
 * Agirliklar: SMS tek basina HIGH (OTP/calinti riski); konum/rehber/mikrofon
 * tek basina MEDIUM; yalnizca kamera LOW. Karmalar toplanir.
 */
object PrivacyRisk {

    enum class Group { CAMERA, MICROPHONE, LOCATION, SMS, CONTACTS }

    enum class Level { HIGH, MEDIUM, LOW }

    const val PERMISSION_CAMERA = "android.permission.CAMERA"
    const val PERMISSION_RECORD_AUDIO = "android.permission.RECORD_AUDIO"
    const val PERMISSION_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
    const val PERMISSION_COARSE_LOCATION = "android.permission.ACCESS_COARSE_LOCATION"
    const val PERMISSION_BACKGROUND_LOCATION = "android.permission.ACCESS_BACKGROUND_LOCATION"
    const val PERMISSION_READ_SMS = "android.permission.READ_SMS"
    const val PERMISSION_RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    const val PERMISSION_SEND_SMS = "android.permission.SEND_SMS"
    const val PERMISSION_READ_CONTACTS = "android.permission.READ_CONTACTS"

    val GROUP_PERMISSIONS: Map<Group, Set<String>> = mapOf(
        Group.CAMERA to setOf(PERMISSION_CAMERA),
        Group.MICROPHONE to setOf(PERMISSION_RECORD_AUDIO),
        Group.LOCATION to setOf(
            PERMISSION_FINE_LOCATION,
            PERMISSION_COARSE_LOCATION,
            PERMISSION_BACKGROUND_LOCATION
        ),
        Group.SMS to setOf(PERMISSION_READ_SMS, PERMISSION_RECEIVE_SMS, PERMISSION_SEND_SMS),
        Group.CONTACTS to setOf(PERMISSION_READ_CONTACTS)
    )

    private val WEIGHTS: Map<Group, Int> = mapOf(
        Group.SMS to 4,
        Group.CONTACTS to 2,
        Group.LOCATION to 2,
        Group.MICROPHONE to 2,
        Group.CAMERA to 1
    )

    data class App(
        val packageName: String,
        val label: String,
        val isSystem: Boolean,
        val groups: Set<Group>
    ) {
        val displayName: String get() = label.ifBlank { packageName }
        val score: Int get() = scoreOf(groups)
        val level: Level get() = levelFor(groups)
    }

    /** Verilmis izinlerden etkilenen gruplar (bos kume = listeye girmez). */
    fun groupsFor(grantedPermissions: Collection<String>): Set<Group> {
        if (grantedPermissions.isEmpty()) return emptySet()
        val granted = grantedPermissions.toSet()
        return GROUP_PERMISSIONS.entries
            .filter { (_, permissions) -> permissions.any { it in granted } }
            .map { it.key }
            .toSet()
    }

    fun scoreOf(groups: Set<Group>): Int = groups.sumOf { WEIGHTS.getValue(it) }

    fun levelFor(groups: Set<Group>): Level = when {
        scoreOf(groups) >= 4 -> Level.HIGH
        scoreOf(groups) >= 2 -> Level.MEDIUM
        else -> Level.LOW
    }

    /** Risk puani yuksekten dusuge, esitlikte ada gore (kararli sira). */
    fun sort(apps: List<App>): List<App> =
        apps.sortedWith(
            compareByDescending<App> { scoreOf(it.groups) }
                .thenBy { it.displayName.lowercase() }
                .thenBy { it.packageName }
        )
}
