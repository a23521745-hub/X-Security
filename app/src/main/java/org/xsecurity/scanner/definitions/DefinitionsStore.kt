package org.xsecurity.scanner.definitions

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.xsecurity.scanner.data.SignatureStore

/** UI ve bildirimin beslendigi tek tanim-kanali durum noktasi (StateFlow + kalicilama). */
enum class DefinitionsStatus {
    IDLE,
    CHECKING,
    UP_TO_DATE,
    UPDATE_AVAILABLE,
    DOWNLOADING,
    ERROR,
    NOT_CONFIGURED
}

data class DefinitionsState(
    val status: DefinitionsStatus = DefinitionsStatus.IDLE,
    val installedDefVersion: Int = 0,
    val available: DefinitionsManifest? = null,
    val progress: Float = 0f,
    val message: String? = null,
    val checkedAt: Long = 0L,
    val lastInstalledAt: Long = 0L
) {
    val isBusy: Boolean get() = status == DefinitionsStatus.CHECKING || status == DefinitionsStatus.DOWNLOADING
}

object DefinitionsStore {

    private const val PREFS = "xsec_definitions"
    private const val KEY_STATUS = "status"
    private const val KEY_INSTALLED_VERSION = "installed_def_version"
    private const val KEY_AVAILABLE_JSON = "available_json"
    private const val KEY_CHECKED_AT = "checked_at"
    private const val KEY_LAST_INSTALLED_AT = "last_installed_at"

    private val _state = MutableStateFlow(DefinitionsState())
    val state: StateFlow<DefinitionsState> = _state.asStateFlow()

    fun restore(context: Context) {
        val prefs = prefs(context)
        val available = prefs.getString(KEY_AVAILABLE_JSON, null)
            ?.let { runCatching { DefinitionsManifest.fromJson(it) }.getOrNull() }
        val storedStatus = runCatching {
            DefinitionsStatus.valueOf(prefs.getString(KEY_STATUS, null) ?: DefinitionsStatus.IDLE.name)
        }.getOrDefault(DefinitionsStatus.IDLE)

        val effectiveStatus = when {
            // Surec indirme ortasinda olmusse durum kaybolmustur; yeniden kontrol yapilabilir.
            storedStatus == DefinitionsStatus.DOWNLOADING -> DefinitionsStatus.IDLE
            storedStatus == DefinitionsStatus.UPDATE_AVAILABLE && available == null -> DefinitionsStatus.IDLE
            else -> storedStatus
        }

        _state.value = DefinitionsState(
            status = effectiveStatus,
            installedDefVersion = installedDefVersion(context),
            available = available,
            checkedAt = prefs.getLong(KEY_CHECKED_AT, 0L),
            lastInstalledAt = prefs.getLong(KEY_LAST_INSTALLED_AT, 0L)
        )
    }

    /**
     * Yuklu tanim paketi surumu. Ilk okumada cozumlenir ve kalicilanir:
     *  - diskteki dosyalar paketle gelen veritabaninin kendisiyse -> paket surumu,
     *  - degilse (eski ornek dosyalar, kullanicinin kurdugu dosyalar, eksik dosya)
     *    -> 0; yani "ilk OTA paketi her zaman kurulum onerir".
     */
    fun installedDefVersion(context: Context): Int {
        val prefs = prefs(context)
        val stored = prefs.getInt(KEY_INSTALLED_VERSION, Int.MIN_VALUE)
        if (stored != Int.MIN_VALUE) return stored

        val bundled = SignatureStore.bundledDefVersion(context)
        val matchesBundled = SignatureStore.Kind.values().all { kind ->
            val info = SignatureStore.info(context, kind)
            val bundledSha = SignatureStore.bundledSha256Short(context, kind)
            info.source == "bundled" && bundledSha != null && info.sha256Short == bundledSha
        }
        val initial = if (matchesBundled) bundled else 0
        prefs.edit { putInt(KEY_INSTALLED_VERSION, initial) }
        return initial
    }

    fun checking() {
        _state.value = _state.value.copy(status = DefinitionsStatus.CHECKING, progress = 0f, message = null)
    }

    fun upToDate() {
        _state.value = _state.value.copy(
            status = DefinitionsStatus.UP_TO_DATE,
            progress = 1f,
            message = null,
            available = null,
            checkedAt = System.currentTimeMillis()
        )
        persist(_state.value)
    }

    fun updateAvailable(manifest: DefinitionsManifest) {
        _state.value = _state.value.copy(
            status = DefinitionsStatus.UPDATE_AVAILABLE,
            available = manifest,
            progress = 0f,
            message = null,
            checkedAt = System.currentTimeMillis()
        )
        persist(_state.value)
    }

    /** Durumu degistirmeden bilgilendirici bir mesaj birakir (orn. kullanici veritabani korunuyor). */
    fun notice(message: String) {
        _state.value = _state.value.copy(message = message)
    }

    fun downloading(manifest: DefinitionsManifest) {
        _state.value = _state.value.copy(
            status = DefinitionsStatus.DOWNLOADING,
            available = manifest,
            progress = 0f,
            message = null
        )
    }

    fun setDownloadProgress(fraction: Float) {
        if (_state.value.status != DefinitionsStatus.DOWNLOADING) return
        _state.value = _state.value.copy(progress = fraction.coerceIn(0f, 1f))
    }

    fun installed(defVersion: Int) {
        _state.value = _state.value.copy(
            status = DefinitionsStatus.UP_TO_DATE,
            installedDefVersion = defVersion,
            available = null,
            progress = 1f,
            message = null,
            checkedAt = System.currentTimeMillis(),
            lastInstalledAt = System.currentTimeMillis()
        )
        persist(_state.value)
    }

    fun error(message: String) {
        _state.value = _state.value.copy(status = DefinitionsStatus.ERROR, progress = 0f, message = message)
    }

    fun notConfigured(message: String) {
        _state.value = _state.value.copy(status = DefinitionsStatus.NOT_CONFIGURED, message = message)
    }

    fun reset() {
        _state.value = DefinitionsState()
    }

    private fun persist(state: DefinitionsState) {
        lastContext?.let { context ->
            prefs(context).edit {
                putString(KEY_STATUS, state.status.name)
                putInt(KEY_INSTALLED_VERSION, state.installedDefVersion)
                putString(KEY_AVAILABLE_JSON, state.available?.toJson())
                putLong(KEY_CHECKED_AT, state.checkedAt)
                putLong(KEY_LAST_INSTALLED_AT, state.lastInstalledAt)
            }
        }
    }

    @Volatile
    private var lastContext: Context? = null

    private fun prefs(context: Context): android.content.SharedPreferences {
        lastContext = context.applicationContext
        return context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }
}
