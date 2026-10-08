package org.xsecurity.scanner.ota

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** UI ve bildirimin beslendigi tek OTA durum noktasi (StateFlow + kalicilama). */
enum class OtaStatus {
    IDLE,
    CHECKING,
    UP_TO_DATE,
    UPDATE_AVAILABLE,
    DOWNLOADING,
    READY_TO_INSTALL,
    ERROR,
    NOT_CONFIGURED
}

data class OtaState(
    val status: OtaStatus = OtaStatus.IDLE,
    val available: UpdateInfo? = null,
    val progress: Float = 0f,
    val message: String? = null,
    val downloadedPath: String? = null,
    val checkedAt: Long = 0L
) {
    val isBusy: Boolean get() = status == OtaStatus.CHECKING || status == OtaStatus.DOWNLOADING
}

object OtaStore {

    private const val PREFS = "xsec_ota"
    private const val KEY_STATUS = "status"
    private const val KEY_INFO = "update_info_json"
    private const val KEY_PATH = "downloaded_path"
    private const val KEY_CHECKED_AT = "checked_at"

    private val _state = MutableStateFlow(OtaState())
    val state: StateFlow<OtaState> = _state.asStateFlow()

    fun restore(context: Context) {
        val prefs = prefs(context)
        val info = prefs.getString(KEY_INFO, null)?.let { runCatching { UpdateInfo.fromJson(it) }.getOrNull() }
        val path = prefs.getString(KEY_PATH, null)?.takeIf { java.io.File(it).isFile }
        val status = runCatching {
            OtaStatus.valueOf(prefs.getString(KEY_STATUS, OtaStatus.IDLE.name) ?: OtaStatus.IDLE.name)
        }.getOrDefault(OtaStatus.IDLE)

        _state.value = OtaState(
            // Dosya silinmisse READY_TO_INSTALL anlamsizdir; tekrar indirilebilir.
            status = if (status == OtaStatus.READY_TO_INSTALL && path == null) OtaStatus.IDLE else status,
            available = info,
            downloadedPath = path,
            checkedAt = prefs.getLong(KEY_CHECKED_AT, 0L)
        )
    }

    fun checking() {
        _state.value = _state.value.copy(status = OtaStatus.CHECKING, progress = 0f, message = null)
    }

    fun upToDate() {
        _state.value = _state.value.copy(
            status = OtaStatus.UP_TO_DATE,
            progress = 1f,
            message = null,
            available = null,
            checkedAt = System.currentTimeMillis()
        )
        persist(_state.value)
    }

    fun updateAvailable(info: UpdateInfo) {
        _state.value = _state.value.copy(
            status = OtaStatus.UPDATE_AVAILABLE,
            available = info,
            progress = 0f,
            message = null,
            checkedAt = System.currentTimeMillis()
        )
        persist(_state.value)
    }

    fun downloading(info: UpdateInfo) {
        _state.value = _state.value.copy(
            status = OtaStatus.DOWNLOADING,
            available = info,
            progress = 0f,
            message = null
        )
    }

    fun setDownloadProgress(fraction: Float) {
        if (_state.value.status != OtaStatus.DOWNLOADING) return
        _state.value = _state.value.copy(progress = fraction.coerceIn(0f, 1f))
    }

    fun readyToInstall(info: UpdateInfo, path: String) {
        _state.value = _state.value.copy(
            status = OtaStatus.READY_TO_INSTALL,
            available = info,
            progress = 1f,
            downloadedPath = path,
            message = null,
            checkedAt = System.currentTimeMillis()
        )
        persist(_state.value)
    }

    fun error(message: String) {
        _state.value = _state.value.copy(status = OtaStatus.ERROR, progress = 0f, message = message)
    }

    fun notConfigured(message: String) {
        _state.value = _state.value.copy(status = OtaStatus.NOT_CONFIGURED, message = message)
    }

    fun reset() {
        _state.value = OtaState()
    }

    private fun persist(state: OtaState) {
        lastContext?.let { context ->
            prefs(context).edit {
                putString(KEY_STATUS, state.status.name)
                putString(KEY_INFO, state.available?.toJson())
                putString(KEY_PATH, state.downloadedPath)
                putLong(KEY_CHECKED_AT, state.checkedAt)
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
