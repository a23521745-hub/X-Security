package org.xsecurity.scanner.device

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Koruma modu ayari.
 *
 *  - [ProtectionMode.ALWAYS]: on plan servisi + Download/ izleme + kurulum kalkani (Asama C).
 *  - [ProtectionMode.INSTALL_ONLY] (varsayilan): yalnizca kurulum ani kalkani; kalici
 *    servis yok, pil dostu.
 *  - [ProtectionMode.OFF]: hicbir otomatik tarama yok; kullanici elle tarar.
 */
enum class ProtectionMode { ALWAYS, INSTALL_ONLY, OFF }

data class ProtectionState(
    val mode: ProtectionMode = ProtectionMode.INSTALL_ONLY,
    val quietWhenClean: Boolean = true
)

object ProtectionSettings {

    private const val PREFS = "xsec_protection"
    private const val KEY_MODE = "mode"
    private const val KEY_QUIET_CLEAN = "quiet_when_clean"

    private val _state = MutableStateFlow(ProtectionState())
    val state: StateFlow<ProtectionState> = _state.asStateFlow()

    fun restore(context: Context) {
        _state.value = ProtectionState(mode = mode(context), quietWhenClean = quietWhenClean(context))
    }

    fun mode(context: Context): ProtectionMode = parseMode(prefs(context).getString(KEY_MODE, null))

    fun setMode(context: Context, mode: ProtectionMode) {
        prefs(context).edit { putString(KEY_MODE, mode.name) }
        _state.value = _state.value.copy(mode = mode)
    }

    /** Temiz kurulumlar icin bildirim gosterilmesin mi? (varsayilan: sessiz) */
    fun quietWhenClean(context: Context): Boolean = prefs(context).getBoolean(KEY_QUIET_CLEAN, true)

    fun setQuietWhenClean(context: Context, quiet: Boolean) {
        prefs(context).edit { putBoolean(KEY_QUIET_CLEAN, quiet) }
        _state.value = _state.value.copy(quietWhenClean = quiet)
    }

    /** Saf: bilinmeyen/bos deger varsayilana duser. */
    fun parseMode(raw: String?): ProtectionMode =
        raw?.let { value -> ProtectionMode.values().firstOrNull { it.name == value } } ?: ProtectionMode.INSTALL_ONLY

    /** Saf: kurulum kalkani bu modda calisir mi? */
    fun installShieldEnabled(mode: ProtectionMode): Boolean = mode != ProtectionMode.OFF

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
