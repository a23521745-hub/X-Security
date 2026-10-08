package org.xsecurity.scanner.autopilot

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object AutopilotSettings {
    private const val PREFS = "xsec_autopilot"
    private const val KEY_AUTONOMY = "autonomy_level"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_LAST_SCAN_ENQUEUED = "last_scan_enqueued"
    private const val KEY_LAST_FOREGROUND_PACKAGE = "last_foreground_package"

    private val _autonomy = MutableStateFlow(PolicyEngine.DEFAULT_LEVEL)
    val autonomy: StateFlow<AutonomyLevel> = _autonomy.asStateFlow()

    fun restore(context: Context) {
        _autonomy.value = level(context)
    }

    fun level(context: Context): AutonomyLevel {
        val raw = prefs(context).getString(KEY_AUTONOMY, PolicyEngine.DEFAULT_LEVEL.name)
        return runCatching { AutonomyLevel.valueOf(raw ?: PolicyEngine.DEFAULT_LEVEL.name) }
            .getOrDefault(PolicyEngine.DEFAULT_LEVEL)
    }

    fun setLevel(context: Context, level: AutonomyLevel) {
        prefs(context).edit { putString(KEY_AUTONOMY, level.name) }
        _autonomy.value = level
    }

    /** Foundations are enabled by default; the sensor loop still degrades gracefully without optional access. */
    fun isEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ENABLED, true)

    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit { putBoolean(KEY_ENABLED, enabled) }
    }

    fun lastScanEnqueuedAt(context: Context): Long = prefs(context).getLong(KEY_LAST_SCAN_ENQUEUED, 0L)

    fun markScanEnqueued(context: Context, atMillis: Long) {
        prefs(context).edit { putLong(KEY_LAST_SCAN_ENQUEUED, atMillis) }
    }

    fun lastForegroundPackage(context: Context): String? =
        prefs(context).getString(KEY_LAST_FOREGROUND_PACKAGE, null)

    fun setLastForegroundPackage(context: Context, packageName: String?) {
        prefs(context).edit {
            if (packageName == null) remove(KEY_LAST_FOREGROUND_PACKAGE)
            else putString(KEY_LAST_FOREGROUND_PACKAGE, packageName)
        }
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
