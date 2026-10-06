package org.xsecurity.scanner.quarantine

import android.content.Context
import androidx.core.content.edit

/** Minimal private hand-off for a user-authorized Accessibility force-stop assist. */
internal object QuarantineAssistStore {
    private const val PREFS = "xsec_quarantine_assist"
    private const val KEY_PACKAGE = "package"
    private const val KEY_RECORD_ID = "record_id"
    private const val KEY_STAGE = "stage"
    private const val KEY_STARTED_AT = "started_at"

    data class Request(val packageName: String, val recordId: String, val stage: String, val startedAtMillis: Long)

    fun set(context: Context, packageName: String, recordId: String, stage: String) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putString(KEY_PACKAGE, packageName)
            putString(KEY_RECORD_ID, recordId)
            putString(KEY_STAGE, stage)
            putLong(KEY_STARTED_AT, System.currentTimeMillis())
        }
    }

    fun current(context: Context): Request? {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val pkg = prefs.getString(KEY_PACKAGE, null) ?: return null
        val record = prefs.getString(KEY_RECORD_ID, null) ?: return null
        val stage = prefs.getString(KEY_STAGE, null) ?: return null
        val started = prefs.getLong(KEY_STARTED_AT, 0L)
        if (started == 0L || System.currentTimeMillis() - started > MAX_AGE_MILLIS) {
            clear(context)
            return null
        }
        return Request(pkg, record, stage, started)
    }

    fun updateStage(context: Context, stage: String) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { putString(KEY_STAGE, stage) }
    }

    fun clear(context: Context) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { clear() }
    }

    fun clearIfRecord(context: Context, recordId: String) {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getString(KEY_RECORD_ID, null) == recordId) prefs.edit { clear() }
    }

    private const val MAX_AGE_MILLIS = 5L * 60L * 1000L
}
