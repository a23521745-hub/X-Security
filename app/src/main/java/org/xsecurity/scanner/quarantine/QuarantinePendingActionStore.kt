package org.xsecurity.scanner.quarantine

import android.content.Context
import androidx.core.content.edit

/** One-shot return-state for the explicit system uninstall confirmation flow. */
object QuarantinePendingActionStore {
    private const val PREFS = "xsec_quarantine_pending_action"
    private const val KEY_PACKAGE = "package"
    private const val KEY_RECORD = "record"

    fun setUninstall(context: Context, packageName: String, recordId: String?) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putString(KEY_PACKAGE, packageName)
            putString(KEY_RECORD, recordId)
        }
    }

    data class PendingUninstall(val packageName: String, val recordId: String?)

    fun consumeUninstall(context: Context): PendingUninstall? {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val packageName = prefs.getString(KEY_PACKAGE, null) ?: return null
        val recordId = prefs.getString(KEY_RECORD, null)
        prefs.edit { remove(KEY_PACKAGE); remove(KEY_RECORD) }
        return PendingUninstall(packageName, recordId)
    }
}
