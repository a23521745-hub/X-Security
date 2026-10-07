package org.xsecurity.scanner.quarantine

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.xsecurity.scanner.R
import org.xsecurity.scanner.autopilot.AutopilotNotifications
import org.xsecurity.scanner.ui.MainActivity

/**
 * Notifications for file-vault records. Wording comes from [QuarantineWording] so the honesty
 * rule is enforced on the exact texts: while the original is on the device the notification is
 * an ongoing "copy saved, original still present" prompt with a "Delete now" action; only after
 * the original is gone does it say "quarantined".
 */
object QuarantineFileNotifications {
    private const val ID_BASE = 4700
    private const val ID_MASK = 0x3FF

    fun notificationId(recordId: String): Int = ID_BASE + (recordId.hashCode() and ID_MASK)

    /** Vault copy exists, original still present: urgent, ongoing, with the retry action. */
    fun showStaged(context: Context, record: QuarantineRecord) {
        if (!QuarantineHonesty.originalRemovalPending(record)) {
            cancel(context, record.id)
            return
        }
        AutopilotNotifications.ensureChannels(context)
        val (titleKey, bodyKey) = QuarantineWording.notificationKeys(record)
        val hint = QuarantineWording.hintKey(record.cutResult)?.let { resolve(context, it) }
        val body = listOfNotNull(resolve(context, bodyKey, record.label), hint).joinToString(" ")
        val builder = NotificationCompat.Builder(context, AutopilotNotifications.CHANNEL_CRITICAL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(resolve(context, titleKey))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(cutIntent(context, record.id, QuarantineCutActivity.MODE_CUT))
            .setOngoing(true)
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .addAction(
                R.drawable.ic_stat_shield,
                resolve(context, QuarantineWording.KEY_ACTION_DELETE_NOW),
                cutIntent(context, record.id, QuarantineCutActivity.MODE_CUT)
            )
            .addAction(
                R.drawable.ic_stat_shield,
                resolve(context, QuarantineWording.KEY_ACTION_OPEN_QUARANTINE),
                openQuarantineIntent(context)
            )
        notify(context, notificationId(record.id), builder.build())
    }

    /** Original removed: replaces the ongoing prompt with a dismissible confirmation. */
    fun showRemoved(context: Context, record: QuarantineRecord) {
        if (!QuarantineHonesty.mayClaimFullQuarantine(record)) {
            // Never announce a full quarantine for a record whose original is still there.
            showStaged(context, record)
            return
        }
        AutopilotNotifications.ensureChannels(context)
        val (titleKey, bodyKey) = QuarantineWording.notificationKeys(record)
        val body = resolve(context, bodyKey, record.label)
        val notification = NotificationCompat.Builder(context, AutopilotNotifications.CHANNEL_INFO)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(resolve(context, titleKey))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(openQuarantineIntent(context))
            .setOngoing(false)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        notify(context, notificationId(record.id), notification)
    }

    fun cancel(context: Context, recordId: String) {
        runCatching { NotificationManagerCompat.from(context).cancel(notificationId(recordId)) }
    }

    /** Resolves a [QuarantineWording] key to the localized text (explicit map: resource shrinking safe). */
    fun resolve(context: Context, key: String, vararg args: Any): String {
        val id = when (key) {
            QuarantineWording.KEY_STATE_COPY_SAVED_ORIGINAL_PRESENT -> R.string.quarantine_display_copy_saved_original_present
            QuarantineWording.KEY_STATE_QUARANTINED_ORIGINAL_REMOVED -> R.string.quarantine_display_quarantined_original_removed
            QuarantineWording.KEY_STATE_COPY_DELETED_ORIGINAL_PRESENT -> R.string.quarantine_display_copy_deleted_original_present
            QuarantineWording.KEY_RESIDUE_PRESENT -> R.string.quarantine_residue_present
            QuarantineWording.KEY_RESIDUE_REMOVED -> R.string.quarantine_residue_removed
            QuarantineWording.KEY_NOTIF_STAGED_TITLE -> R.string.quarantine_file_staged_title
            QuarantineWording.KEY_NOTIF_STAGED_BODY -> R.string.quarantine_file_staged_body
            QuarantineWording.KEY_NOTIF_REMOVED_TITLE -> R.string.quarantine_file_removed_title
            QuarantineWording.KEY_NOTIF_REMOVED_BODY -> R.string.quarantine_file_removed_body
            QuarantineWording.KEY_ACTION_DELETE_NOW -> R.string.quarantine_file_action_delete_now
            QuarantineWording.KEY_ACTION_OPEN_QUARANTINE -> R.string.autopilot_open_quarantine
            QuarantineWording.KEY_SCAN_RESULT_STAGED -> R.string.autopilot_file_vaulted
            QuarantineWording.KEY_CUT_RESULT_REMOVED -> R.string.quarantine_cut_result_removed
            QuarantineWording.KEY_CUT_RESULT_DENIED -> R.string.quarantine_cut_result_denied
            QuarantineWording.KEY_CUT_RESULT_FAILED -> R.string.quarantine_cut_result_failed
            QuarantineWording.KEY_HINT_DENIED -> R.string.quarantine_cut_hint_denied
            QuarantineWording.KEY_HINT_PERMISSION -> R.string.quarantine_cut_hint_permission
            QuarantineWording.KEY_HINT_LOCATION_UNKNOWN -> R.string.quarantine_cut_hint_location_unknown
            QuarantineWording.KEY_HINT_CHANGED -> R.string.quarantine_cut_hint_changed
            QuarantineWording.KEY_HINT_VAULT -> R.string.quarantine_cut_hint_vault
            QuarantineWording.KEY_HINT_STILL_PRESENT -> R.string.quarantine_cut_hint_still_present
            QuarantineWording.KEY_HINT_DELETE_FAILED -> R.string.quarantine_cut_hint_delete_failed
            QuarantineWording.KEY_HINT_AWAITING -> R.string.quarantine_cut_hint_awaiting
            else -> return key
        }
        return if (args.isEmpty()) context.getString(id) else context.getString(id, *args)
    }

    private fun cutIntent(context: Context, recordId: String, mode: String): PendingIntent {
        val intent = Intent(context, QuarantineCutActivity::class.java).apply {
            putExtra(QuarantineCutActivity.EXTRA_RECORD_ID, recordId)
            putExtra(QuarantineCutActivity.EXTRA_MODE, mode)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        return PendingIntent.getActivity(
            context,
            notificationId(recordId) xor mode.hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun openQuarantineIntent(context: Context): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            putExtra(MainActivity.EXTRA_OPEN_QUARANTINE, true)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        return PendingIntent.getActivity(
            context,
            ID_BASE,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun notify(context: Context, id: Int, notification: android.app.Notification) {
        val manager = NotificationManagerCompat.from(context)
        if (!manager.areNotificationsEnabled()) return
        try {
            manager.notify(id, notification)
        } catch (_: SecurityException) {
            // API 33+: POST_NOTIFICATIONS not granted; the Quarantine screen still shows the honest state.
        } catch (_: RuntimeException) {
            // OEM notification failures must never break the quarantine flow.
        }
    }
}
