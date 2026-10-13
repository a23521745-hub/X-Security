package org.xsecurity.scanner.autopilot

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.xsecurity.scanner.R
import org.xsecurity.scanner.quarantine.QuarantineUserActions
import org.xsecurity.scanner.ui.MainActivity

/** Quiet, user-configurable AutoPilot channels. Only critical threats use HIGH importance. */
object AutopilotNotifications {
    const val CHANNEL_CRITICAL = "autopilot_critical"
    const val CHANNEL_INFO = "autopilot_info"
    const val CHANNEL_DIGEST = "autopilot_digest"

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        listOf(
            NotificationChannel(CHANNEL_CRITICAL, context.getString(R.string.autopilot_channel_critical), NotificationManager.IMPORTANCE_HIGH),
            NotificationChannel(CHANNEL_INFO, context.getString(R.string.autopilot_channel_info), NotificationManager.IMPORTANCE_LOW),
            NotificationChannel(CHANNEL_DIGEST, context.getString(R.string.autopilot_channel_digest), NotificationManager.IMPORTANCE_MIN)
        ).forEach { channel ->
            channel.description = when (channel.id) {
                CHANNEL_CRITICAL -> context.getString(R.string.autopilot_channel_critical_desc)
                CHANNEL_INFO -> context.getString(R.string.autopilot_channel_info_desc)
                else -> context.getString(R.string.autopilot_channel_digest_desc)
            }
            channel.setSound(null, null)
            channel.enableVibration(false)
            channel.setShowBadge(false)
            manager.createNotificationChannel(channel)
        }
    }

    fun showDecision(
        context: Context,
        event: SecurityEvent,
        decision: PolicyDecision,
        recordId: String? = null
    ) {
        ensureChannels(context)
        val packageName = event.packageName
        val target = packageName?.let { packageLabel(context, it) } ?: context.getString(R.string.autopilot_unknown_target)
        val (title, body, channel, notificationId) = when (decision.action) {
            PolicyAction.BLOCK_AND_QUARANTINE -> Quad(
                context.getString(R.string.autopilot_notif_block_title),
                context.getString(R.string.autopilot_notif_block_body, target),
                CHANNEL_CRITICAL,
                ID_CRITICAL
            )
            PolicyAction.BLOCK_CONTENT -> Quad(
                context.getString(R.string.autopilot_notif_block_title),
                context.getString(R.string.autopilot_notif_content_block_body),
                CHANNEL_CRITICAL,
                ID_CRITICAL + (packageName?.hashCode()?.and(0x3FFF) ?: 0)
            )
            PolicyAction.ASK_USER -> Quad(
                context.getString(R.string.autopilot_notif_ask_title),
                context.getString(R.string.autopilot_notif_ask_body, target),
                CHANNEL_INFO,
                ID_INFO + (packageName?.hashCode()?.and(0x3FFF) ?: 0)
            )
            PolicyAction.RECOMMEND_CONTAINMENT -> Quad(
                context.getString(R.string.autopilot_notif_recommend_title),
                context.getString(R.string.autopilot_notif_recommend_body, target),
                CHANNEL_CRITICAL,
                ID_CRITICAL + 1
            )
            PolicyAction.ALLOW -> return
        }
        val builder = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(openAppIntent(context))
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(if (channel == CHANNEL_CRITICAL) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW)

        val userMayAct = decision.action == PolicyAction.ASK_USER ||
            decision.action == PolicyAction.BLOCK_AND_QUARANTINE
        // P0 emergency brake: the event flag AND the authoritative safelist must both clear
        // before a Remove / 24h-allow action is offered.
        val systemPackage = event.isSystemPackage ||
            (!packageName.isNullOrBlank() && SystemPackageSafelist.isSystemPackage(context, packageName))
        if (userMayAct && !packageName.isNullOrBlank() && !systemPackage) {
            builder.addAction(
                R.drawable.ic_stat_shield,
                context.getString(R.string.autopilot_allow_24h),
                actionIntent(context, AutopilotActionReceiver.ACTION_ALLOW, packageName, recordId)
            )
            builder.addAction(
                R.drawable.ic_stat_shield,
                context.getString(R.string.action_uninstall),
                actionIntent(context, AutopilotActionReceiver.ACTION_UNINSTALL, packageName, recordId)
            )
        }
        notify(context, notificationId, builder.build())
    }

    fun showDigest(context: Context, digest: AutopilotDigest) {
        ensureChannels(context)
        val body = context.getString(
            R.string.autopilot_digest_body,
            digest.decisions,
            digest.contained,
            digest.prompts
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_DIGEST)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(context.getString(R.string.autopilot_digest_title))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(openAppIntent(context))
            .setAutoCancel(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
        notify(context, ID_DIGEST, notification)
    }

    private fun actionIntent(context: Context, action: String, packageName: String, recordId: String?): PendingIntent {
        val intent = Intent(context, AutopilotActionReceiver::class.java).apply {
            this.action = action
            putExtra(AutopilotActionReceiver.EXTRA_PACKAGE, packageName)
            putExtra(AutopilotActionReceiver.EXTRA_RECORD_ID, recordId)
        }
        val requestCode = packageName.hashCode() xor action.hashCode()
        return PendingIntent.getBroadcast(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun packageLabel(context: Context, packageName: String): String = try {
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        context.packageManager.getApplicationLabel(info).toString().ifBlank { packageName }
    } catch (_: Exception) {
        packageName
    }

    private fun openAppIntent(context: Context): PendingIntent? {
        val intent = Intent(context, MainActivity::class.java).addFlags(
            Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        )
        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun notify(context: Context, id: Int, notification: android.app.Notification) {
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return
        try {
            NotificationManagerCompat.from(context).notify(id, notification)
        } catch (_: SecurityException) {
            // Notifications are optional; overlay/full-screen fallback is handled separately.
        } catch (_: RuntimeException) {
            // OEM notification errors must not interrupt a policy decision.
        }
    }

    private data class Quad(val title: String, val body: String, val channel: String, val id: Int)

    private const val ID_CRITICAL = 4401
    private const val ID_INFO = 4500
    private const val ID_DIGEST = 4601
}

class AutopilotActionReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.getStringExtra(EXTRA_PACKAGE)?.takeIf { it.isNotBlank() } ?: return
        val recordId = intent.getStringExtra(EXTRA_RECORD_ID)
        when (intent.action) {
            ACTION_ALLOW -> QuarantineUserActions.allowFor24Hours(context, packageName, recordId)
            ACTION_UNINSTALL -> {
                val uninstall = QuarantineUserActions.uninstallIntent(context, packageName, recordId) ?: return
                org.xsecurity.scanner.quarantine.QuarantinePendingActionStore.setUninstall(context, packageName, recordId)
                runCatching { context.startActivity(uninstall) }
            }
        }
    }

    companion object {
        const val ACTION_ALLOW = "org.xsecurity.scanner.autopilot.ALLOW_24H"
        const val ACTION_UNINSTALL = "org.xsecurity.scanner.autopilot.UNINSTALL"
        const val EXTRA_PACKAGE = "autopilot_package"
        const val EXTRA_RECORD_ID = "autopilot_record_id"
    }
}
