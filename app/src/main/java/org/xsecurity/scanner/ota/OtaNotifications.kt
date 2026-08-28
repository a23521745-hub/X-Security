package org.xsecurity.scanner.ota

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.xsecurity.scanner.R
import org.xsecurity.scanner.ui.MainActivity

/**
 * OTA indirmeye hazir/indiriliyor bildirimleri.
 *
 * Dokunma her zaman uygulamayi ([MainActivity]) acar; kurulum karari orada kullaniciya
 * aittir. Bu kanal hicbir sekilde otomatik kurulum yapmaz.
 */
object OtaNotifications {

    private const val CHANNEL_ID = "xsec_ota_status"
    private const val NOTIFICATION_ID = 4211

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.ota_notif_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = context.getString(R.string.ota_notif_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    fun showDownloading(context: Context, fraction: Float) {
        val percent = (fraction.coerceIn(0f, 1f) * 100f).toInt()
        val notification = base(context)
            .setContentTitle(context.getString(R.string.ota_notif_downloading_title))
            .setContentText(context.getString(R.string.ota_downloading, percent))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setProgress(100, percent, false)
            .build()
        notify(context, notification)
    }

    /**
     * Periyodik kontrolun "yeni surum var" sonucu icin sessiz, dusuk oncelikli
     * bildirim. Uygulamayi acar; indirme/kurulum karari yine kullanicinindir.
     */
    fun showUpdateAvailable(context: Context, info: UpdateInfo) {
        val notification = base(context)
            .setContentTitle(context.getString(R.string.ota_notif_available_title))
            .setContentText(context.getString(R.string.ota_notif_available_body, info.versionName))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(false)
            .setAutoCancel(true)
            .setSilent(true)
            .build()
        notify(context, notification)
    }

    fun showReadyToInstall(context: Context, info: UpdateInfo) {
        val notification = base(context)
            .setContentTitle(context.getString(R.string.ota_notif_ready_title))
            .setContentText(context.getString(R.string.ota_notif_ready_body, info.versionName))
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                context.getString(R.string.ota_notif_ready_body, info.versionName)
            ))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(false)
            .setAutoCancel(true)
            .build()
        notify(context, notification)
    }

    fun showError(context: Context, message: String) {
        val notification = base(context)
            .setContentTitle(context.getString(R.string.ota_notif_error_title))
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(false)
            .setAutoCancel(true)
            .build()
        notify(context, notification)
    }

    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
    }

    private fun base(context: Context): NotificationCompat.Builder =
        NotificationCompat.Builder(context, CHANNEL_ID)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppIntent(context))
            .setWhen(System.currentTimeMillis())

    private fun openAppIntent(context: Context): PendingIntent {
        val launch = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context,
            0,
            launch,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun notify(context: Context, notification: Notification) {
        val manager = NotificationManagerCompat.from(context)
        if (!manager.areNotificationsEnabled()) return
        runCatching { manager.notify(NOTIFICATION_ID, notification) }
    }
}
