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

    private const val CHANNEL_ID = "ota_updates"
    private const val NOTIFICATION_ID = 40

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.ota_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = context.getString(R.string.ota_channel_desc)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    fun showUpdateAvailable(context: Context, versionName: String) {
        val notification = baseBuilder(context)
            .setContentTitle(context.getString(R.string.ota_notif_new_title))
            .setContentText(
                context.getString(R.string.ota_notif_new_text, versionName)
            )
            .setAutoCancel(true)
            .build()
        notify(context, notification)
    }

    fun showDownloadProgress(context: Context, percent: Int) {
        val notification = baseBuilder(context)
            .setContentTitle(context.getString(R.string.ota_notif_download_title))
            .setContentText(context.getString(R.string.ota_notif_download_text, percent))
            .setProgress(100, percent.coerceIn(0, 100), false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
        notify(context, notification)
    }

    fun showReadyToInstall(context: Context, versionName: String) {
        val notification = baseBuilder(context)
            .setContentTitle(context.getString(R.string.ota_notif_ready_title))
            .setContentText(
                context.getString(R.string.ota_notif_ready_text, versionName)
            )
            .setAutoCancel(true)
            .build()
        notify(context, notification)
    }

    fun showDownloadFailed(context: Context) {
        val notification = baseBuilder(context)
            .setContentTitle(context.getString(R.string.ota_notif_error_title))
            .setContentText(context.getString(R.string.ota_notif_error_text))
            .setAutoCancel(true)
            .build()
        notify(context, notification)
    }

    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
    }

    private fun baseBuilder(context: Context): NotificationCompat.Builder =
        NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_scanner)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppIntent(context))

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
        try {
            manager.notify(NOTIFICATION_ID, notification)
        } catch (security: SecurityException) {
            // Android 13+ (API 33): bildirim izni istenmemis/reddedilmis olabilir.
            // Bildirim kritik olmadigindan sessizce atlanir.
        } catch (error: RuntimeException) {
            // Beklenmedik bildirim hatasi: uygulamayi bozmamak icin yut.
        }
    }
}
