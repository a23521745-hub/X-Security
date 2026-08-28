package org.xsecurity.scanner.data

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.xsecurity.scanner.R
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus

/**
 * Tarama ilerlemesi ve sonuc bildirimi.
 *
 * Onceki surumde worker sonuclari yalnizca `outputData`'ya yaziyordu; UI sonucu
 * okumadigi icin taramanin cikti kayboluyordu. Bildirim, uygulamanin "taramam
 * bitti, su bulundu" diyebildigi tek kalici kanaldi.
 */
object ScanNotifications {

    private const val CHANNEL_ID = "scan_progress"
    private const val NOTIFICATION_ID = 10

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.scan_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = context.getString(R.string.scan_channel_desc)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    fun showScanStarted(context: Context, targetName: String) {
        val notification = builder(context)
            .setContentTitle(context.getString(R.string.scan_notif_started_title))
            .setContentText(context.getString(R.string.scan_notif_started_text, targetName))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
        notify(context, notification)
    }

    fun showScanProgress(context: Context, percent: Int) {
        val notification = builder(context)
            .setContentTitle(context.getString(R.string.scan_notif_progress_title))
            .setContentText(context.getString(R.string.scan_notif_progress_text, percent))
            .setProgress(100, percent.coerceIn(0, 100), false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
        notify(context, notification)
    }

    fun showScanResult(context: Context, summary: String) {
        val notification = builder(context)
            .setContentTitle(context.getString(R.string.scan_notif_done_title))
            .setContentText(summary)
            .setAutoCancel(true)
            .build()
        notify(context, notification)
    }

    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
    }

    private fun builder(context: Context): NotificationCompat.Builder =
        NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_scanner)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppIntent(context))

    private fun openAppIntent(context: Context): PendingIntent {
        val launch = Intent(context, org.xsecurity.scanner.ui.MainActivity::class.java).apply {
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
        // API 33+ kullanicisi izin vermediyse sessizce atla; crash yerine izlenemez bildirim.
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
