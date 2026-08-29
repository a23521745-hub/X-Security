package org.xsecurity.scanner.definitions

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
 * Tanim paketi kurulum bildirimleri.
 *
 * APK guncellemesinden farki: imzali tanim paketinin kurulmasi kullanici onayı
 * gerektirmez (dosya, uygulamanin kendi alanina atomik yazilir). Bildirim yalnizca
 * "kuruldu" / "kurulamadi" bilgisidir; dokununca uygulama acilir.
 */
object DefinitionsNotifications {

    private const val CHANNEL_ID = "xsec_definitions_status"
    private const val NOTIFICATION_ID = 4212

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.def_notif_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = context.getString(R.string.def_notif_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    fun showInstalled(
        context: Context,
        defVersion: Int,
        yaraRules: Int,
        clamSignatures: Int,
        hashSignatures: Int = 0
    ) {
        ensureChannel(context)
        val body = context.getString(
            R.string.def_notif_installed_body,
            defVersion,
            yaraRules,
            clamSignatures,
            hashSignatures
        )
        val notification = base(context)
            .setContentTitle(context.getString(R.string.def_notif_installed_title))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(false)
            .setAutoCancel(true)
            .setSilent(true)
            .build()
        notify(context, notification)
    }

    fun showError(context: Context, message: String) {
        ensureChannel(context)
        val notification = base(context)
            .setContentTitle(context.getString(R.string.def_notif_error_title))
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(false)
            .setAutoCancel(true)
            .build()
        notify(context, notification)
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
        try {
            manager.notify(NOTIFICATION_ID, notification)
        } catch (security: SecurityException) {
            // Android 13+ (API 33): bildirim izni istenmemis/reddedilmis olabilir.
            // Lint (MissingPermission) acik SecurityException ele alinmasini istiyor;
            // bildirim kritik olmadigindan sessizce atlanir.
        } catch (error: RuntimeException) {
            // Beklenmedik bildirim hatasi: uygulamayi bozmamak icin yut.
        }
    }
}
