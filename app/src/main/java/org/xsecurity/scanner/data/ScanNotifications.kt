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
import org.xsecurity.scanner.device.AppScanEntry
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

    private const val CHANNEL_ID = "xsec_scan_status"
    private const val NOTIFICATION_ID = 4201

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = context.getString(R.string.notif_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    fun showProgress(context: Context, fileName: String, fraction: Float) {
        val percent = (fraction.coerceIn(0f, 1f) * 100f).toInt()
        val notification = base(context)
            .setContentTitle(context.getString(R.string.notif_scanning_title))
            .setContentText(fileName)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setProgress(100, percent, percent <= 0)
            .build()
        notify(context, notification)
    }

    fun showResult(context: Context, result: ScanResult) {
        val title: String
        val body: String
        val importance: Int
        when {
            result.status == ScanStatus.FAILED -> {
                title = context.getString(R.string.notif_failed_title)
                body = result.errorMessage ?: context.getString(R.string.notif_failed_body)
                importance = NotificationManager.IMPORTANCE_DEFAULT
            }
            result.isInfected -> {
                title = context.getString(R.string.notif_threats_title, result.threats.size)
                body = result.threats.take(3).joinToString(", ") { it.name }
                importance = NotificationManager.IMPORTANCE_HIGH
            }
            else -> {
                title = context.getString(R.string.notif_clean_title)
                body = context.getString(R.string.notif_clean_body, result.fileName)
                importance = NotificationManager.IMPORTANCE_LOW
            }
        }
        val builder = base(context)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setOngoing(false)
            .setOnlyAlertOnce(false)
            .setAutoCancel(true)
            .setSmallIcon(R.drawable.ic_stat_shield)
        if (importance >= NotificationManager.IMPORTANCE_HIGH) {
            builder.setPriority(NotificationCompat.PRIORITY_HIGH)
        }
        notify(context, builder.build())
    }

    /**
     * Kurulu uygulama taramasi ozeti. Tehdit varsa yuksek oncelik + ilk enfekte paket
     * icin sistem kaldirma ekranini acan eylem (sessiz kaldirma yok; kullanici onaylar).
     */
    fun showDeviceScanResult(context: Context, entries: List<AppScanEntry>) {
        val infected = entries.filter { it.isInfected }
        val failed = entries.count { it.isFailed }
        val builder = base(context)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(false)
            .setOnlyAlertOnce(false)
            .setAutoCancel(true)
        if (infected.isEmpty()) {
            val body = context.getString(R.string.notif_device_clean_body, entries.size, failed)
            builder.setContentTitle(context.getString(R.string.notif_device_clean_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
        } else {
            val body = infected.take(4).joinToString("\n") { entry ->
                "${entry.label} (${entry.packageName}): " + entry.threats.take(2).joinToString(", ") { it.name }
            }
            builder.setContentTitle(context.getString(R.string.notif_device_threats_title, infected.size))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
            uninstallAction(context, infected.first().packageName)?.let { builder.addAction(it) }
        }
        notify(context, builder.build())
    }

    /** Sistem "uygulamayi kaldir" ekranina goturen eylem; sessiz kaldirma mumkun degildir. */
    fun uninstallAction(context: Context, packageName: String): NotificationCompat.Action? {
        val intent = ScanController.uninstallIntent(packageName)
        val pending = PendingIntent.getActivity(
            context,
            packageName.hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Action.Builder(
            R.drawable.ic_stat_shield,
            context.getString(R.string.action_uninstall),
            pending
        ).build()
    }

    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
    }

    private fun base(context: Context): NotificationCompat.Builder =
        NotificationCompat.Builder(context, CHANNEL_ID)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppIntent(context))
            .setWhen(System.currentTimeMillis())

    private fun openAppIntent(context: Context): PendingIntent? {
        val launch = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return null
        return PendingIntent.getActivity(
            context,
            0,
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
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
            // Lint (MissingPermission) acik SecurityException ele alinmasini istiyor;
            // bildirim kritik olmadigindan sessizce atlanir.
        } catch (error: RuntimeException) {
            // Beklenmedik bildirim hatasi: uygulamayi bozmamak icin yut.
        }
    }
}
