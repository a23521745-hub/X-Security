package org.xsecurity.scanner.device

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.xsecurity.scanner.R
import org.xsecurity.scanner.data.ScanController
import org.xsecurity.scanner.ui.MainActivity
import java.io.File

/**
 * "Her zaman acik" koruma: kalici bildirimli on plan servisi.
 *
 *  - Download/ klasorunu [FileObserver] ile izler; yeni `.apk` yazimi **kapaninca**
 *    (CLOSE_WRITE / MOVED_TO) dosya mevcut tarama hattina ([ScanController.enqueueFromUri])
 *    verilir — yani ayni motor, ayni bildirim, ayni gecmis karti.
 *  - Surec ayakta oldugu icin kurulum ani kalkaninin dinamik kaydi da garanti olur.
 *  - Android 14+: `foregroundServiceType=dataSync`; Android 15 bu ture 6 saatlik ust
 *    sinir koyar — [onTimeout] gelince servis kendini durdurur ve kullaniciya
 *    "korumayi yeniden baslatmak icin dokunun" bildirimi birakir (sessiz calismaya
 *    devam etmis gibi gorunmek yerine).
 *  - Servis hicbir zaman ag kullanmaz; yalnizca yerel dosya olaylarini dinler.
 */
class RealtimeProtectionService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val dedup = DownloadWatchPolicy.Deduplicator()
    private var observer: FileObserver? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel(this)
        // 5 saniye kurali: startForegroundService sonrasi bildirim hemen verilmeli.
        startInForeground()
        InstallShieldReceiver.register(this)
        startWatching()
        running = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        observer?.stopWatching()
        observer = null
        scope.cancel()
        super.onDestroy()
    }

    /** Android 15+: dataSync on plan servisleri icin sistem zaman siniri doldu. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        showPausedNotification(this)
        stopSelf()
    }

    private fun startInForeground() {
        val notification = buildNotification()
        try {
            // Derleme zamani sabiti; ServiceCompat API 29 altinda turu zaten yok sayar.
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } catch (error: Exception) {
            // Android 12+ arka plandan baslatma kisiti veya izin eksigi: sessizce kapan,
            // ayar ekraninda mod "Her zaman acik" kalir ve bir sonraki acilista denenir.
            stopSelf()
        }
    }

    private fun startWatching() {
        val directory = downloadsDirectory()
        if (directory == null || !directory.isDirectory) return
        val handler: (Int, String?) -> Unit = { event, name -> onFileEvent(directory, event, name) }
        observer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Maske acikca FileObserver SDK sabitlerinden kurulmali: lint'in WrongConstant
            // kontrolu baska siniftan gelen sabit zincirini (WATCH_MASK = 0x88) dogrulayamiyor.
            // Izlenen olay seti policy ile ayni:
            // CLOSE_WRITE | MOVED_TO == DownloadWatchPolicy.WATCH_MASK.
            object : FileObserver(directory, FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO) {
                override fun onEvent(event: Int, path: String?) = handler(event, path)
            }
        } else {
            @Suppress("DEPRECATION")
            object : FileObserver(directory.absolutePath, FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO) {
                override fun onEvent(event: Int, path: String?) = handler(event, path)
            }
        }
        runCatching { observer?.startWatching() }
    }

    private fun onFileEvent(directory: File, event: Int, name: String?) {
        if (name == null || !DownloadWatchPolicy.shouldScan(event, name)) return
        val file = File(directory, name)
        if (!file.isFile || file.length() <= 0L) return
        if (!dedup.accept(file.absolutePath, file.length(), file.lastModified(), System.currentTimeMillis())) return
        scope.launch {
            // fromDownloadWatch=true: tarama gecmisi REALTIME (indirme izlemeden) olarak kaydedilir.
            runCatching { ScanController.enqueueFromUri(applicationContext, Uri.fromFile(file), file.name, fromDownloadWatch = true) }
        }
    }

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.protection_notif_title))
            .setContentText(getString(R.string.protection_notif_body))
            .setStyle(NotificationCompat.BigTextStyle().bigText(getString(R.string.protection_notif_body)))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openAppIntent(this))
            .build()

    companion object {
        private const val CHANNEL_ID = "xsec_protection"
        private const val NOTIFICATION_ID = 4301
        private const val PAUSED_NOTIFICATION_ID = 4302
        private const val ACTION_STOP = "org.xsecurity.scanner.action.STOP_PROTECTION"

        @Volatile
        var running: Boolean = false
            private set

        fun start(context: Context) {
            val intent = Intent(context, RealtimeProtectionService::class.java)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (_: Exception) {
                // Arka plandan baslatma kisiti: kullanici uygulamayi actiginda tekrar denenir.
            }
        }

        fun stop(context: Context) {
            runCatching { context.stopService(Intent(context, RealtimeProtectionService::class.java)) }
        }

        /** Izlenen klasor: paylasilan depolamadaki herkese acik Download/. */
        fun downloadsDirectory(): File? = try {
            @Suppress("DEPRECATION")
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        } catch (_: Throwable) {
            null
        }

        /**
         * "Koruma duraklatildi, yeniden baslatmak icin dokunun" bildirimi: sistem zaman
         * siniri (Android 15) ya da acilista baslatma kisiti sonrasi kullaniciyi bilgilendirir.
         */
        fun showPausedNotification(context: Context) {
            ensureChannel(context)
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            val body = context.getString(R.string.protection_notif_paused_body)
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(context.getString(R.string.protection_notif_paused_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setSmallIcon(R.drawable.ic_stat_shield)
                .setAutoCancel(true)
                .setContentIntent(openAppIntent(context))
                .build()
            try {
                manager.notify(PAUSED_NOTIFICATION_ID, notification)
            } catch (_: SecurityException) {
                // Bildirim izni yok: sessizce atla.
            } catch (_: RuntimeException) {
                // Beklenmedik bildirim hatasi: yut.
            }
        }

        fun ensureChannel(context: Context) {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            if (manager.getNotificationChannel(CHANNEL_ID) != null) return
            val channel = NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.protection_notif_channel_name),
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = context.getString(R.string.protection_notif_channel_description)
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }

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
    }
}
