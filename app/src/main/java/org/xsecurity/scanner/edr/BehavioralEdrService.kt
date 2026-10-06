package org.xsecurity.scanner.edr

import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import org.xsecurity.scanner.R
import org.xsecurity.scanner.ui.MainActivity
import java.util.concurrent.Executor

/**
 * Rootless davranışsal EDR: gerçek zamanlı kamera/mikrofon izleyici.
 *
 *  - `AppOpsManager.OnOpActiveChangedListener` ([EdrAppOpsWatcher]) ile
 *    `OPSTR_CAMERA` / `OPSTR_RECORD_AUDIO` işlemlerinin aktifleşmesini dinler
 *    (olay-güdümlü; pil dostu, kök gerektirmez, polling yok). Dinleyici arayüzü
 *    SDK'da API 30+'ta public olduğu için ayrı bir `@RequiresApi(30)` sınıfta
 *    tutulur ve yalnızca API 30+'ta oluşturulur (minSdk 26'da lint + VerifyError
 *    güvenliği).
 *  - Aktifleşen paketin ön/arka plan durumu `ActivityManager` üzerinden
 *    (`RunningAppProcessInfo.importance != IMPORTANCE_FOREGROUND`), ekran
 *    durumu `PowerManager.isInteractive` ile çözülür; karar saf
 *    [EdrTriggerPolicy]'dedir.
 *  - Arka planda (veya ekran kapalıyken) erişimde yüksek öncelikli uyarı
 *    bildirimi (`IMPORTANCE_HIGH`) + `Log.w("XSecurityEDR", ...)` kaydı.
 *
 * Bilinen platform sınırları (arıza değil, Android kısıtı):
 *  - `startWatchingActive` API 30+ gerektirir; API 26-29'da servis çalışır ama
 *    izleme pasiftir (log ile belirtilir).
 *  - `WATCH_APPOPS` izni imza-seviyesidir ve rootless uygulamalara verilmez;
 *    bu olmadan sistem geri çağrıları **yalnızca kendi UID'miz** için üretir.
 *    Servis yine de tam şartnameye uygun yazılmıştır: ayrıcalıklı/sistem
 *    kurulumunda tüm paketleri izler, normal kurulumda kendi UID'mizi izler
 *    (X-Security kamera/mikrofon kullanmadığı için buradaki her aktifleşme
 *    zaten şüphelidir).
 *  - `getRunningAppProcesses()` API 26+ üçüncü parti süreçleri listelemez;
 *    bulunamayan paket arka plan sayılır (fail-closed).
 *
 * Yaşam döngüsü [org.xsecurity.scanner.device.RealtimeProtectionService] ile
 * aynıdır (ön plan servisi, `dataSync` türü — depodaki kanıtlanmış kalıp):
 * "Her zaman açık" koruma modunda çalışır, diğer modlarda durur. Böylece
 * "Sadece kurulum anı" modunun "kalıcı bildirim yok" sözü bozulmaz.
 */
class BehavioralEdrService : Service() {

    private val dedup = EdrTriggerPolicy.Deduplicator()

    /**
     * API 30+ dinleyici sarmalayıcısı ([EdrAppOpsWatcher]) — `Any?` tutulur ki
     * bu sınıfın hiçbir üyesi API 30 türüne derleme-zamanı bağı kurmasın.
     * Yalnızca API 30+'ta null-dışı olur; cast hep `@RequiresApi(30)` kodda.
     */
    private var watcher: Any? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannels(this)
        // 5 saniye kuralı: startForegroundService sonrası bildirim hemen verilmeli.
        startInForeground()
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
        stopWatching()
        super.onDestroy()
    }

    /** Android 15+: dataSync ön plan servisleri için sistem zaman sınırı doldu. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        showPausedNotification(this)
        stopSelf()
    }

    private fun startWatching() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            Log.i(
                EdrTriggerPolicy.TAG,
                "AppOps active watching requires API 30+; EDR dormant on API " +
                    "${Build.VERSION.SDK_INT}"
            )
            return
        }
        startWatchingApi30()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun startWatchingApi30() {
        val ops = runCatching { getSystemService(AppOpsManager::class.java) }.getOrNull()
        if (ops == null) {
            Log.w(EdrTriggerPolicy.TAG, "AppOpsManager unavailable; EDR cannot watch")
            return
        }
        try {
            // Framework sabitleri kullanılır; değerler EdrTriggerPolicy'deki aynalarla aynıdır.
            val newWatcher = EdrAppOpsWatcher(
                ops,
                mainExecutor,
                arrayOf(AppOpsManager.OPSTR_CAMERA, AppOpsManager.OPSTR_RECORD_AUDIO),
                ::handleOpActive
            )
            newWatcher.start()
            watcher = newWatcher
        } catch (error: Exception) {
            Log.w(EdrTriggerPolicy.TAG, "startWatchingActive failed: ${error.message}")
        }
    }

    private fun stopWatching() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            watcher = null
            return
        }
        stopWatchingApi30()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun stopWatchingApi30() {
        val current = watcher as? EdrAppOpsWatcher
        watcher = null
        if (current != null) runCatching { current.stop() }
    }

    private fun handleOpActive(op: String?, packageName: String?, active: Boolean) {
        if (!active || packageName.isNullOrEmpty()) return
        if (!EdrTriggerPolicy.isWatchedOp(op)) return
        // Not: ayrıcalıksız kurulumda geri çağrılar yalnızca kendi UID'miz için
        // gelir; X-Security kamera/mikrofon kullanmadığı için kendi paketimiz
        // dahil her aktifleşme değerlendirilir (atlama yok).
        val importance = importanceOf(packageName) ?: EdrTriggerPolicy.IMPORTANCE_UNKNOWN
        val interactive = isScreenInteractive()
        if (!EdrTriggerPolicy.shouldAlert(op, true, importance, interactive)) {
            Log.i(
                EdrTriggerPolicy.TAG,
                "Foreground ${EdrTriggerPolicy.sensorLabel(op)} use by $packageName (ignored)"
            )
            return
        }
        if (!dedup.accept("$packageName|$op", System.currentTimeMillis())) return
        Log.w(EdrTriggerPolicy.TAG, "Suspicious access by: $packageName")
        showAlert(this, packageName, op, interactive)
    }

    /** Paketin işlem önemi; liste kısıtlıysa null (çağıran fail-closed sayar). */
    private fun importanceOf(packageName: String): Int? {
        val processes = runCatching {
            getSystemService(ActivityManager::class.java)?.runningAppProcesses
        }.getOrNull() ?: return null
        for (info in processes) {
            if (info.pkgList?.contains(packageName) == true) return info.importance
        }
        return null
    }

    private fun isScreenInteractive(): Boolean =
        runCatching { getSystemService(PowerManager::class.java)?.isInteractive }
            .getOrNull() ?: true

    private fun startInForeground() {
        val notification = buildServiceNotification()
        try {
            // Depodaki kanıtlanmış kalıp (bkz. RealtimeProtectionService):
            // ServiceCompat API 29 altında türü zaten yok sayar.
            ServiceCompat.startForeground(
                this,
                SERVICE_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } catch (error: Exception) {
            // Android 12+ arka plandan başlatma kısıtı veya izin eksiği: sessizce kapan.
            stopSelf()
        }
    }

    private fun buildServiceNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_SERVICE_ID)
            .setContentTitle(getString(R.string.edr_service_title))
            .setContentText(getString(R.string.edr_service_body))
            .setStyle(NotificationCompat.BigTextStyle().bigText(getString(R.string.edr_service_body)))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openAppIntent(this))
            .build()

    companion object {
        private const val CHANNEL_SERVICE_ID = "xsec_edr_service"
        private const val CHANNEL_ALERT_ID = "xsec_edr_alert"
        private const val SERVICE_NOTIFICATION_ID = 4401
        private const val PAUSED_NOTIFICATION_ID = 4402
        private const val ALERT_ID_BASE = 44100
        private const val ACTION_STOP = "org.xsecurity.scanner.action.STOP_EDR"

        @Volatile
        var running: Boolean = false
            private set

        fun start(context: Context) {
            val intent = Intent(context, BehavioralEdrService::class.java)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (_: Exception) {
                // Arka plandan başlatma kısıtı: kullanıcı uygulamayı açtığında tekrar denenir.
            }
        }

        fun stop(context: Context) {
            runCatching { context.stopService(Intent(context, BehavioralEdrService::class.java)) }
        }

        /**
         * Yüksek öncelikli arka plan erişim uyarısı (şartname metni):
         * başlık + "[paket] uygulaması ekran kapalıyken / arka plandayken
         * [Camera/Microphone] erişimi sağladı!".
         */
        fun showAlert(context: Context, packageName: String, op: String?, screenInteractive: Boolean) {
            // Dashboard kartindaki 24 saatlik sayac; hatasi bildirimi engellemez.
            runCatching { EdrAlertStore.record(context) }
            ensureChannels(context)
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            val sensor = context.getString(
                if (op == AppOpsManager.OPSTR_RECORD_AUDIO) {
                    R.string.edr_sensor_microphone
                } else {
                    R.string.edr_sensor_camera
                }
            )
            val whenWord = context.getString(
                if (screenInteractive) R.string.edr_context_background else R.string.edr_context_screen_off
            )
            val body = context.getString(R.string.edr_alert_body, packageName, whenWord, sensor)
            val notification = NotificationCompat.Builder(context, CHANNEL_ALERT_ID)
                .setContentTitle(context.getString(R.string.edr_alert_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setSmallIcon(R.drawable.ic_stat_shield)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setContentIntent(openAppIntent(context))
                .build()
            try {
                manager.notify(alertNotificationId(packageName, op), notification)
            } catch (_: SecurityException) {
                // Bildirim izni yok: sessizce atla.
            } catch (_: RuntimeException) {
                // Beklenmedik bildirim hatası: yut.
            }
        }

        /** Paket+işlem başına kararlı, servis bildirimiyle çakışmayan kimlik. */
        fun alertNotificationId(packageName: String, op: String?): Int =
            ALERT_ID_BASE + ((packageName.hashCode() * 31 + (op?.hashCode() ?: 0)) and 0x7FFF)

        /**
         * "İzleme duraklatıldı, yeniden başlatmak için dokunun" bildirimi: sistem zaman
         * sınırı (Android 15) sonrası kullanıcıyı bilgilendirir.
         */
        fun showPausedNotification(context: Context) {
            ensureChannels(context)
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            val body = context.getString(R.string.protection_notif_paused_body)
            val notification = NotificationCompat.Builder(context, CHANNEL_SERVICE_ID)
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
                // Beklenmedik bildirim hatası: yut.
            }
        }

        fun ensureChannels(context: Context) {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            if (manager.getNotificationChannel(CHANNEL_SERVICE_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_SERVICE_ID,
                        context.getString(R.string.edr_service_channel_name),
                        NotificationManager.IMPORTANCE_MIN
                    ).apply {
                        description = context.getString(R.string.edr_service_channel_description)
                        setShowBadge(false)
                    }
                )
            }
            if (manager.getNotificationChannel(CHANNEL_ALERT_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ALERT_ID,
                        context.getString(R.string.edr_alert_channel_name),
                        // Şartname: yüksek öncelikli uyarı bildirimi.
                        NotificationManager.IMPORTANCE_HIGH
                    ).apply {
                        description = context.getString(R.string.edr_alert_channel_description)
                        setShowBadge(true)
                    }
                )
            }
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

/**
 * API 30+ AppOps dinleyici sarmalayıcısı.
 *
 * `OnOpActiveChangedListener` arayüzü SDK'da API 30'da public oldu; bu sınıf
 * `@RequiresApi(30)` taşır ve [BehavioralEdrService] onu yalnızca sürüm
 * korumalı koldan oluşturur. Böylece minSdk 26 derlemesi lint-temiz kalır ve
 * eski cihazlarda sınıf-doğrulama (VerifyError) riski oluşmaz.
 */
@RequiresApi(Build.VERSION_CODES.R)
private class EdrAppOpsWatcher(
    private val appOps: AppOpsManager,
    private val executor: Executor,
    private val ops: Array<String>,
    private val onActive: (op: String?, packageName: String?, active: Boolean) -> Unit
) : AppOpsManager.OnOpActiveChangedListener {

    private var started = false

    override fun onOpActiveChanged(op: String, uid: Int, packageName: String, active: Boolean) {
        onActive(op, packageName, active)
    }

    fun start() {
        if (started) return
        appOps.startWatchingActive(ops, executor, this)
        started = true
    }

    fun stop() {
        if (!started) return
        started = false
        runCatching { appOps.stopWatchingActive(this) }
    }
}
