package org.xsecurity.scanner.device

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * Yeniden baslatmada "Her zaman acik" korumayi geri getirir. BOOT_COMPLETED,
 * API 26+ manifest alicilarina hala iletilen (muaf) yayinlardandir ve bir on plan
 * servisini baslatmasina izin verilir. Diger modlarda hicbir sey yapmaz.
 */
class ProtectionBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (ProtectionSettings.mode(context) != ProtectionMode.ALWAYS) return
        if (!StorageAccess.hasAllFilesAccess(context)) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            // Android 15: dataSync on plan servisi BOOT_COMPLETED'dan baslatilamaz;
            // kullaniciya "dokunup yeniden baslat" bildirimi birakilir.
            RealtimeProtectionService.showPausedNotification(context)
            return
        }
        RealtimeProtectionService.start(context)
    }
}
