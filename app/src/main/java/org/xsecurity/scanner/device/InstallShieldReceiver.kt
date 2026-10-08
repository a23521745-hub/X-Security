package org.xsecurity.scanner.device

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import org.xsecurity.scanner.data.ScanController

/**
 * Kurulum ani kalkani: `PACKAGE_ADDED` / `PACKAGE_REPLACED` geldiginde yeni paketin
 * APK'sini hemen tarama kuyruguna koyar (tarama [org.xsecurity.scanner.worker.PackageScanWorker]).
 *
 * Iki kayit yolu birlikte kullanilir:
 *  1. **Manifest** kaydi (`<receiver>`): sistemin bu yayini arka plandaki uygulamalara
 *     iletmesine izin verdigi her durumda (OEM, eski API, gelecekteki muafiyet) calisir.
 *  2. **Dinamik** kayit ([register]): API 26+ arka plan kisitlamalari paket yayinlarini
 *     manifest alicilarina iletmez; surec ayaktayken (uygulama acik, WorkManager isi,
 *     Asama C'deki on plan servisi) bu kayit yayini garanti eder.
 *
 * Alici ince tutulur: karar [InstallShieldPolicy]'de, is worker'da.
 */
class InstallShieldReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (!ProtectionSettings.installShieldEnabled(ProtectionSettings.mode(context))) return
        val verdict = InstallShieldPolicy.decide(
            action = intent.action,
            packageName = InstallShieldPolicy.packageNameFromData(intent.dataString),
            replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false),
            selfPackage = context.packageName
        )
        if (verdict != InstallShieldPolicy.Verdict.SCAN) return
        val packageName = InstallShieldPolicy.packageNameFromData(intent.dataString) ?: return
        ScanController.enqueuePackageScan(context.applicationContext, packageName)
    }

    companion object {
        @Volatile
        private var dynamic: InstallShieldReceiver? = null

        /** Surec omru boyunca gecerli dinamik kayit; tekrar cagrilmasi zararsizdir. */
        fun register(context: Context) {
            if (dynamic != null) return
            synchronized(this) {
                if (dynamic != null) return
                val receiver = InstallShieldReceiver()
                val filter = IntentFilter().apply {
                    addAction(Intent.ACTION_PACKAGE_ADDED)
                    addAction(Intent.ACTION_PACKAGE_REPLACED)
                    addDataScheme("package")
                }
                val app = context.applicationContext
                try {
                    // Sistem yayini: RECEIVER_EXPORTED (API 33+ zorunlu bayrak; Compat eskiyi yonetir).
                    ContextCompat.registerReceiver(app, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
                    dynamic = receiver
                } catch (_: Exception) {
                    // Kayit basarisizsa manifest alicisi tek yol olarak kalir.
                }
            }
        }

        fun unregister(context: Context) {
            val receiver = dynamic ?: return
            synchronized(this) {
                dynamic = null
                runCatching { context.applicationContext.unregisterReceiver(receiver) }
            }
        }

        val isRegistered: Boolean get() = dynamic != null
    }
}
