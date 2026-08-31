package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import org.xsecurity.scanner.ota.OtaController
import org.xsecurity.scanner.ota.OtaNotifications
import org.xsecurity.scanner.ota.OtaStore

/**
 * Periyodik (gunde bir) imzali guncelleme kontrolu.
 *
 *  - Ag gereksinimi WorkManager kisitiyla saglanir; baglanti yoksa is ertelenir.
 *  - Sonuc [OtaStore] durumuna yazilir; kullaniciyi rahatsiz etmemek icin
 *    yalnizca gercekten YENI bir surum bulundugunda sessiz bir bildirim cikarilir.
 *  - Hicbir kosulda uygulama bu is yuzunden cokmez: tum istisnalar yakalanir.
 */
class OtaCheckWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = try {
        OtaController.check(applicationContext)
        notifyIfNewUpdate()
        Result.success()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Throwable) {
        // Periyodik kontrol hatasi uygulamayi bozmaz; sessizce bir sonraki
        // periyot (veya kullanicinin manuel kontrolu) denenir.
        Result.failure()
    }

    private fun notifyIfNewUpdate() {
        val state = OtaStore.state.value
        val info = state.available ?: return
        if (state.status != org.xsecurity.scanner.ota.OtaStatus.UPDATE_AVAILABLE) return
        runCatching {
            OtaNotifications.ensureChannel(applicationContext)
            OtaNotifications.showUpdateAvailable(applicationContext, info)
        }
    }
}
