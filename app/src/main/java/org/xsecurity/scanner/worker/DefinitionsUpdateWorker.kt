package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import org.xsecurity.scanner.community.CommunityUpdater
import org.xsecurity.scanner.definitions.DefinitionsController
import org.xsecurity.scanner.definitions.DefinitionsNotifications

/**
 * Periyodik (gunde bir) VEYA manuel tetiklenen tanim paketi guncellemesi.
 *
 *  - Kontrol + indirme + dogrulama + kurulum akisinin tamami
 *    [DefinitionsController.checkAndInstall] icindedir.
 *  - Ag hatalarinda (CATCH kosullari) WorkManager artan beklemeyle tekrar dener;
 *    denemeler bittiginde son hata bir bildirimle kullaniciya bildirilir.
 *  - Uygulama bu is yuzunden asla cokmez: tum istisnalar yakalanir.
 */
class DefinitionsUpdateWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = try {
        // Imzali kanal kontrolunden sonra dogrudan topluluk kaynaklari da tazelenir.
        // Topluluk hatasi imzali kanalin sonucunu BOZMAMALI: ayri try, hata yalnizca
        // kaynak durumuna yazilir.
        runCatching { CommunityUpdater.refreshAll(applicationContext) }
        when (val outcome = DefinitionsController.checkAndInstall(applicationContext)) {
            is DefinitionsController.Outcome.Error -> {
                if (runAttemptCount < MAX_ATTEMPTS) {
                    Result.retry()
                } else {
                    runCatching {
                        DefinitionsNotifications.showError(applicationContext, outcome.message)
                    }
                    Result.failure()
                }
            }
            else -> Result.success()
        }
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Throwable) {
        if (runAttemptCount < MAX_ATTEMPTS) {
            Result.retry()
        } else {
            runCatching {
                DefinitionsNotifications.showError(
                    applicationContext,
                    error.message ?: "Tanim paketi guncellenemedi."
                )
            }
            Result.failure()
        }
    }

    companion object {
        private const val MAX_ATTEMPTS = 3
    }
}
