package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.ota.ApkDownloader
import org.xsecurity.scanner.ota.OtaController
import org.xsecurity.scanner.ota.OtaNotifications
import org.xsecurity.scanner.ota.OtaStore
import org.xsecurity.scanner.ota.UpdateInfo
import java.io.File

/**
 * Gunceleme APK'sini indirip dogrulayan arka plan isi.
 *
 *  - Indirme + SHA-256/boyut dogrulamasi akista yapilir (bkz. [ApkDownloader]).
 *  - Basarili sonucta durum READY_TO_INSTALL olur ve bir bildirim gosterilir; ancak
 *    kurulum **hicbir zaman otomatik baslamaz**. Kullanici bildirime/uygulamaya dokunup
 *    "Kur"a basinca sistem paket ekrani acilir.
 *  - Hata/cancel yollarinda kismi dosya silinir, `Result.failure/retry` doner.
 */
class OtaDownloadWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = try {
        withContext(Dispatchers.IO) { execute() }
    } catch (cancelled: CancellationException) {
        OtaStore.reset()
        throw cancelled
    } catch (error: Exception) {
        OtaStore.error(error.message ?: "Güncelleme indirilemedi.")
        Result.failure(failureData(error.message ?: "indirme hatası"))
    }

    private fun execute(): Result {
        val context = applicationContext
        val raw = inputData.getString(KEY_INFO_JSON)
        if (raw.isNullOrBlank()) {
            return Result.failure(failureData("Eksik girdi: güncelleme bilgisi"))
        }
        val info = try {
            UpdateInfo.fromJson(raw)
        } catch (error: Throwable) {
            return Result.failure(failureData("Güncelleme bilgisi okunamadı: ${error.message}"))
        }

        OtaNotifications.ensureChannel(context)
        OtaStore.downloading(info)
        OtaNotifications.showDownloading(context, 0f)

        val target = File(OtaController.downloadDirectory(context), "update-${info.versionCode}.apk")
        runCatching { if (target.exists()) target.delete() }

        val outcome = ApkDownloader(OtaController.currentConfig()).download(info, target) { fraction ->
            OtaStore.setDownloadProgress(fraction)
            OtaNotifications.showDownloading(context, fraction)
        }

        return when (outcome) {
            is ApkDownloader.Result.Success -> {
                OtaStore.readyToInstall(info, outcome.file.absolutePath)
                OtaNotifications.showReadyToInstall(context, info)
                Result.success(
                    Data.Builder()
                        .putString(KEY_APK_PATH, outcome.file.absolutePath)
                        .putString(KEY_SHA256, outcome.sha256)
                        .putLong(KEY_BYTES, outcome.bytes)
                        .build()
                )
            }
            is ApkDownloader.Result.Failure -> {
                runCatching { target.delete() }
                OtaStore.error(outcome.message)
                OtaNotifications.showError(context, outcome.message)
                if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure(failureData(outcome.message))
            }
        }
    }

    private fun failureData(message: String): Data =
        Data.Builder().putString(KEY_ERROR, message.take(400)).build()

    companion object {
        const val KEY_INFO_JSON = "info_json"
        const val KEY_APK_PATH = "apk_path"
        const val KEY_SHA256 = "sha256"
        const val KEY_BYTES = "bytes"
        const val KEY_ERROR = "error"

        private const val MAX_ATTEMPTS = 2
    }
}
