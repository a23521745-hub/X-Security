package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.R
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.data.ScanController
import org.xsecurity.scanner.data.ScanNotifications
import org.xsecurity.scanner.data.ScanStore
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.engine.ScanResult
import java.io.File

/**
 * Arka plan tarama isi.
 *
 * Duzeltmeler:
 *  - Govde `try/catch` ile sarildi: yakalanmayan exception `CoroutineWorker` icinde
 *    uygulamayi cokertiyordu.
 *  - Motor yuklenemezse "temiz" DEGIL, hata raporlanir (`Result.retry()` / `failure()`).
 *  - `outputData` bilerek kucuk tutuluyor: WorkManager `Data` siniri ~10 KB'dir; uzun
 *    imza listeleri `Data size is too large` ile isiyi patlatiyordu. Tam liste
 *    `ScanStore` uzerinden okunur.
 *  - Ilerleme hem arayuze hem bildirime yazilir (bildirim kisitlamasi nedeniyle yuzde
 *    5'te bir guncellenir).
 *  - Iptalde bildirim temizlenir ve `CancellationException` yutulmadan yukulur.
 */
class ApkScanWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = try {
        withContext(Dispatchers.IO) { execute() }
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Exception) {
        fail(
            filePath = inputData.getString(KEY_APK_PATH).orEmpty(),
            message = error.message ?: error.javaClass.simpleName
        )
    }

    private suspend fun execute(): Result {
        val context = applicationContext
        val apkPath = inputData.getString(KEY_APK_PATH)
        if (apkPath.isNullOrBlank()) {
            return Result.failure(failureData("Missing input: apk_path"))
        }
        val staged = File(apkPath)
        val displayName = inputData.getString(KEY_DISPLAY_NAME) ?: staged.name

        ScanNotifications.ensureChannel(context)
        ScanStore.markScanning(context)

        val yaraFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.YARA)
        val clamFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_AV)

        val acquired = ScanEngines.acquire(yaraFile, clamFile)
        if (acquired.isFailure) {
            val reason = acquired.exceptionOrNull()?.message
                ?: context.getString(R.string.engine_unknown_error)
            return fail(filePath = apkPath, message = context.getString(R.string.engine_unavailable, reason))
        }

        val engine = acquired.getOrThrow()
        ScanStore.publishEngine(
            EngineInfo.from(engine, yaraFile?.absolutePath, clamFile?.absolutePath)
        )

        var lastNotifiedPercent = -1
        val result = try {
            engine.scan(staged) { fraction ->
                ScanStore.setProgress(fraction)
                val percent = (fraction * 100f).toInt()
                if (percent - lastNotifiedPercent >= PROGRESS_NOTIFY_STEP || percent >= 100) {
                    lastNotifiedPercent = percent
                    ScanNotifications.showProgress(context, displayName, fraction)
                }
            }
        } catch (cancelled: CancellationException) {
            ScanNotifications.cancel(context)
            ScanStore.reset()
            throw cancelled
        }

        ScanStore.publishResult(context, result)
        ScanNotifications.showResult(context, result)

        // Kullanicinin dosyasini kopya olarak diskte birakmiyoruz; hata halinde retry
        // icin kopya korunur.
        if (result.isComplete && staged.parentFile == ScanController.stagingDirectory(context)) {
            runCatching { staged.delete() }
        }

        return if (result.isComplete) {
            Result.success(summaryData(result))
        } else if (runAttemptCount < MAX_ATTEMPTS) {
            // Sonuc state/bildirim tarafi zaten yayinlandi; burada yalnizca WorkManager
            // kararini veriyoruz (retry sirasinda kopya dosya korunur).
            Result.retry()
        } else {
            Result.failure(failureData(result.errorMessage ?: "The scan could not be completed."))
        }
    }

    /** Hata yolini tek yerden yurutmek icin: state + bildirim + WorkManager sonucu. */
    private fun fail(filePath: String, message: String): Result {
        val context = applicationContext
        val failed = ScanResult.failed(filePath, message)
        ScanStore.publishResult(context, failed)
        ScanNotifications.showResult(context, failed)
        return if (runAttemptCount < MAX_ATTEMPTS) {
            Result.retry()
        } else {
            Result.failure(failureData(message))
        }
    }

    /** UI bu kucuk ozeti okur; ayrintili liste ScanStore'da. */
    private fun summaryData(result: ScanResult): Data = Data.Builder()
        .putString(KEY_FILE_PATH, result.fileName)
        .putString(KEY_SHA256, result.sha256)
        .putBoolean(KEY_INFECTED, result.isInfected)
        .putInt(KEY_THREAT_COUNT, result.threats.size)
        .putLong(KEY_BYTES_SCANNED, result.bytesScanned)
        .putLong(KEY_DURATION_MILLIS, result.durationMillis)
        .putStringArray(
            KEY_THREAT_NAMES,
            result.threats.take(MAX_NAMES_IN_OUTPUT).map { "${it.engine}:${it.name}" }.toTypedArray()
        )
        .putBoolean(KEY_TRUNCATED, result.engineWarnings.isNotEmpty())
        .build()

    private fun failureData(message: String): Data = Data.Builder()
        .putString(KEY_ERROR, message.take(400))
        .build()

    companion object {
        const val KEY_APK_PATH = "apk_path"
        const val KEY_DISPLAY_NAME = "display_name"
        const val KEY_SHA256 = "sha256"

        const val KEY_FILE_PATH = "file_path"
        const val KEY_INFECTED = "infected"
        const val KEY_THREAT_COUNT = "threat_count"
        const val KEY_THREAT_NAMES = "threat_names"
        const val KEY_BYTES_SCANNED = "bytes_scanned"
        const val KEY_DURATION_MILLIS = "duration_millis"
        const val KEY_TRUNCATED = "has_warnings"
        const val KEY_ERROR = "error"

        private const val MAX_ATTEMPTS = 2
        private const val MAX_NAMES_IN_OUTPUT = 8
        private const val PROGRESS_NOTIFY_STEP = 5
    }
}
