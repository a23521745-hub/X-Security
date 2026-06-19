package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.WorkerParameters
import org.xsecurity.scanner.engine.ApkScannerEngine

class ApkScanWorker(
    appContext: Context,
    workerParams: WorkerParameters,
    private val scannerEngine: ApkScannerEngine = ApkScannerEngine()
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val apkPath = inputData.getString(KEY_APK_PATH) ?: return Result.failure()
        val yaraPath = inputData.getString(KEY_YARA_PATH) ?: return Result.failure()
        val clamDbPath = inputData.getString(KEY_CLAM_DB_PATH) ?: return Result.failure()

        val result = scannerEngine.scan(apkPath, yaraPath, clamDbPath)

        return Result.success(
            Data.Builder()
                .putString(KEY_FILE_PATH, result.filePath)
                .putBoolean(KEY_INFECTED, result.isInfected)
                .putStringArray(KEY_YARA_MATCHES, result.yaraMatches.toTypedArray())
                .putStringArray(KEY_CLAM_MATCHES, result.clamAvMatches.toTypedArray())
                .build()
        )
    }

    companion object {
        const val KEY_APK_PATH = "apk_path"
        const val KEY_YARA_PATH = "yara_path"
        const val KEY_CLAM_DB_PATH = "clam_db_path"

        const val KEY_FILE_PATH = "file_path"
        const val KEY_INFECTED = "infected"
        const val KEY_YARA_MATCHES = "yara_matches"
        const val KEY_CLAM_MATCHES = "clam_matches"
    }
}
