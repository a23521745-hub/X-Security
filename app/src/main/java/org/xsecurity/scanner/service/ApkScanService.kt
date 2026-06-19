package org.xsecurity.scanner.service

import android.content.Context
import androidx.lifecycle.LifecycleService
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import org.xsecurity.scanner.worker.ApkScanWorker

class ApkScanService : LifecycleService() {

    fun enqueueScan(
        context: Context,
        apkPath: String,
        yaraRulePath: String,
        clamAvDbPath: String
    ) {
        val request = OneTimeWorkRequestBuilder<ApkScanWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.NOT_REQUIRED)
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .setInputData(
                Data.Builder()
                    .putString(ApkScanWorker.KEY_APK_PATH, apkPath)
                    .putString(ApkScanWorker.KEY_YARA_PATH, yaraRulePath)
                    .putString(ApkScanWorker.KEY_CLAM_DB_PATH, clamAvDbPath)
                    .build()
            )
            .build()

        WorkManager.getInstance(context).enqueueUniqueWork(
            "apk_scan_$apkPath",
            ExistingWorkPolicy.REPLACE,
            request
        )
    }
}
