package org.xsecurity.scanner.service

import android.content.Context
import android.content.Intent
import androidx.lifecycle.LifecycleService
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import org.xsecurity.scanner.worker.ApkScanWorker

class ApkScanService : LifecycleService() {


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val apkPath = intent?.getStringExtra(EXTRA_APK_PATH)
        val yaraRulePath = intent?.getStringExtra(EXTRA_YARA_RULE_PATH)
        val clamAvDbPath = intent?.getStringExtra(EXTRA_CLAM_DB_PATH)

        if (!apkPath.isNullOrBlank() && !yaraRulePath.isNullOrBlank() && !clamAvDbPath.isNullOrBlank()) {
            enqueueScan(applicationContext, apkPath, yaraRulePath, clamAvDbPath)
        }

        stopSelf(startId)
        return START_NOT_STICKY
    }

    companion object {
        const val EXTRA_APK_PATH = "extra_apk_path"
        const val EXTRA_YARA_RULE_PATH = "extra_yara_rule_path"
        const val EXTRA_CLAM_DB_PATH = "extra_clam_db_path"

        fun start(
            context: Context,
            apkPath: String,
            yaraRulePath: String,
            clamAvDbPath: String
        ) {
            val intent = Intent(context, ApkScanService::class.java)
                .putExtra(EXTRA_APK_PATH, apkPath)
                .putExtra(EXTRA_YARA_RULE_PATH, yaraRulePath)
                .putExtra(EXTRA_CLAM_DB_PATH, clamAvDbPath)
            context.startService(intent)
        }

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
}
