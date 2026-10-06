package org.xsecurity.scanner.autopilot

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/** Daily aggregate-only digest. Audit details and screen content are never included. */
class AutopilotDigestWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val start = now - TimeUnit.HOURS.toMillis(24)
        val digest = AutopilotDigest.from(AuditLog.read(applicationContext, 1_000), start, now)
        if (digest.decisions > 0) AutopilotNotifications.showDigest(applicationContext, digest)
        Result.success()
    }
}

object AutopilotDigestScheduler {
    const val WORK_NAME = "xsec_autopilot_daily_digest"

    fun schedule(context: Context) {
        val request = PeriodicWorkRequestBuilder<AutopilotDigestWorker>(24, TimeUnit.HOURS).build()
        runCatching {
            WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
