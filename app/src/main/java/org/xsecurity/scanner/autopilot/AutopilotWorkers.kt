package org.xsecurity.scanner.autopilot

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class AutopilotEventWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val event = SecurityEventCodec.decode(inputData) ?: return@withContext Result.failure()
        try {
            when (AutopilotRuntime.evaluate(applicationContext, event)) {
                ActionDispatcher.Result.AUDIT_FAILED, ActionDispatcher.Result.ACTION_FAILED -> Result.retry()
                ActionDispatcher.Result.EXECUTED -> Result.success()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            Result.retry()
        }
    }
}

class AutopilotPulseWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = try {
        withContext(Dispatchers.IO) { AutopilotScheduler.pulse(applicationContext) }
        Result.success()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        Result.retry()
    }
}
