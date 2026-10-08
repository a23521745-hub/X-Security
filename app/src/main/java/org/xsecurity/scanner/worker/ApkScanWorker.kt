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
import org.xsecurity.scanner.data.ScanHistoryEntry
import org.xsecurity.scanner.data.ScanHistoryStore
import org.xsecurity.scanner.data.ScanHistoryType
import org.xsecurity.scanner.data.ScanNotifications
import org.xsecurity.scanner.data.ScanStore
import org.xsecurity.scanner.community.CommunityStore
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
        val sourceUri = inputData.getString(KEY_SOURCE_URI)?.takeIf { it.isNotBlank() }
        val historyType = if (isRealtimeTrigger) ScanHistoryType.REALTIME else ScanHistoryType.FILE
        val historyTrigger =
            if (isRealtimeTrigger) ScanHistoryStore.TRIGGER_DOWNLOAD_WATCH else ScanHistoryStore.TRIGGER_FILE_PICKER
        // Record identity: where this scan came from, shown in the quarantine detail view.
        val scanOrigin = if (isRealtimeTrigger) {
            org.xsecurity.scanner.quarantine.QuarantineFormat.ORIGIN_DOWNLOAD_WATCH
        } else {
            org.xsecurity.scanner.quarantine.QuarantineFormat.ORIGIN_FILE_PICKER
        }

        ScanNotifications.ensureChannel(context)
        ScanStore.markScanning(context)

        val yaraFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.YARA)
        val clamFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_AV)
        val hashFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_HASHES)
        val communityYara = CommunityStore.enabledYaraFiles(context)
        val communityHashes = CommunityStore.enabledHashFiles(context)

        val acquired = ScanEngines.acquire(yaraFile, clamFile, hashFile, communityYara, communityHashes)
        if (acquired.isFailure) {
            val reason = acquired.exceptionOrNull()?.message
                ?: context.getString(R.string.engine_unknown_error)
            return fail(
                filePath = apkPath,
                message = context.getString(R.string.engine_unavailable, reason),
                type = historyType,
                trigger = historyTrigger,
                title = displayName
            )
        }

        val engine = acquired.getOrThrow()
        val engineInfo = EngineInfo.from(engine, yaraFile?.absolutePath, clamFile?.absolutePath, hashFile?.absolutePath)
        ScanStore.publishEngine(engineInfo)

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
        if (result.isComplete) {
            val verdict = when {
                result.threats.isNotEmpty() -> org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.KNOWN_BAD
                result.status == org.xsecurity.scanner.engine.ScanStatus.CLEAN -> org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.KNOWN_GOOD
                else -> org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.UNKNOWN
            }
            val autoResult = org.xsecurity.scanner.autopilot.AutopilotRuntime.evaluate(
                context,
                org.xsecurity.scanner.autopilot.SecurityEvent.FileScan(
                    path = staged.absolutePath,
                    sha256 = result.sha256,
                    verdict = verdict,
                    engine = result.threats.map { it.engine }.distinct().sorted().joinToString(",").ifBlank { "signature_set" },
                    sourceUri = sourceUri,
                    origin = scanOrigin
                )
            )
            if (verdict != org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.KNOWN_BAD) {
                // Clean/unknown: we have no business keeping a grant on the user's file.
                org.xsecurity.scanner.quarantine.SourceGrants.release(context, sourceUri)
            }
            val autonomy = org.xsecurity.scanner.autopilot.AutopilotSettings.level(context)
            val decisionText = when {
                verdict == org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.KNOWN_GOOD -> R.string.autopilot_file_clean
                verdict == org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.KNOWN_BAD && autonomy == org.xsecurity.scanner.autopilot.AutonomyLevel.L2 && autoResult == org.xsecurity.scanner.autopilot.ActionDispatcher.Result.EXECUTED -> R.string.autopilot_file_vaulted
                verdict == org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.KNOWN_BAD -> R.string.autopilot_file_ask
                else -> R.string.autopilot_file_ask
            }
            ScanStore.setAutopilotDecision(context.getString(decisionText))
        } else {
            org.xsecurity.scanner.autopilot.AutopilotRuntime.evaluate(
                context,
                org.xsecurity.scanner.autopilot.SecurityEvent.FileScan(
                    path = staged.absolutePath,
                    sha256 = result.sha256,
                    verdict = org.xsecurity.scanner.autopilot.SecuritySignal.Verdict.UNKNOWN,
                    engine = "unavailable",
                    sourceUri = sourceUri,
                    origin = scanOrigin
                )
            )
        }
        ScanNotifications.showResult(context, result)
        recordHistory(
            context = context,
            result = result,
            title = displayName,
            type = historyType,
            trigger = historyTrigger,
            engineInfo = engineInfo
        )

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

    /**
     * Hata yolunu tek yerden yurutmek icin: state + bildirim + gecmis + WorkManager sonucu.
     * [type]/[trigger] verilmezse girdi verisinden (indirme izlemede REALTIME) carpilir.
     */
    private fun fail(
        filePath: String,
        message: String,
        type: ScanHistoryType? = null,
        trigger: String? = null,
        title: String? = null
    ): Result {
        val context = applicationContext
        val failed = ScanResult.failed(filePath, message)
        ScanStore.publishResult(context, failed)
        ScanNotifications.showResult(context, failed)
        recordHistory(
            context = context,
            result = failed,
            title = title ?: (inputData.getString(KEY_DISPLAY_NAME) ?: filePath.substringAfterLast('/')),
            type = type ?: if (isRealtimeTrigger) ScanHistoryType.REALTIME else ScanHistoryType.FILE,
            trigger = trigger
                ?: if (isRealtimeTrigger) ScanHistoryStore.TRIGGER_DOWNLOAD_WATCH
                else ScanHistoryStore.TRIGGER_FILE_PICKER,
            engineInfo = null
        )
        return if (runAttemptCount < MAX_ATTEMPTS) {
            Result.retry()
        } else {
            // Giving up: no verdict, so no reason to keep a grant on the user's original.
            org.xsecurity.scanner.quarantine.SourceGrants.release(context, inputData.getString(KEY_SOURCE_URI))
            Result.failure(failureData(message))
        }
    }

    /** Tamamlanan her dosya taramasi (temiz/tehdit/hata) gecmise tek kayit olarak girer. */
    private fun recordHistory(
        context: Context,
        result: ScanResult,
        title: String,
        type: ScanHistoryType,
        trigger: String,
        engineInfo: EngineInfo?
    ) {
        val entry = ScanHistoryEntry(
            timestamp = System.currentTimeMillis(),
            type = type,
            trigger = trigger,
            title = title,
            status = result.status.name,
            durationMillis = result.durationMillis,
            bytesScanned = result.bytesScanned,
            threatCount = result.threats.size,
            threats = ScanHistoryStore.threatsOf(result.threats),
            engineCounters = ScanHistoryStore.counters(engineInfo),
            warnings = result.engineWarnings + (result.errorMessage?.let { listOf(it) } ?: emptyList())
        )
        runCatching { ScanHistoryStore.record(context, entry) }
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

    /**
     * Tetikleyici: kullanicinin dosya secicisinden gelen taramalar [ScanHistoryType.FILE],
     * "her zaman acik" indirme izlemeden gelenler [ScanHistoryType.REALTIME]. Ayrim
     * [ScanController] tarafindan yazilan [KEY_TRIGGER] girdi anahtariyla yapilir.
     */
    private val isRealtimeTrigger: Boolean
        get() = inputData.getString(KEY_TRIGGER) == TRIGGER_REALTIME

    companion object {
        const val KEY_APK_PATH = "apk_path"
        const val KEY_DISPLAY_NAME = "display_name"
        const val KEY_SHA256 = "sha256"
        const val KEY_TRIGGER = "trigger"
        /** URI of the user's original file (content:// or file://); the staged copy is only what we scan. */
        const val KEY_SOURCE_URI = "source_uri"

        /** Indirme izleme tetikleyicisi (REALTIME). */
        const val TRIGGER_REALTIME = "realtime"
        /** Kullanici dosya secici (FILE). */
        const val TRIGGER_FILE_PICKER = "file_picker"

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
