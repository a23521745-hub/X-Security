package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.R
import org.xsecurity.scanner.community.CommunityStore
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.data.ScanHistoryEntry
import org.xsecurity.scanner.data.ScanHistoryFlaggedApp
import org.xsecurity.scanner.data.ScanHistoryStore
import org.xsecurity.scanner.data.ScanHistoryType
import org.xsecurity.scanner.data.ScanNotifications
import org.xsecurity.scanner.data.ScanStore
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.device.AppScanEntry
import org.xsecurity.scanner.device.DeviceScanStore
import org.xsecurity.scanner.device.DeviceScanSummary
import org.xsecurity.scanner.device.InstallShieldPolicy
import org.xsecurity.scanner.device.InstalledAppsSource
import org.xsecurity.scanner.device.ProtectionSettings
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import java.io.File

/**
 * Kurulum ani kalkani isi: tek bir paketin APK'sini (temel + split) tarar.
 *
 *  - Sessizdir: dashboard'un "taraniyor" durumunu ele gecirmez (kullanicinin
 *    baslattigi taramayla karismasin); yalnizca sonuc bildirimi ve, tehditse,
 *    cihaz tarama listesine (DeviceScanStore) girdi ekler + ScanStore gecmisine yazar.
 *  - Paket yayin ile tarama arasinda kaldirildiysa (loadOne null) sessizce biter.
 *  - Motor yuklenemezse "temiz" DEGIL, dusuk oncelikli hata bildirimi.
 */
class PackageScanWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = try {
        withContext(Dispatchers.IO) { execute() }
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Exception) {
        val packageName = inputData.getString(KEY_PACKAGE).orEmpty()
        notifyFailure(packageName, error.message ?: error.javaClass.simpleName)
        Result.failure()
    }

    private fun execute(): Result {
        val context = applicationContext
        val packageName = inputData.getString(KEY_PACKAGE)
        if (packageName.isNullOrBlank()) return Result.failure()

        val app = InstalledAppsSource.loadOne(context, packageName) ?: return Result.success()

        val yaraFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.YARA)
        val clamFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_AV)
        val hashFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_HASHES)
        val historyType = if (isRealtimeTrigger) ScanHistoryType.REALTIME else ScanHistoryType.INSTALL_SHIELD
        val historyTrigger =
            if (isRealtimeTrigger) ScanHistoryStore.TRIGGER_DOWNLOAD_WATCH
            else ScanHistoryStore.TRIGGER_INSTALL_SHIELD

        val acquired = ScanEngines.acquire(
            yaraFile, clamFile, hashFile,
            CommunityStore.enabledYaraFiles(context),
            CommunityStore.enabledHashFiles(context)
        )
        if (acquired.isFailure) {
            val reason = acquired.exceptionOrNull()?.message ?: context.getString(R.string.engine_unknown_error)
            val message = context.getString(R.string.engine_unavailable, reason)
            notifyFailure(packageName, message)
            recordHistory(
                context = context,
                entry = AppScanEntry(packageName = packageName, label = packageName, status = ScanStatus.FAILED, errorMessage = message),
                title = packageName,
                type = historyType,
                trigger = historyTrigger,
                engineInfo = null
            )
            return if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure()
        }
        val engine = acquired.getOrThrow()
        val engineInfo = EngineInfo.from(engine, yaraFile?.absolutePath, clamFile?.absolutePath, hashFile?.absolutePath)

        val results = app.apkPaths.map { path ->
            try {
                engine.scan(File(path))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                ScanResult.failed(path, error.message ?: error.javaClass.simpleName)
            }
        }
        val entry = DeviceScanSummary.mergeEntry(app, results)

        // Tum tamamlanan kalkan taramalari (temiz/tehdit/hata) gecmise girer.
        recordHistory(
            context = context,
            entry = entry,
            title = context.getString(R.string.shield_result_name, entry.label),
            type = historyType,
            trigger = historyTrigger,
            engineInfo = engineInfo
        )

        ScanNotifications.ensureChannel(context)
        when (InstallShieldPolicy.alertFor(entry, quietWhenClean = ProtectionSettings.quietWhenClean(context))) {
            InstallShieldPolicy.Alert.THREAT -> {
                DeviceScanStore.upsertEntry(context, entry)
                // Gecmis kartinda da gorunsun: tek-uygulama ozeti.
                ScanStore.publishResult(
                    context,
                    DeviceScanSummary.toScanResult(
                        entries = listOf(entry),
                        durationMillis = results.sumOf { it.durationMillis },
                        displayName = context.getString(R.string.shield_result_name, entry.label)
                    )
                )
                ScanNotifications.showInstallThreat(context, entry)
            }
            InstallShieldPolicy.Alert.CLEAN_INFO -> ScanNotifications.showInstallClean(context, entry)
            InstallShieldPolicy.Alert.FAILED_INFO -> notifyFailure(packageName, entry.errorMessage ?: context.getString(R.string.notif_failed_body))
            InstallShieldPolicy.Alert.NONE -> Unit
        }
        return Result.success()
    }

    /**
     * Tetikleyici: normalde [InstallShieldPolicy] yayini (INSTALL_SHIELD). Girdiye
     * [KEY_TRIGGER]=realtime yaziliyorsa (ornek: baska bir koruma yolundan) REALTIME
     * olarak raporlanir; ayrim girdi anahtariyla yapilir.
     */
    private val isRealtimeTrigger: Boolean
        get() = inputData.getString(KEY_TRIGGER) == TRIGGER_REALTIME

    private fun recordHistory(
        context: Context,
        entry: AppScanEntry,
        title: String,
        type: ScanHistoryType,
        trigger: String,
        engineInfo: EngineInfo?
    ) {
        val historyEntry = ScanHistoryEntry(
            timestamp = System.currentTimeMillis(),
            type = type,
            trigger = trigger,
            title = title,
            status = entry.status.name,
            durationMillis = entry.durationMillis,
            bytesScanned = entry.bytesScanned,
            appsScanned = 1,
            appsFlagged = if (entry.isInfected) 1 else 0,
            threatCount = entry.threats.size,
            threats = ScanHistoryStore.threatsOf(entry.threats),
            flaggedApps = if (entry.isInfected) {
                listOf(ScanHistoryFlaggedApp(entry.packageName, entry.label, entry.threats.map { it.name }))
            } else {
                emptyList()
            },
            engineCounters = ScanHistoryStore.counters(engineInfo),
            warnings = entry.errorMessage?.let { listOf(it) } ?: emptyList()
        )
        runCatching { ScanHistoryStore.record(context, historyEntry) }
    }

    private fun notifyFailure(packageName: String, message: String) {
        val context = applicationContext
        ScanNotifications.ensureChannel(context)
        ScanNotifications.showInstallFailed(
            context,
            AppScanEntry(packageName = packageName, label = packageName, status = ScanStatus.FAILED, errorMessage = message)
        )
    }

    companion object {
        const val KEY_PACKAGE = "package_name"
        const val KEY_TRIGGER = "trigger"
        /** Indirme izleme tetikleyicisi (REALTIME); varsayilan INSTALL_SHIELD. */
        const val TRIGGER_REALTIME = "realtime"
        /** Kurulum kalkan yayini (varsayilan). */
        const val TRIGGER_INSTALL_SHIELD = "install_shield"
        private const val MAX_ATTEMPTS = 2
    }
}
