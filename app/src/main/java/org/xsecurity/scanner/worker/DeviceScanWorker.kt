package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.R
import org.xsecurity.scanner.community.CommunityStore
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.data.ScanNotifications
import org.xsecurity.scanner.data.ScanStore
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.device.AppScanEntry
import org.xsecurity.scanner.device.DeviceScanStore
import org.xsecurity.scanner.device.DeviceScanSummary
import org.xsecurity.scanner.device.InstalledApp
import org.xsecurity.scanner.device.InstalledAppPolicy
import org.xsecurity.scanner.device.InstalledAppsSource
import org.xsecurity.scanner.engine.ApkScannerEngine
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.engine.ScanResult
import java.io.File

/**
 * "Tumunu tara": kurulu uygulamalarin APK'larini mevcut motorla sirayla tarar.
 *
 *  - Uygulama-basina sonuc [DeviceScanStore]'a, ozet tek [ScanResult] olarak mevcut
 *    [ScanStore]'a yazilir; boylece "Son tarama"/bulgular kartlari da cihaz
 *    taramasini gosterir.
 *  - Ilerleme hem UI'a hem bildirime yazilir (uygulama basina bir kez).
 *  - Motor yuklenemezse "temiz" DEGIL, hata raporlanir.
 *  - Tek bir APK'nin okunamamasi (izin, silinmis dosya) taramayi durdurmaz; girdi
 *    FAILED olarak listelenir.
 */
class DeviceScanWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = try {
        withContext(Dispatchers.IO) { execute() }
    } catch (cancelled: CancellationException) {
        ScanNotifications.cancel(applicationContext)
        DeviceScanStore.reset()
        ScanStore.reset()
        throw cancelled
    } catch (error: Exception) {
        fail(error.message ?: error.javaClass.simpleName)
    }

    private suspend fun execute(): Result {
        val context = applicationContext
        val includeSystem = inputData.getBoolean(KEY_INCLUDE_SYSTEM, false)
        val startedAt = System.currentTimeMillis()

        ScanNotifications.ensureChannel(context)

        val yaraFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.YARA)
        val clamFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_AV)
        val hashFile = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_HASHES)
        val communityYara = CommunityStore.enabledYaraFiles(context)
        val communityHashes = CommunityStore.enabledHashFiles(context)

        val acquired = ScanEngines.acquire(yaraFile, clamFile, hashFile, communityYara, communityHashes)
        if (acquired.isFailure) {
            val reason = acquired.exceptionOrNull()?.message ?: context.getString(R.string.engine_unknown_error)
            return fail(context.getString(R.string.engine_unavailable, reason))
        }
        val engine = acquired.getOrThrow()
        ScanStore.publishEngine(
            EngineInfo.from(engine, yaraFile?.absolutePath, clamFile?.absolutePath, hashFile?.absolutePath)
        )

        val targets = InstalledAppPolicy.selectTargets(
            InstalledAppsSource.load(context),
            InstalledAppPolicy.Options(includeSystemApps = includeSystem, selfPackage = context.packageName)
        )
        DeviceScanStore.markStarted(targets.size)
        ScanStore.markScanning(context)

        val displayName = context.getString(R.string.device_scan_result_name, targets.size)
        val entries = ArrayList<AppScanEntry>(targets.size)
        for ((index, app) in targets.withIndex()) {
            currentCoroutineContext().ensureActive()
            DeviceScanStore.markProgress(index, app.displayName, entries.toList())
            val fraction = index.toFloat() / targets.size.coerceAtLeast(1).toFloat()
            ScanStore.setProgress(fraction)
            ScanNotifications.showProgress(context, app.displayName, fraction)
            entries += scanApp(engine, app)
        }

        val summary = DeviceScanSummary.toScanResult(
            entries = entries,
            durationMillis = System.currentTimeMillis() - startedAt,
            displayName = displayName
        )
        DeviceScanStore.publish(context, entries)
        ScanStore.publishResult(context, summary)
        ScanNotifications.showDeviceScanResult(context, entries)
        return Result.success()
    }

    private fun scanApp(engine: ApkScannerEngine, app: InstalledApp): AppScanEntry {
        val results = app.apkPaths.map { path ->
            try {
                engine.scan(File(path))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                ScanResult.failed(path, error.message ?: error.javaClass.simpleName)
            }
        }
        return DeviceScanSummary.mergeEntry(app, results)
    }

    private fun fail(message: String): Result {
        val context = applicationContext
        DeviceScanStore.markFailed(message)
        ScanStore.markFailed(context, message)
        ScanNotifications.cancel(context)
        return Result.failure()
    }

    companion object {
        const val KEY_INCLUDE_SYSTEM = "include_system"
    }
}
