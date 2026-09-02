package org.xsecurity.scanner.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.limitedParallelism
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.R
import org.xsecurity.scanner.community.CommunityStore
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.data.ScanHistoryEntry
import org.xsecurity.scanner.data.ScanHistoryStore
import org.xsecurity.scanner.data.ScanHistoryType
import org.xsecurity.scanner.data.ScanNotifications
import org.xsecurity.scanner.data.ScanStore
import org.xsecurity.scanner.data.ScanHistoryFlaggedApp
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.device.AppScanEntry
import org.xsecurity.scanner.device.DeviceScanCache
import org.xsecurity.scanner.device.DeviceScanStore
import org.xsecurity.scanner.device.DeviceScanSummary
import org.xsecurity.scanner.device.InstalledApp
import org.xsecurity.scanner.device.InstalledAppPolicy
import org.xsecurity.scanner.device.InstalledAppsSource
import org.xsecurity.scanner.engine.ApkScannerEngine
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * "Tumunu tara": kurulu uygulamalarin APK'larini mevcut motorla tarar.
 *
 *  - Uygulama-basina sonuc [DeviceScanStore]'a, ozet tek [ScanResult] olarak mevcut
 *    [ScanStore]'a, turun kalici ozeti [ScanHistoryStore]'a yazilir.
 *  - **Paralellik** sinirli: [MAX_SCAN_PARALLELISM] kadar uygulama ayni anda
 *    taranir (IO havuzunun kismisi); motor artik parmak izi bazinda bir kez derlendigi
 *    icin bu guvenlidir. Sonuclar hedef sirada [Array] slot'lariyla korunur.
 *  - **Onbellek** ([DeviceScanCache]): motor parmak izi + surum kodu + guncelleme
 *    zamani ayni kalan uygulamalar yeniden taranmaz; ozet "X tarandi, Y onbellegi isledi"
 *    seklinde raporlanir.
 *  - Ilerleme hem UI'a hem bildirime yazilir (tamamlanan her uygulamada).
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
        val message = error.message ?: error.javaClass.simpleName
        // Beklenmeyen hata taramayi yarisinda kestiyse gecmise de FAILED kalsin.
        runCatching {
            recordHistory(
                context = applicationContext,
                entries = emptyList(),
                status = ScanStatus.FAILED.name,
                durationMillis = 0L,
                bytesScanned = 0L,
                engineInfo = null,
                cachedCount = 0,
                displayName = applicationContext.getString(R.string.device_scan_result_name, 0),
                warnings = listOf(message)
            )
        }
        fail(message)
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
            val message = context.getString(R.string.engine_unavailable, reason)
            recordHistory(
                context = context,
                entries = emptyList(),
                status = ScanStatus.FAILED.name,
                durationMillis = System.currentTimeMillis() - startedAt,
                bytesScanned = 0L,
                engineInfo = null,
                cachedCount = 0,
                displayName = context.getString(R.string.device_scan_result_name, 0),
                warnings = listOf(message)
            )
            return fail(message)
        }
        val engine = acquired.getOrThrow()
        val engineInfo = EngineInfo.from(engine, yaraFile?.absolutePath, clamFile?.absolutePath, hashFile?.absolutePath)
        ScanStore.publishEngine(engineInfo)

        val targets = InstalledAppPolicy.selectTargets(
            InstalledAppsSource.load(context),
            InstalledAppPolicy.Options(includeSystemApps = includeSystem, selfPackage = context.packageName)
        )

        // Onbellek: parmak izi + surum + guncelleme zamani uyunan uygulamalar bu turde
        // yeniden taranmaz (girdileri onceden taranmis halini tasir).
        val cacheFile = DeviceScanCache.file(context)
        val cache = DeviceScanCache.load(cacheFile)
        val cacheHits = HashMap<String, AppScanEntry>()
        for (app in targets) {
            DeviceScanCache.hitFor(cache, engine.fingerprint, app)?.let { cacheHits[app.packageName] = it }
        }

        val displayName = context.getString(R.string.device_scan_result_name, targets.size)
        DeviceScanStore.markStarted(targets.size, cacheHits.size)
        ScanStore.markScanning(context)

        // Sonuclar hedef sirada slot'larda; tamamlananlar hedef sirasinda listelenir.
        val slots = arrayOfNulls<AppScanEntry>(targets.size)
        val indexByPackage = targets.withIndex().associate { (index, app) -> app.packageName to index }
        cacheHits.forEach { (packageName, entry) ->
            indexByPackage[packageName]?.let { slots[it] = entry }
        }

        val completed = AtomicInteger(0)
        val dispatcher = Dispatchers.IO.limitedParallelism(scanParallelism())
        try {
            coroutineScope {
                targets.indices
                    .filter { slots[it] == null }
                    .map { index ->
                        val app = targets[index]
                        async(dispatcher) {
                            currentCoroutineContext().ensureActive()
                            try {
                                slots[index] = scanApp(engine, app)
                            } finally {
                                // Onbellek isleyenler aninda "tamamlandigi" icin ilerlemeye
                                // baslangictan sayilir: tamamlanan = tarama + onbellek.
                                val done = (completed.incrementAndGet() + cacheHits.size)
                                    .coerceAtMost(targets.size)
                                val fraction = done.toFloat() / targets.size.coerceAtLeast(1).toFloat()
                                DeviceScanStore.markProgress(done, app.displayName, slots.mapNotNull { it })
                                ScanStore.setProgress(fraction)
                                ScanNotifications.showProgress(context, app.displayName, fraction)
                            }
                        }
                    }
                    .awaitAll()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        }

        val entries = slots.filterNotNull()
        val summary = DeviceScanSummary.toScanResult(
            entries = entries,
            durationMillis = System.currentTimeMillis() - startedAt,
            displayName = displayName
        )

        // Onbellegi tazele: yalnizca BU turdeki hedefler kalir — kaldirilmis paketler
        // kendiliginden prunedur, parmak izi degisen imza seti bir sonraki turde
        // tum kayitlari esgecer.
        val freshCache = targets.associate { app ->
            app.packageName to DeviceScanCache.CachedApp(
                versionCode = app.versionCode,
                lastUpdateTime = app.lastUpdateTime,
                entry = slots[indexByPackage.getValue(app.packageName)]
                    ?: AppScanEntry(
                        packageName = app.packageName,
                        label = app.displayName,
                        status = ScanStatus.FAILED,
                        errorMessage = "entry missing"
                    )
            )
        }
        runCatching { DeviceScanCache.save(cacheFile, DeviceScanCache.Snapshot(engine.fingerprint, freshCache)) }

        DeviceScanStore.publish(context, entries, cachedCount = cacheHits.size)
        ScanStore.publishResult(context, summary)
        ScanNotifications.showDeviceScanResult(context, entries)
        recordHistory(
            context = context,
            entries = entries,
            status = summary.status.name,
            durationMillis = summary.durationMillis,
            bytesScanned = entries.sumOf { it.bytesScanned },
            engineInfo = engineInfo,
            cachedCount = cacheHits.size,
            displayName = displayName,
            warnings = summary.engineWarnings
        )
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

    private fun recordHistory(
        context: Context,
        entries: List<AppScanEntry>,
        status: String,
        durationMillis: Long,
        bytesScanned: Long,
        engineInfo: EngineInfo?,
        cachedCount: Int,
        displayName: String,
        warnings: List<String>
    ) {
        val allThreats = entries.flatMap { it.threats }
        val entry = ScanHistoryEntry(
            timestamp = System.currentTimeMillis(),
            type = ScanHistoryType.DEVICE,
            trigger = ScanHistoryStore.TRIGGER_MANUAL,
            title = displayName,
            status = status,
            durationMillis = durationMillis,
            bytesScanned = bytesScanned,
            appsScanned = entries.size,
            appsFlagged = DeviceScanSummary.infectedCount(entries),
            appsCached = cachedCount,
            threatCount = allThreats.size,
            threats = ScanHistoryStore.threatsOf(allThreats),
            flaggedApps = entries.filter { it.isInfected }
                .take(ScanHistoryStore.MAX_FLAGGED_APPS)
                .map { app ->
                    ScanHistoryFlaggedApp(
                        packageName = app.packageName,
                        label = app.label,
                        threatNames = app.threats.map { it.name }
                    )
                },
            engineCounters = ScanHistoryStore.counters(engineInfo),
            warnings = warnings
        )
        runCatching { ScanHistoryStore.record(context, entry) }
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

        /** Paralel cihaz taramasinin ust siniri (cihaz cekirdegiyle sinirlanir). */
        private const val MAX_SCAN_PARALLELISM = 4

        private fun scanParallelism(): Int =
            minOf(MAX_SCAN_PARALLELISM, Runtime.getRuntime().availableProcessors()).coerceAtLeast(1)
    }
}
