package org.xsecurity.scanner.engine

import java.io.File

/**
 * Motor orneklerinin surec-ici onbellegi.
 *
 * Onceki surumde onbellek motor *ornegine* aitti ve worker her taramada yeni bir
 * `ApkScannerEngine()` kuruyordu; yani devasa `.ndb`/`.yar` dosyalari her dosya icin
 * yeniden parse ediliyordu. Ayrica `if (cached == null)` yuzunden imza guncellemesi
 * hicbir zaman yuklenmiyordu. Simdi parmak izi (yol + boyut + mtime) degistiginde
 * onbellek kendiliginden duser.
 */
object ScanEngines {

    private val lock = Any()

    @Volatile
    private var cached: ApkScannerEngine? = null

    val current: ApkScannerEngine? get() = cached

    fun acquire(
        yaraFile: File?,
        clamFile: File?,
        hashFile: File? = null,
        communityYaraFiles: List<File> = emptyList(),
        communityHashFiles: List<File> = emptyList(),
        force: Boolean = false
    ): Result<ApkScannerEngine> {
        val fingerprint = ApkScannerEngine.fingerprintOf(
            yaraFile,
            clamFile,
            hashFile,
            *communityYaraFiles.toTypedArray(),
            *communityHashFiles.toTypedArray()
        )
        if (!force) {
            cached?.takeIf { it.fingerprint == fingerprint }?.let { return Result.success(it) }
        }
        synchronized(lock) {
            if (!force) {
                cached?.takeIf { it.fingerprint == fingerprint }?.let { return Result.success(it) }
            }
            val loaded = ApkScannerEngine.load(yaraFile, clamFile, hashFile, communityYaraFiles, communityHashFiles)
            loaded.onSuccess { cached = it }
            loaded.onFailure { cached = null }
            return loaded
        }
    }

    fun invalidate() {
        synchronized(lock) { cached = null }
    }
}
