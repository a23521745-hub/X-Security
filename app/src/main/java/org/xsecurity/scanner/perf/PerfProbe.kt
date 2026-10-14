package org.xsecurity.scanner.perf

import android.os.StrictMode
import android.os.SystemClock
import android.util.Log
import org.xsecurity.scanner.BuildConfig
import org.xsecurity.scanner.autopilot.SystemPackageCache

/**
 * Debug-only measurement probes for the optimization hotfix.
 *
 * Nothing here runs in a release build ([BuildConfig.DEBUG] gate): the probes exist so the
 * acceptance protocol can be executed on a real device with only `adb logcat`/`dumpsys`
 * (`tools/perf/device-probe.sh`):
 *
 *  - **StrictMode** (thread: disk reads/writes, network, custom slow calls; VM: leaked closables)
 *    with `penaltyLog`, so "StrictMode-clean debug" is decided by an empty violation log instead of
 *    a feeling. No `penaltyDeath`, never crashes the gate run.
 *  - **stage timings** for the cold-start restore path (`perf cold_start_restore_ms=...`) so the
 *    main-thread vs IO split is visible per launch.
 *  - **safelist cache counters** (`perf safelist_cache lookups=.. hits=.. entries=..`) so the
 *    "PackageManager query per recomposition" fix is verifiable on the device by scrolling the
 *    quarantine list and reading the counters (lookups must stay flat while scrolling).
 */
object PerfProbe {

    const val TAG = "XSecurityPerf"

    fun installDebugProbes() {
        if (!BuildConfig.DEBUG) return
        runCatching {
            StrictMode.setThreadPolicy(
                StrictMode.ThreadPolicy.Builder()
                    .detectDiskReads()
                    .detectDiskWrites()
                    .detectNetwork()
                    .detectCustomSlowCalls()
                    .penaltyLog()
                    .build()
            )
            StrictMode.setVmPolicy(
                StrictMode.VmPolicy.Builder()
                    .detectLeakedClosableObjects()
                    .penaltyLog()
                    .build()
            )
            Log.i(TAG, "debug probes enabled (StrictMode penaltyLog, perf stages, cache counters)")
        }
    }

    fun markStart(): Long = SystemClock.elapsedRealtime()

    fun markEnd(label: String, startedAt: Long) {
        if (!BuildConfig.DEBUG) return
        val elapsed = SystemClock.elapsedRealtime() - startedAt
        Log.i(TAG, "perf ${label}_ms=$elapsed (thread=${Thread.currentThread().name})")
    }

    fun logSafelistCache(stats: SystemPackageCache.Stats) {
        if (!BuildConfig.DEBUG) return
        Log.i(
            TAG,
            "perf safelist_cache lookups=${stats.lookups} hits=${stats.hits} entries=${stats.entries}"
        )
    }
}
