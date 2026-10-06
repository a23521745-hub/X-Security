package org.xsecurity.scanner.autopilot

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.content.Intent
import org.xsecurity.scanner.definitions.DefinitionsStore
import java.util.concurrent.TimeUnit

/** UsageStats polling fallback; the accessibility sensor uses the same package-only deduplicator. */
object ForegroundAppObserver {
    private val eventLock = Any()

    fun hasUsageAccess(context: Context): Boolean = try {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) ==
            AppOpsManager.MODE_ALLOWED
    } catch (_: RuntimeException) {
        false
    }

    fun usageAccessSettingsIntent(): Intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)

    fun poll(context: Context, nowMillis: Long = System.currentTimeMillis()): SecurityEvent.ForegroundApp? {
        if (!hasUsageAccess(context)) return null
        val packageName = foregroundPackage(context, nowMillis) ?: return null
        return eventForPackage(context, packageName, nowMillis)
    }

    /** Called by both sensors; emits once per package transition and never reads window text. */
    fun eventForPackage(
        context: Context,
        packageName: String,
        nowMillis: Long = System.currentTimeMillis()
    ): SecurityEvent.ForegroundApp? = synchronized(eventLock) {
        if (packageName.isBlank() || packageName == AutopilotSettings.lastForegroundPackage(context)) return@synchronized null
        AutopilotSettings.setLastForegroundPackage(context, packageName)
        if (!AutopilotSettings.isEnabled(context) || packageName == context.packageName) return@synchronized null
        if (SystemPackageSafelist.isSystemPackage(context, packageName)) return@synchronized null
        SecurityEvent.ForegroundApp(packageName, isSystemPackage = false, occurredAtMillis = nowMillis)
    }

    fun foregroundPackage(context: Context, nowMillis: Long = System.currentTimeMillis()): String? {
        val manager = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return null
        val events = runCatching {
            manager.queryEvents(nowMillis - TimeUnit.MINUTES.toMillis(30), nowMillis)
        }.getOrNull() ?: return null
        val event = UsageEvents.Event()
        var latest: String? = null
        var latestAt = 0L
        while (events.hasNextEvent()) {
            if (!events.getNextEvent(event)) continue
            val foreground = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                event.eventType == UsageEvents.Event.ACTIVITY_RESUMED
            } else {
                @Suppress("DEPRECATION")
                event.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND
            }
            if (foreground && event.timeStamp >= latestAt) {
                latestAt = event.timeStamp
                latest = event.packageName
            }
        }
        return latest
    }
}

/** WorkManager-backed pulse; optional access denial leaves package-install observation active. */
object AutopilotScheduler {
    const val PERIODIC_WORK_NAME = "xsec_autopilot_sensor_pulse"
    const val SCAN_INTERVAL_MILLIS = 24L * 60L * 60L * 1000L
    const val DEFINITIONS_STALE_MILLIS = 7L * 24L * 60L * 60L * 1000L
    private const val DEFINITIONS_STALE_SIGNAL_INTERVAL = 24L * 60L * 60L * 1000L

    fun schedule(context: Context) {
        val appContext = context.applicationContext
        // Continue using the established OTA/definitions schedulers; AutoPilot does not
        // duplicate their network/update workers.
        org.xsecurity.scanner.ota.OtaController.schedulePeriodicCheck(appContext)
        org.xsecurity.scanner.definitions.DefinitionsController.schedulePeriodicCheck(appContext)
        AutopilotDigestScheduler.schedule(appContext)
        if (!AutopilotSettings.isEnabled(appContext)) {
            runCatching { androidx.work.WorkManager.getInstance(appContext).cancelUniqueWork(PERIODIC_WORK_NAME) }
            return
        }
        val request = androidx.work.PeriodicWorkRequestBuilder<AutopilotPulseWorker>(15, TimeUnit.MINUTES)
            .setConstraints(
                androidx.work.Constraints.Builder()
                    .setRequiresBatteryNotLow(false)
                    .build()
            )
            .build()
        runCatching {
            androidx.work.WorkManager.getInstance(appContext).enqueueUniquePeriodicWork(
                PERIODIC_WORK_NAME,
                androidx.work.ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }

    internal suspend fun pulse(context: Context, nowMillis: Long = System.currentTimeMillis()) {
        val appContext = context.applicationContext
        if (!AutopilotSettings.isEnabled(appContext)) return

        val lastScan = AutopilotSettings.lastScanEnqueuedAt(appContext)
        if (lastScan == 0L || nowMillis - lastScan >= SCAN_INTERVAL_MILLIS) {
            AutopilotRuntime.evaluate(appContext, SecurityEvent.ScanDue(nowMillis))
        }

        DefinitionsStore.restore(appContext)
        val defState = DefinitionsStore.state.value
        val lastFreshnessSignal = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getLong(KEY_LAST_DEFS_STALE_SIGNAL, 0L)
        val latestDefinitionsActivity = maxOf(defState.lastInstalledAt, defState.checkedAt)
        val definitionsStale = latestDefinitionsActivity == 0L ||
            nowMillis - latestDefinitionsActivity >= DEFINITIONS_STALE_MILLIS
        if (definitionsStale && (lastFreshnessSignal == 0L || nowMillis - lastFreshnessSignal >= DEFINITIONS_STALE_SIGNAL_INTERVAL)) {
            appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putLong(KEY_LAST_DEFS_STALE_SIGNAL, nowMillis).apply()
            AutopilotRuntime.evaluate(appContext, SecurityEvent.DefsStale(latestDefinitionsActivity, nowMillis))
        }

        // No Usage Access means no polling events; opt-in Accessibility remains the immediate sensor.
        // v17 checks active quarantine/positive verdict cache only; it never scans every launch.
        ForegroundAppObserver.poll(appContext, nowMillis)?.let {
            ForegroundInterceptionCoordinator.handle(appContext, it)
        }
    }

    private const val PREFS = "xsec_autopilot_sensor"
    private const val KEY_LAST_DEFS_STALE_SIGNAL = "last_defs_stale_signal"
}
