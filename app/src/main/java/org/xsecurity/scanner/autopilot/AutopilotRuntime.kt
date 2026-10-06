package org.xsecurity.scanner.autopilot

import android.content.Context
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.quarantine.QuarantineRepository

/** Coordinates provider collection -> pure policy -> audited action dispatch. */
object AutopilotRuntime {
    private val providers: List<SignalProvider> by lazy {
        listOf(
            ScannerVerdictProvider(),
            HeuristicRiskProvider(),
            PhishingSignalProvider(),
            PrivacySignalProvider()
        )
    }

    suspend fun evaluate(
        context: Context,
        event: SecurityEvent,
        request: SignalRequest = SignalRequest()
    ): ActionDispatcher.Result = withContext(Dispatchers.IO) {
        val appContext = context.applicationContext
        val evaluatedEvent = safelistedEvent(appContext, event)
        val signals = ArrayList<SecuritySignal>()
        var providerFailed = false
        for (provider in providers) {
            try {
                provider.provide(appContext, evaluatedEvent, request)?.let(signals::add)
            } catch (_: Exception) {
                providerFailed = true
            }
        }
        if (providerFailed && evaluatedEvent.hasRiskTarget()) {
            signals += SecuritySignal(
                provider = SecuritySignal.ProviderId.LIFECYCLE,
                verdict = SecuritySignal.Verdict.UNKNOWN,
                risk = SecuritySignal.Risk.HIGH,
                reasonCode = "signal_provider_evaluation_incomplete"
            )
        }
        if (evaluatedEvent.hasRiskTarget() && signals.isEmpty()) {
            val phishingShareWithoutLink = evaluatedEvent is SecurityEvent.Manual &&
                evaluatedEvent.origin == "phishing_share" && !request.phishingText.isNullOrBlank()
            signals += SecuritySignal(
                provider = if (phishingShareWithoutLink) SecuritySignal.ProviderId.PHISHING else SecuritySignal.ProviderId.LIFECYCLE,
                verdict = SecuritySignal.Verdict.UNKNOWN,
                risk = SecuritySignal.Risk.LOW,
                reasonCode = if (phishingShareWithoutLink) "phishing_no_link_signal" else "no_applicable_signal"
            )
        }
        val autonomy = AutopilotSettings.level(appContext)
        val bypassActive = evaluatedEvent.packageName?.let {
            QuarantineRepository.activeBypass(appContext, it) != null
        } ?: false
        val decision = PolicyEngine.decide(evaluatedEvent, signals, autonomy, bypassActive)
        ActionDispatcher().dispatch(appContext, evaluatedEvent, signals, decision, autonomy)
    }

    private fun safelistedEvent(context: Context, event: SecurityEvent): SecurityEvent {
        val packageName = event.packageName ?: return event
        if (event.isSystemPackage || !SystemPackageSafelist.isSystemPackage(context, packageName)) return event
        return when (event) {
            is SecurityEvent.PackageInstalled -> event.copy(isSystemPackage = true)
            is SecurityEvent.ForegroundApp -> event.copy(isSystemPackage = true)
            is SecurityEvent.Manual -> event.copy(isSystemPackage = true)
            is SecurityEvent.ScanDue, is SecurityEvent.DefsStale, is SecurityEvent.Boot -> event
        }
    }

    /** Enqueue an event for receiver-safe WorkManager processing. */
    fun enqueue(context: Context, event: SecurityEvent): Boolean = try {
        val request = OneTimeWorkRequestBuilder<AutopilotEventWorker>()
            .setInputData(SecurityEventCodec.encode(event))
            .addTag(TAG)
            .build()
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            SecurityEventCodec.uniqueWorkName(event),
            ExistingWorkPolicy.REPLACE,
            request
        )
        true
    } catch (_: RuntimeException) {
        false
    }

    const val TAG = "xsec-autopilot"
}

/** Only stable identifiers are serialized; ephemeral phishing text never crosses WorkManager. */
object SecurityEventCodec {
    private const val KEY_TYPE = "event_type"
    private const val KEY_PACKAGE = "event_package"
    private const val KEY_SYSTEM = "event_system"
    private const val KEY_OCCURRED_AT = "event_occurred_at"
    private const val KEY_INSTALLER = "event_installer"
    private const val KEY_LAST_DEFS = "event_last_defs"
    private const val KEY_ORIGIN = "event_origin"
    private const val KEY_INCLUDE_SYSTEM = "event_include_system"

    fun encode(event: SecurityEvent): Data {
        val data = Data.Builder()
            .putString(KEY_TYPE, event.type.name)
            .putBoolean(KEY_SYSTEM, event.isSystemPackage)
            .putLong(KEY_OCCURRED_AT, event.occurredAtMillis)
        event.packageName?.let { data.putString(KEY_PACKAGE, it) }
        when (event) {
            is SecurityEvent.PackageInstalled -> event.installerPackageName?.let { data.putString(KEY_INSTALLER, it) }
            is SecurityEvent.DefsStale -> data.putLong(KEY_LAST_DEFS, event.lastSuccessfulUpdateMillis)
            is SecurityEvent.Manual -> {
                data.putString(KEY_ORIGIN, stableOrigin(event.origin))
                data.putBoolean(KEY_INCLUDE_SYSTEM, event.includeSystemApps)
            }
            is SecurityEvent.ForegroundApp, is SecurityEvent.ScanDue, is SecurityEvent.Boot -> Unit
        }
        return data.build()
    }

    fun decode(data: Data): SecurityEvent? {
        val occurredAt = data.getLong(KEY_OCCURRED_AT, System.currentTimeMillis())
        val pkg = data.getString(KEY_PACKAGE)
        val system = data.getBoolean(KEY_SYSTEM, false)
        return when (runCatching { SecurityEvent.Type.valueOf(data.getString(KEY_TYPE).orEmpty()) }.getOrNull()) {
            SecurityEvent.Type.PACKAGE_INSTALLED -> pkg?.let {
                SecurityEvent.PackageInstalled(it, system, data.getString(KEY_INSTALLER), occurredAt)
            }
            SecurityEvent.Type.FOREGROUND_APP -> pkg?.let { SecurityEvent.ForegroundApp(it, system, occurredAt) }
            SecurityEvent.Type.SCAN_DUE -> SecurityEvent.ScanDue(occurredAt)
            SecurityEvent.Type.DEFS_STALE -> SecurityEvent.DefsStale(data.getLong(KEY_LAST_DEFS, 0L), occurredAt)
            SecurityEvent.Type.BOOT -> SecurityEvent.Boot(occurredAt)
            SecurityEvent.Type.MANUAL -> SecurityEvent.Manual(
                packageName = pkg,
                isSystemPackage = system,
                origin = data.getString(KEY_ORIGIN) ?: "manual",
                includeSystemApps = data.getBoolean(KEY_INCLUDE_SYSTEM, false),
                occurredAtMillis = occurredAt
            )
            null -> null
        }
    }

    fun uniqueWorkName(event: SecurityEvent): String = when (event) {
        is SecurityEvent.PackageInstalled -> "${AutopilotRuntime.TAG}_install_${event.packageName}"
        is SecurityEvent.ForegroundApp -> "${AutopilotRuntime.TAG}_foreground_${event.packageName}"
        is SecurityEvent.ScanDue -> "${AutopilotRuntime.TAG}_scan_due"
        is SecurityEvent.DefsStale -> "${AutopilotRuntime.TAG}_defs_stale"
        is SecurityEvent.Boot -> "${AutopilotRuntime.TAG}_boot"
        is SecurityEvent.Manual -> "${AutopilotRuntime.TAG}_manual_${event.packageName ?: stableOrigin(event.origin)}"
    }

    private fun stableOrigin(origin: String): String = when (origin) {
        "device_scan", "phishing_share" -> origin
        else -> "manual"
    }
}
