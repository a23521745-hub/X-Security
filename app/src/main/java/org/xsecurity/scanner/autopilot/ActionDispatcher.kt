package org.xsecurity.scanner.autopilot

import android.content.Context
import org.xsecurity.scanner.data.ScanController
import org.xsecurity.scanner.data.UpdatePreferences
import org.xsecurity.scanner.definitions.DefinitionsController
import org.xsecurity.scanner.ota.OtaController
import org.xsecurity.scanner.quarantine.QuarantineCoordinator
import org.xsecurity.scanner.quarantine.QuarantineRepository
import org.xsecurity.scanner.quarantine.QuarantineState

/** Executes policy outcomes only after the corresponding audit record is durable. */
class ActionDispatcher(
    private val capabilityProvider: CapabilityProvider = RootlessCapabilityProvider()
) {
    enum class Result { EXECUTED, AUDIT_FAILED, ACTION_FAILED }

    fun dispatch(
        context: Context,
        event: SecurityEvent,
        signals: List<SecuritySignal>,
        decision: PolicyDecision,
        autonomy: AutonomyLevel
    ): Result {
        val appContext = context.applicationContext
        val audit = AuditRecord.from(event, signals, decision, autonomy)
        if (!AuditLog.append(appContext, audit)) return Result.AUDIT_FAILED

        when (decision.action) {
            PolicyAction.ALLOW -> return dispatchAllowedEvent(appContext, event)
            PolicyAction.ASK_USER -> {
                AutopilotNotifications.showDecision(appContext, event, decision)
                if (!event.packageName.isNullOrBlank()) {
                    OverlayWarning.show(appContext, event.packageName!!, null, decision.reasonCode)
                }
                return Result.EXECUTED
            }
            PolicyAction.RECOMMEND_CONTAINMENT -> {
                AutopilotNotifications.showDecision(appContext, event, decision)
                return Result.EXECUTED
            }
            PolicyAction.BLOCK_CONTENT -> {
                // The offending item is ephemeral content, not an installed package; never serialize or quarantine it.
                AutopilotNotifications.showDecision(appContext, event, decision)
                return Result.EXECUTED
            }
            PolicyAction.BLOCK_AND_QUARANTINE -> {
                if (event is SecurityEvent.FileScan) {
                    val stored = runCatching {
                        org.xsecurity.scanner.quarantine.FileVault.store(
                            appContext, java.io.File(event.path), "f-${java.util.UUID.randomUUID()}"
                        )
                    }.getOrNull()
                    if (stored == null) {
                        appendActionFailure(appContext, event, signals, autonomy, "file_vault_failed")
                        AutopilotNotifications.showDecision(appContext, event, PolicyDecision(PolicyAction.ASK_USER, "file_vault_failed", notify = true))
                        return Result.ACTION_FAILED
                    }
                    val record = QuarantineRepository.newRecord(
                        packageName = "file-vault",
                        label = java.io.File(event.path).name.take(120).ifBlank { "Scanned file" },
                        sha256 = stored.sha256,
                        verdict = "KNOWN_BAD",
                        engine = event.engine.ifBlank { "unknown" },
                        vaultFileName = stored.fileName,
                        restoreInfo = "encrypted_file_vault"
                    )
                    QuarantineRepository.insert(appContext, record)
                    QuarantineRepository.transition(appContext, record.id, QuarantineState.PENDING, org.xsecurity.scanner.quarantine.QuarantineActor.AUTOMATION)
                    QuarantineRepository.transition(appContext, record.id, QuarantineState.QUARANTINED, org.xsecurity.scanner.quarantine.QuarantineActor.AUTOMATION)
                    AutopilotNotifications.showDecision(appContext, event, decision)
                    return Result.EXECUTED
                }
                val packageName = event.packageName
                if (packageName != null) {
                    // Defense in depth: a stale/misreported event cannot cross the system safelist.
                    if (event.isSystemPackage || SystemPackageSafelist.isSystemPackage(appContext, packageName)) {
                        appendSafelistGuardRecord(appContext, event, signals, autonomy)
                        return Result.EXECUTED
                    }
                    val record = QuarantineCoordinator.quarantine(
                        context = appContext,
                        packageName = packageName,
                        signals = signals,
                        capabilityProvider = capabilityProvider
                    )
                    if (record?.state == QuarantineState.FAILED) {
                        appendActionFailure(appContext, event, signals, autonomy, record.failureCode ?: "soft_quarantine_failed")
                    }
                    AutopilotNotifications.showDecision(appContext, event, decision, record?.id)
                    if (record?.state != QuarantineState.PENDING) {
                        OverlayWarning.show(appContext, packageName, record?.id, decision.reasonCode)
                    }
                } else {
                    // Phishing content has no installable package target. Its known-bad verdict
                    // is surfaced as a block warning; no unrelated package is touched.
                    AutopilotNotifications.showDecision(appContext, event, decision)
                }
                return Result.EXECUTED
            }
        }
    }

    private fun dispatchAllowedEvent(context: Context, event: SecurityEvent): Result {
        when (event) {
            is SecurityEvent.Boot -> {
                AutopilotScheduler.schedule(context)
                OtaController.schedulePeriodicCheck(context)
                DefinitionsController.schedulePeriodicCheck(context)
            }
            is SecurityEvent.ScanDue -> {
                val accepted = ScanController.enqueueDeviceScan(context, includeSystemApps = false)
                if (accepted) AutopilotSettings.markScanEnqueued(context, System.currentTimeMillis())
                else return Result.ACTION_FAILED
            }
            is SecurityEvent.DefsStale -> {
                if (UpdatePreferences.isAutoCheckEnabled(context)) {
                    DefinitionsController.enqueueManualCheck(context)
                } else {
                    DefinitionsController.schedulePeriodicCheck(context)
                }
            }
            is SecurityEvent.Manual -> {
                when {
                    event.origin == "phishing_share" -> Unit // explicit phishing scan is already being shown in its activity
                    event.packageName.isNullOrBlank() -> {
                        if (!ScanController.enqueueDeviceScan(context, includeSystemApps = event.includeSystemApps)) return Result.ACTION_FAILED
                    }
                    !event.isSystemPackage -> {
                        if (!ScanController.enqueuePackageScan(context, event.packageName!!)) return Result.ACTION_FAILED
                    }
                }
            }
            is SecurityEvent.PackageInstalled, is SecurityEvent.ForegroundApp, is SecurityEvent.FileScan -> Unit
        }
        return Result.EXECUTED
    }

    private fun appendSafelistGuardRecord(
        context: Context,
        event: SecurityEvent,
        signals: List<SecuritySignal>,
        autonomy: AutonomyLevel
    ) {
        AuditLog.append(
            context,
            AuditRecord.from(
                event,
                signals,
                PolicyDecision(PolicyAction.ALLOW, PolicyEngine.REASON_SYSTEM_SAFELIST, notify = false),
                autonomy
            )
        )
    }

    private fun appendActionFailure(
        context: Context,
        event: SecurityEvent,
        signals: List<SecuritySignal>,
        autonomy: AutonomyLevel,
        failureCode: String
    ) {
        val safeCode = failureCode.takeIf { it.matches(Regex("[a-zA-Z0-9_]{1,80}")) } ?: "soft_quarantine_failed"
        AuditLog.append(
            context,
            AuditRecord.from(
                event,
                signals + SecuritySignal(
                    SecuritySignal.ProviderId.LIFECYCLE,
                    SecuritySignal.Verdict.UNKNOWN,
                    SecuritySignal.Risk.HIGH,
                    safeCode
                ),
                PolicyDecision(PolicyAction.ASK_USER, "action_failed_$safeCode", notify = true),
                autonomy
            )
        )
    }
}
