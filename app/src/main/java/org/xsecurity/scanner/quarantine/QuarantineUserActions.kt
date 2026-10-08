package org.xsecurity.scanner.quarantine

import android.content.Context
import android.content.Intent
import org.xsecurity.scanner.autopilot.AuditLog
import org.xsecurity.scanner.autopilot.AuditRecord
import org.xsecurity.scanner.autopilot.AutopilotSettings
import org.xsecurity.scanner.autopilot.SecurityEvent
import org.xsecurity.scanner.autopilot.SecuritySignal
import org.xsecurity.scanner.autopilot.SystemPackageSafelist
import java.util.UUID

/** Explicit user gestures for bypass, restore, retry, and the system uninstall confirmation flow. */
object QuarantineUserActions {
    fun allowFor24Hours(context: Context, packageName: String, recordId: String? = null): Boolean {
        if (QuarantineRepository.addTimeboxedBypass(context, packageName) == null) return false
        if (recordId != null) {
            val record = QuarantineRepository.record(context, recordId)
            if (record != null && record.packageName == packageName && record.state == QuarantineState.PENDING) {
                QuarantineAssistStore.clearIfRecord(context, recordId)
                QuarantineRepository.transition(
                    context,
                    recordId,
                    QuarantineState.CANCELLED,
                    QuarantineActor.USER_ACTION
                )
            } else if (record != null && record.packageName == packageName && record.state == QuarantineState.QUARANTINED) {
                if (PackageSoftQuarantine.restore(context, packageName).state == QuarantineState.RESTORED) {
                    QuarantineRepository.transition(
                        context,
                        recordId,
                        QuarantineState.RESTORED,
                        QuarantineActor.USER_ACTION
                    )
                }
            }
        }
        return true
    }

    fun uninstallIntent(context: Context, packageName: String, recordId: String? = null): Intent? {
        if (packageName.isBlank() || SystemPackageSafelist.isSystemPackage(context, packageName)) return null
        val now = System.currentTimeMillis()
        val record = AuditRecord(
            id = UUID.randomUUID().toString(),
            timestampMillis = now,
            eventType = SecurityEvent.Type.MANUAL.name,
            packageName = packageName,
            isSystemPackage = false,
            eventOccurredAtMillis = now,
            signals = listOf(
                SecuritySignal(
                    SecuritySignal.ProviderId.LIFECYCLE,
                    SecuritySignal.Verdict.UNKNOWN,
                    SecuritySignal.Risk.LOW,
                    "user_opened_system_uninstall_confirmation"
                )
            ),
            decisionAction = "USER_UNINSTALL_INTENT",
            decisionReason = if (recordId == null) "user_requested_uninstall" else "user_requested_quarantine_uninstall",
            autonomyLevel = AutopilotSettings.level(context).name
        )
        if (!AuditLog.append(context, record)) return null
        return Intent(Intent.ACTION_DELETE, android.net.Uri.parse("package:$packageName"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    fun restore(context: Context, recordId: String): Boolean {
        val record = QuarantineRepository.record(context, recordId) ?: return false
        if (record.state != QuarantineState.QUARANTINED) return false
        if (QuarantineHonesty.isFileRecord(record)) {
            // File vault: move the bytes back and drop the vault copy (VaultDeleteFlow handles audit + notifications).
            return VaultDeleteFlow.restore(context, recordId) is RestoreOutcome.Restored
        }
        if (SystemPackageSafelist.isSystemPackage(context, record.packageName)) return false
        val result = PackageSoftQuarantine.restore(context, record.packageName)
        if (result.state != QuarantineState.RESTORED) return false
        return QuarantineRepository.transition(
            context,
            recordId,
            QuarantineState.RESTORED,
            QuarantineActor.USER_ACTION
        ) is QuarantineTransitionResult.Accepted
    }

    fun retry(context: Context, recordId: String, capabilityProvider: org.xsecurity.scanner.autopilot.CapabilityProvider): Boolean {
        val record = QuarantineRepository.record(context, recordId) ?: return false
        if (record.state != QuarantineState.FAILED) return false
        if (SystemPackageSafelist.isSystemPackage(context, record.packageName)) return false
        val pending = QuarantineRepository.transition(
            context,
            recordId,
            QuarantineState.PENDING,
            QuarantineActor.USER_ACTION
        )
        if (pending !is QuarantineTransitionResult.Accepted) return false
        val result = capabilityProvider.quarantine(context, record.packageName, recordId)
        return when (result.state) {
            QuarantineState.QUARANTINED -> QuarantineRepository.transition(
                context, recordId, QuarantineState.QUARANTINED, QuarantineActor.AUTOMATION
            ) is QuarantineTransitionResult.Accepted
            QuarantineState.PENDING -> true
            else -> {
                QuarantineRepository.transition(
                    context,
                    recordId,
                    QuarantineState.FAILED,
                    QuarantineActor.AUTOMATION,
                    failureCode = result.failureCode ?: "rootless_action_failed"
                )
                false
            }
        }
    }

    fun markUninstalledAfterUserConfirmation(context: Context, recordId: String): Boolean {
        val record = QuarantineRepository.record(context, recordId) ?: return false
        if (record.state !in setOf(QuarantineState.PENDING, QuarantineState.QUARANTINED, QuarantineState.FAILED)) return false
        val stillInstalled = try {
            context.packageManager.getPackageInfo(record.packageName, 0)
            true
        } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
            false
        } catch (_: RuntimeException) {
            true
        }
        if (stillInstalled) return false
        QuarantineAssistStore.clearIfRecord(context, recordId)
        return QuarantineRepository.transition(
            context,
            recordId,
            QuarantineState.DELETED,
            QuarantineActor.USER_ACTION
        ) is QuarantineTransitionResult.Accepted
    }
}
