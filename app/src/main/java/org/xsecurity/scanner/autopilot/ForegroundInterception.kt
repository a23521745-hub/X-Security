package org.xsecurity.scanner.autopilot

import android.content.Context
import android.content.Intent
import org.xsecurity.scanner.R
import org.xsecurity.scanner.quarantine.QuarantineRepository
import org.xsecurity.scanner.quarantine.QuarantineState

/** Shared handler for Accessibility and UsageStats foreground events. No universal launch scan. */
object ForegroundInterceptionCoordinator {
    fun handle(context: Context, event: SecurityEvent.ForegroundApp): Boolean {
        val appContext = context.applicationContext
        val packageName = event.packageName.takeIf { it.isNotBlank() } ?: return false
        if (!AutopilotSettings.isEnabled(appContext)) return false
        val systemPackage = event.isSystemPackage || SystemPackageSafelist.isSystemPackage(appContext, packageName)
        if (systemPackage) return false

        val record = runCatching {
            QuarantineRepository.recordsForPackage(appContext, packageName)
                .asSequence()
                .filter { it.state == QuarantineState.PENDING || it.state == QuarantineState.QUARANTINED }
                .maxByOrNull { it.updatedAtMillis }
        }.getOrNull()
        val bypassActive = runCatching {
            QuarantineRepository.activeBypass(appContext, packageName) != null
        }.getOrDefault(true)
        val cached = KnownBadVerdictCache.get(appContext, packageName)
        val interception = ForegroundInterceptionPolicy.decide(
            ForegroundInterceptionInput(
                packageName = packageName,
                isSystemPackage = systemPackage,
                activeBypass = bypassActive,
                quarantineRecord = record,
                cachedKnownBad = cached
            )
        ) ?: return false

        val signal = SecuritySignal(
            provider = interception.provider,
            verdict = interception.verdict,
            risk = SecuritySignal.Risk.HIGH,
            reasonCode = interception.reasonCode
        )
        val audit = AuditRecord.from(
            event.copy(isSystemPackage = false),
            listOf(signal),
            PolicyDecision(PolicyAction.ASK_USER, interception.reasonCode, notify = true),
            AutopilotSettings.level(appContext)
        )
        // Never display/perform an interception unless its content-free audit row is durable.
        if (!AuditLog.append(appContext, audit)) return false
        OverlayWarning.showInterception(appContext, interception)
        return true
    }

    /** Go Back is a user choice: audit first, then return to Home without killing the target app. */
    fun goBack(context: Context, interception: ForegroundInterception): Boolean {
        val now = System.currentTimeMillis()
        val event = SecurityEvent.ForegroundApp(interception.packageName, false, now)
        val signal = SecuritySignal(
            provider = interception.provider,
            verdict = interception.verdict,
            risk = SecuritySignal.Risk.HIGH,
            reasonCode = interception.reasonCode
        )
        val audit = AuditRecord.from(
            event,
            listOf(signal),
            PolicyDecision(PolicyAction.ASK_USER, interception.reasonCode, notify = true),
            AutopilotSettings.level(context),
            now
        ).copy(
            decisionAction = "USER_GO_BACK",
            decisionReason = "user_go_back_${interception.reasonCode}"
        )
        if (!AuditLog.append(context.applicationContext, audit)) return false
        val homeIntent = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_HOME)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return runCatching {
            context.applicationContext.startActivity(homeIntent)
            true
        }.getOrDefault(false)
    }
}

/** Localized, non-content reason labels for the warning surface. */
object ForegroundInterceptionLabels {
    fun verdict(context: Context, verdict: SecuritySignal.Verdict): String = context.getString(
        when (verdict) {
            SecuritySignal.Verdict.KNOWN_BAD -> R.string.autopilot_verdict_known_bad
            SecuritySignal.Verdict.KNOWN_GOOD -> R.string.autopilot_verdict_known_good
            SecuritySignal.Verdict.UNKNOWN -> R.string.autopilot_verdict_unknown
        }
    )

    fun reason(context: Context, reasonCode: String): String = context.getString(
        when (reasonCode) {
            "active_quarantine_pending" -> R.string.autopilot_interception_reason_pending
            "active_quarantine_quarantined" -> R.string.autopilot_interception_reason_quarantined
            "signature_match" -> R.string.autopilot_interception_reason_signature
            else -> R.string.autopilot_interception_reason_cached
        }
    )
}
