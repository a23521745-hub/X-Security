package org.xsecurity.scanner.autopilot

/** Pure policy layer: no Android types, storage, clocks, or side effects. */
enum class AutonomyLevel { L0, L1, L2 }

enum class PolicyAction {
    /** Silent allow; AuditLog still records the decision. */
    ALLOW,

    /** Ask the user before taking containment action. */
    ASK_USER,

    /** L0 advisory only: notify, but do not contain automatically. */
    RECOMMEND_CONTAINMENT,

    /** L2 blocks a known-bad ephemeral item without a package target to quarantine. */
    BLOCK_CONTENT,

    /** Rootless, reversible soft quarantine only. There is intentionally no delete action. */
    BLOCK_AND_QUARANTINE
}

data class PolicyDecision(
    val action: PolicyAction,
    val reasonCode: String,
    val notify: Boolean
) {
    val isAutomaticContainment: Boolean get() =
        action == PolicyAction.BLOCK_AND_QUARANTINE || action == PolicyAction.BLOCK_CONTENT
}

/**
 * Locked decision table:
 *  - known bad -> contain + notify (L2), ask (L1), recommend only (L0);
 *  - known good -> silent allow;
 *  - unknown + low risk -> silent allow;
 *  - unknown + high risk -> ask at every level.
 *
 * A conflict is resolved fail-safe: any KNOWN_BAD wins over KNOWN_GOOD, then
 * KNOWN_GOOD wins over risk-only signals. System packages are checked first and
 * are always allowed without any automatic touch. L2 is the product default.
 */
object PolicyEngine {
    val DEFAULT_LEVEL: AutonomyLevel = AutonomyLevel.L2

    fun decide(
        event: SecurityEvent,
        signals: List<SecuritySignal>,
        autonomy: AutonomyLevel = DEFAULT_LEVEL,
        activeTimeboxedBypass: Boolean = false
    ): PolicyDecision {
        if (event.isSystemPackage) {
            return PolicyDecision(PolicyAction.ALLOW, REASON_SYSTEM_SAFELIST, notify = false)
        }
        if (activeTimeboxedBypass && !event.packageName.isNullOrBlank()) {
            return PolicyDecision(PolicyAction.ALLOW, REASON_TIMEBOXED_BYPASS, notify = false)
        }

        // Lifecycle events do not identify a risk unless a provider explicitly emitted
        // a signal (e.g. the ephemeral phishing scan on a Manual event).
        if (!event.hasRiskTarget() && signals.none { it.provider != SecuritySignal.ProviderId.LIFECYCLE }) {
            return PolicyDecision(PolicyAction.ALLOW, REASON_LIFECYCLE, notify = false)
        }

        return when {
            signals.any { it.verdict == SecuritySignal.Verdict.KNOWN_BAD } -> when (autonomy) {
                AutonomyLevel.L0 -> PolicyDecision(
                    PolicyAction.RECOMMEND_CONTAINMENT,
                    REASON_KNOWN_BAD_RECOMMENDATION,
                    notify = true
                )
                AutonomyLevel.L1 -> PolicyDecision(
                    PolicyAction.ASK_USER,
                    REASON_KNOWN_BAD_CONFIRMATION_REQUIRED,
                    notify = true
                )
                AutonomyLevel.L2 -> {
                    val action = if (event is SecurityEvent.Manual &&
                        event.origin == "phishing_share" && event.packageName.isNullOrBlank()
                    ) {
                        PolicyAction.BLOCK_CONTENT
                    } else {
                        PolicyAction.BLOCK_AND_QUARANTINE
                    }
                    PolicyDecision(
                        action,
                        if (action == PolicyAction.BLOCK_CONTENT) REASON_KNOWN_BAD_CONTENT_BLOCKED
                        else REASON_KNOWN_BAD_CONTAINED,
                        notify = true
                    )
                }
            }

            signals.any { it.verdict == SecuritySignal.Verdict.KNOWN_GOOD } ->
                PolicyDecision(PolicyAction.ALLOW, REASON_KNOWN_GOOD, notify = false)

            signals.any { it.risk == SecuritySignal.Risk.HIGH } ->
                PolicyDecision(PolicyAction.ASK_USER, REASON_UNKNOWN_HIGH_RISK, notify = true)

            else -> PolicyDecision(PolicyAction.ALLOW, REASON_UNKNOWN_LOW_RISK, notify = false)
        }
    }

    const val REASON_SYSTEM_SAFELIST = "system_package_safelisted"
    const val REASON_LIFECYCLE = "lifecycle_event_no_target"
    const val REASON_KNOWN_BAD_RECOMMENDATION = "known_bad_recommendation_only"
    const val REASON_KNOWN_BAD_CONFIRMATION_REQUIRED = "known_bad_user_confirmation_required"
    const val REASON_KNOWN_BAD_CONTAINED = "known_bad_soft_quarantine"
    const val REASON_KNOWN_BAD_CONTENT_BLOCKED = "known_bad_ephemeral_content_blocked"
    const val REASON_KNOWN_GOOD = "known_good_silent_allow"
    const val REASON_UNKNOWN_LOW_RISK = "unknown_low_risk_silent_allow"
    const val REASON_UNKNOWN_HIGH_RISK = "unknown_high_risk_ask_user"
    const val REASON_TIMEBOXED_BYPASS = "active_timeboxed_bypass_silent_allow"
}
