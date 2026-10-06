package org.xsecurity.scanner.autopilot

/**
 * AutoPilot readiness score v1 (0..100). This is an explainable posture score,
 * not a malware verdict: scanner readiness is worth 35, current definitions 20,
 * and each optional signal/actuator permission 15. Missing Usage Access reduces
 * coverage but never disables install-time observation; missing overlay uses the
 * full-screen warning fallback and therefore is not a score penalty.
 */
data class AutoPilotHealthInputs(
    val scannerReady: Boolean,
    val definitionsFresh: Boolean,
    val usageAccessGranted: Boolean,
    val accessibilityAssistGranted: Boolean
)

data class AutoPilotHealthScore(val value: Int, val grade: Grade, val deductions: List<String>) {
    enum class Grade { GOOD, DEGRADED, LIMITED }
}

object AutoPilotHealthScoreV1 {
    fun calculate(inputs: AutoPilotHealthInputs): AutoPilotHealthScore {
        var score = 100
        val deductions = ArrayList<String>(4)
        if (!inputs.scannerReady) {
            score -= 35
            deductions += "scanner_not_ready"
        }
        if (!inputs.definitionsFresh) {
            score -= 20
            deductions += "definitions_stale"
        }
        if (!inputs.usageAccessGranted) {
            score -= 15
            deductions += "usage_access_unavailable_install_time_only"
        }
        if (!inputs.accessibilityAssistGranted) {
            score -= 15
            deductions += "accessibility_assist_unavailable_best_effort_only"
        }
        val normalized = score.coerceIn(0, 100)
        val grade = when {
            normalized >= 80 -> AutoPilotHealthScore.Grade.GOOD
            normalized >= 50 -> AutoPilotHealthScore.Grade.DEGRADED
            else -> AutoPilotHealthScore.Grade.LIMITED
        }
        return AutoPilotHealthScore(normalized, grade, deductions)
    }
}
