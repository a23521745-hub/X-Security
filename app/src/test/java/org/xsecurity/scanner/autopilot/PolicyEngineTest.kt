package org.xsecurity.scanner.autopilot

import android.content.pm.ApplicationInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyEngineTest {
    private val packageEvent = SecurityEvent.PackageInstalled("org.example.app")

    @Test
    fun l2IsDefaultAndKnownBadIsContainedAndNotified() {
        assertEquals(AutonomyLevel.L2, PolicyEngine.DEFAULT_LEVEL)
        val result = PolicyEngine.decide(packageEvent, listOf(bad()))
        assertEquals(PolicyAction.BLOCK_AND_QUARANTINE, result.action)
        assertTrue(result.notify)
    }

    @Test
    fun lockedTableAllowsKnownGoodAndUnknownLowSilently() {
        val knownGood = PolicyEngine.decide(packageEvent, listOf(good()))
        assertEquals(PolicyAction.ALLOW, knownGood.action)
        assertFalse(knownGood.notify)
        assertEquals(PolicyEngine.REASON_KNOWN_GOOD, knownGood.reasonCode)

        val unknownLow = PolicyEngine.decide(packageEvent, listOf(unknown(SecuritySignal.Risk.LOW)))
        assertEquals(PolicyAction.ALLOW, unknownLow.action)
        assertFalse(unknownLow.notify)
        assertEquals(PolicyEngine.REASON_UNKNOWN_LOW_RISK, unknownLow.reasonCode)
    }

    @Test
    fun grayUnknownHighRiskAlwaysAsks() {
        AutonomyLevel.values().forEach { level ->
            val decision = PolicyEngine.decide(packageEvent, listOf(unknown(SecuritySignal.Risk.HIGH)), level)
            assertEquals("$level", PolicyAction.ASK_USER, decision.action)
            assertTrue(decision.notify)
        }
    }

    @Test
    fun autonomyLevelsGateKnownBadWithoutChangingTheDecisionEvidence() {
        assertEquals(
            PolicyAction.RECOMMEND_CONTAINMENT,
            PolicyEngine.decide(packageEvent, listOf(bad()), AutonomyLevel.L0).action
        )
        assertEquals(
            PolicyAction.ASK_USER,
            PolicyEngine.decide(packageEvent, listOf(bad()), AutonomyLevel.L1).action
        )
        assertEquals(
            PolicyAction.BLOCK_AND_QUARANTINE,
            PolicyEngine.decide(packageEvent, listOf(bad()), AutonomyLevel.L2).action
        )
    }

    @Test
    fun ephemeralKnownBadContentIsBlockedWithoutCreatingAQuarantineTarget() {
        val phishingEvent = SecurityEvent.Manual(origin = "phishing_share")
        assertEquals(
            PolicyAction.BLOCK_CONTENT,
            PolicyEngine.decide(phishingEvent, listOf(bad()), AutonomyLevel.L2).action
        )
        assertEquals(
            PolicyAction.ASK_USER,
            PolicyEngine.decide(phishingEvent, listOf(bad()), AutonomyLevel.L1).action
        )
        assertEquals(
            PolicyAction.RECOMMEND_CONTAINMENT,
            PolicyEngine.decide(phishingEvent, listOf(bad()), AutonomyLevel.L0).action
        )
    }

    @Test
    fun knownBadWinsConflictingKnownGoodAndSystemPackagesAlwaysWinSafelist() {
        assertEquals(
            PolicyAction.BLOCK_AND_QUARANTINE,
            PolicyEngine.decide(packageEvent, listOf(good(), bad())).action
        )
        val system = packageEvent.copy(isSystemPackage = true)
        val decision = PolicyEngine.decide(system, listOf(bad(), unknown(SecuritySignal.Risk.HIGH)))
        assertEquals(PolicyAction.ALLOW, decision.action)
        assertEquals(PolicyEngine.REASON_SYSTEM_SAFELIST, decision.reasonCode)
        assertFalse(decision.notify)
    }

    @Test
    fun systemAndUpdatedSystemApplicationFlagsAreSafelisted() {
        assertTrue(SystemPackageSafelist.isSystemFlags(ApplicationInfo.FLAG_SYSTEM))
        assertTrue(SystemPackageSafelist.isSystemFlags(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))
        assertFalse(SystemPackageSafelist.isSystemFlags(0))
    }

    @Test
    fun activeBypassIsExplicitAndSilent() {
        val decision = PolicyEngine.decide(packageEvent, listOf(bad()), activeTimeboxedBypass = true)
        assertEquals(PolicyAction.ALLOW, decision.action)
        assertEquals(PolicyEngine.REASON_TIMEBOXED_BYPASS, decision.reasonCode)
    }

    @Test
    fun policyHasNoDeleteAction() {
        assertFalse(PolicyAction.values().any { it.name.contains("DELETE", ignoreCase = true) })
    }

    private fun bad() = SecuritySignal(
        SecuritySignal.ProviderId.SCANNER,
        SecuritySignal.Verdict.KNOWN_BAD,
        SecuritySignal.Risk.HIGH,
        "signature_match"
    )

    private fun good() = SecuritySignal(
        SecuritySignal.ProviderId.SCANNER,
        SecuritySignal.Verdict.KNOWN_GOOD,
        SecuritySignal.Risk.LOW,
        "complete_scan_no_match"
    )

    private fun unknown(risk: SecuritySignal.Risk) = SecuritySignal(
        SecuritySignal.ProviderId.HEURISTIC,
        SecuritySignal.Verdict.UNKNOWN,
        risk,
        "test_signal"
    )
}
