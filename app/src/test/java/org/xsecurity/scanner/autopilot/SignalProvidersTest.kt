package org.xsecurity.scanner.autopilot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch
import org.xsecurity.scanner.phishing.PhishingHeuristics
import org.xsecurity.scanner.privacy.PrivacyRisk

class SignalProvidersTest {
    @Test
    fun scannerProviderClassifiesThreatCleanAndIncompleteResults() {
        val bad = ScanResult(
            status = ScanStatus.THREATS_FOUND,
            filePath = "/tmp/a.apk",
            fileName = "a.apk",
            fileSize = 10,
            threats = listOf(ThreatMatch("YARA", "test"))
        )
        val clean = ScanResult(ScanStatus.CLEAN, "/tmp/a.apk", "a.apk", 10)
        val failed = ScanResult.failed("/tmp/a.apk", "not readable")

        assertEquals(SecuritySignal.Verdict.KNOWN_BAD, ScannerVerdictProvider.classify(listOf(bad)).verdict)
        assertEquals(SecuritySignal.Verdict.KNOWN_GOOD, ScannerVerdictProvider.classify(listOf(clean)).verdict)
        assertEquals(SecuritySignal.Verdict.UNKNOWN, ScannerVerdictProvider.classify(listOf(failed)).verdict)
        assertEquals(SecuritySignal.Risk.HIGH, ScannerVerdictProvider.classify(listOf(failed)).risk)
    }

    @Test
    fun heuristicProviderTreatsInstallerAsRiskOnlyNotAThreatVerdict() {
        val trusted = HeuristicRiskProvider.classifyInstaller("com.android.vending")
        assertEquals(SecuritySignal.ProviderId.HEURISTIC, trusted.provider)
        assertEquals(SecuritySignal.Verdict.UNKNOWN, trusted.verdict)
        assertEquals(SecuritySignal.Risk.LOW, trusted.risk)

        val unknown = HeuristicRiskProvider.classifyInstaller(null)
        assertEquals(SecuritySignal.Risk.HIGH, unknown.risk)
        assertEquals(SecuritySignal.Verdict.UNKNOWN, unknown.verdict)
    }

    @Test
    fun phishingProviderMapsExistingBlocklistVerdictsWithoutUrlPayload() {
        val malicious = PhishingSignalProvider.classify(listOf(PhishingHeuristics.Verdict.MALICIOUS))
        assertNotNull(malicious)
        assertEquals(SecuritySignal.ProviderId.PHISHING, malicious!!.provider)
        assertEquals(SecuritySignal.Verdict.KNOWN_BAD, malicious.verdict)
        assertTrue(malicious.reasonCode.contains("blocklist"))

        val suspicious = PhishingSignalProvider.classify(listOf(PhishingHeuristics.Verdict.SUSPICIOUS))
        assertEquals(SecuritySignal.Risk.HIGH, suspicious?.risk)
        assertEquals(SecuritySignal.Verdict.UNKNOWN, suspicious?.verdict)
        assertNull(PhishingSignalProvider.classify(emptyList()))
    }

    @Test
    fun privacyProviderUsesExistingSensitivePermissionRiskGroups() {
        val high = PrivacySignalProvider.classify(setOf(PrivacyRisk.Group.SMS))
        assertEquals(SecuritySignal.ProviderId.PRIVACY, high.provider)
        assertEquals(SecuritySignal.Verdict.UNKNOWN, high.verdict)
        assertEquals(SecuritySignal.Risk.HIGH, high.risk)

        val medium = PrivacySignalProvider.classify(setOf(PrivacyRisk.Group.LOCATION))
        assertEquals(SecuritySignal.Risk.HIGH, medium.risk)

        val low = PrivacySignalProvider.classify(setOf(PrivacyRisk.Group.CAMERA))
        assertEquals(SecuritySignal.Risk.LOW, low.risk)
    }

    @Test
    fun healthScoreV1IsBoundedAndExplainsMissingCapabilities() {
        val score = AutoPilotHealthScoreV1.calculate(
            AutoPilotHealthInputs(
                scannerReady = false,
                definitionsFresh = false,
                usageAccessGranted = false,
                accessibilityAssistGranted = false
            )
        )
        assertEquals(15, score.value)
        assertEquals(AutoPilotHealthScore.Grade.LIMITED, score.grade)
        assertEquals(4, score.deductions.size)
        assertTrue(score.value in 0..100)
    }
}
