package org.xsecurity.scanner.autopilot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.xsecurity.scanner.quarantine.QuarantineRecord
import org.xsecurity.scanner.quarantine.QuarantineState

class ForegroundInterceptionPolicyTest {
    private val packageName = "com.example.bad"

    @Test
    fun onlyActiveQuarantineStatesIntercept() {
        listOf(QuarantineState.PENDING, QuarantineState.QUARANTINED).forEach { state ->
            val result = ForegroundInterceptionPolicy.decide(
                ForegroundInterceptionInput(
                    packageName = packageName,
                    isSystemPackage = false,
                    activeBypass = false,
                    quarantineRecord = record(state)
                )
            )
            assertNotNull(result)
            assertEquals("active_quarantine_${state.name.lowercase()}", result?.reasonCode)
            assertEquals("record-1", result?.recordId)
        }

        listOf(QuarantineState.DETECTED, QuarantineState.RESTORED, QuarantineState.FAILED, QuarantineState.CANCELLED)
            .forEach { state ->
                assertNull(
                    ForegroundInterceptionPolicy.decide(
                        ForegroundInterceptionInput(
                            packageName = packageName,
                            isSystemPackage = false,
                            activeBypass = false,
                            quarantineRecord = record(state)
                        )
                    )
                )
            }
    }

    @Test
    fun cachedKnownBadVerdictInterceptsMatchingPackageOnly() {
        val cached = CachedKnownBadVerdict(
            packageName = packageName,
            apkSha256 = "a".repeat(64),
            versionCode = 4,
            lastUpdateTime = 100,
            reasonCode = "signature_match",
            provider = SecuritySignal.ProviderId.SCANNER
        )
        val result = ForegroundInterceptionPolicy.decide(
            ForegroundInterceptionInput(packageName, false, false, cachedKnownBad = cached)
        )
        assertEquals(SecuritySignal.Verdict.KNOWN_BAD, result?.verdict)
        assertEquals("signature_match", result?.reasonCode)
        assertNull(
            ForegroundInterceptionPolicy.decide(
                ForegroundInterceptionInput("com.example.other", false, false, cachedKnownBad = cached)
            )
        )
    }

    @Test
    fun unlistedSystemAndBypassedPackagesNeverIntercept() {
        assertNull(ForegroundInterceptionPolicy.decide(ForegroundInterceptionInput(packageName, false, false)))
        assertNull(
            ForegroundInterceptionPolicy.decide(
                ForegroundInterceptionInput(packageName, true, false, quarantineRecord = record(QuarantineState.QUARANTINED))
            )
        )
        assertNull(
            ForegroundInterceptionPolicy.decide(
                ForegroundInterceptionInput(packageName, false, true, cachedKnownBad = cachedVerdict())
            )
        )
    }

    private fun record(state: QuarantineState) = QuarantineRecord(
        id = "record-1",
        packageName = packageName,
        label = "Not shown in the warning",
        sha256 = null,
        verdict = "KNOWN_BAD",
        engine = "SCANNER",
        detectedAtMillis = 10,
        updatedAtMillis = 20,
        state = state
    )

    private fun cachedVerdict() = CachedKnownBadVerdict(
        packageName = packageName,
        apkSha256 = "b".repeat(64),
        versionCode = 1,
        lastUpdateTime = 2,
        reasonCode = "signature_match",
        provider = SecuritySignal.ProviderId.SCANNER
    )
}
