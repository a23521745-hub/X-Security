package org.xsecurity.scanner.autopilot

import org.xsecurity.scanner.device.InstalledApp
import org.xsecurity.scanner.quarantine.QuarantineRecord
import org.xsecurity.scanner.quarantine.QuarantineState

data class CachedKnownBadVerdict(
    val packageName: String,
    val apkSha256: String,
    val versionCode: Long,
    val lastUpdateTime: Long,
    val reasonCode: String,
    val provider: SecuritySignal.ProviderId
) {
    fun matchesInstalled(app: InstalledApp): Boolean =
        app.packageName == packageName && app.versionCode == versionCode && app.lastUpdateTime == lastUpdateTime
}

data class ForegroundInterception(
    val packageName: String,
    val verdict: SecuritySignal.Verdict,
    val provider: SecuritySignal.ProviderId,
    val reasonCode: String,
    val recordId: String? = null
)

data class ForegroundInterceptionInput(
    val packageName: String?,
    val isSystemPackage: Boolean,
    val activeBypass: Boolean,
    val quarantineRecord: QuarantineRecord? = null,
    val cachedKnownBad: CachedKnownBadVerdict? = null
)

/** Pure package-list decision; this policy does not invoke scanners or Android APIs. */
object ForegroundInterceptionPolicy {
    fun decide(input: ForegroundInterceptionInput): ForegroundInterception? {
        val packageName = input.packageName ?: return null
        if (packageName.isBlank() || input.isSystemPackage || input.activeBypass) return null

        val activeRecord = input.quarantineRecord
        if (activeRecord != null && activeRecord.packageName == packageName &&
            (activeRecord.state == QuarantineState.PENDING || activeRecord.state == QuarantineState.QUARANTINED)
        ) {
            val provider = if (activeRecord.engine.contains(SecuritySignal.ProviderId.SCANNER.name)) {
                SecuritySignal.ProviderId.SCANNER
            } else {
                SecuritySignal.ProviderId.LIFECYCLE
            }
            return ForegroundInterception(
                packageName = packageName,
                verdict = SecuritySignal.Verdict.KNOWN_BAD,
                provider = provider,
                reasonCode = "active_quarantine_${activeRecord.state.name.toLowerCase()}",
                recordId = activeRecord.id
            )
        }

        val cached = input.cachedKnownBad ?: return null
        if (cached.packageName != packageName || cached.provider != SecuritySignal.ProviderId.SCANNER) return null
        return ForegroundInterception(
            packageName = packageName,
            verdict = SecuritySignal.Verdict.KNOWN_BAD,
            provider = cached.provider,
            reasonCode = cached.reasonCode
        )
    }
}
