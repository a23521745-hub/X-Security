package org.xsecurity.scanner.autopilot

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.community.CommunityStore
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.device.InstalledAppsSource
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.phishing.PhishingHeuristics
import org.xsecurity.scanner.phishing.PhishingScanner
import org.xsecurity.scanner.phishing.PhishingStore
import org.xsecurity.scanner.privacy.PrivacyRisk
import org.xsecurity.scanner.privacy.PrivacyScanner

/** Android-facing signal adapter. PolicyEngine itself remains pure Kotlin/JVM. */
interface SignalProvider {
    suspend fun provide(
        context: Context,
        event: SecurityEvent,
        request: SignalRequest = SignalRequest()
    ): SecuritySignal?
}

/** Existing YARA/ClamAV/hash scanner -> known-bad/known-good/unknown. */
class ScannerVerdictProvider(
    private val scanPackage: suspend (Context, String) -> List<ScanResult> = Companion::scanInstalledPackage
) : SignalProvider {
    override suspend fun provide(context: Context, event: SecurityEvent, request: SignalRequest): SecuritySignal? {
        if (event !is SecurityEvent.PackageInstalled && event !is SecurityEvent.Manual) return null
        val packageName = event.packageName?.takeIf { event.hasRiskTarget() } ?: return null
        if (event.isSystemPackage) return null
        val results = try {
            scanPackage(context.applicationContext, packageName)
        } catch (_: Exception) {
            return signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.HIGH,
                "scanner_result_unavailable",
                SecuritySignal.ProviderId.SCANNER
            )
        }
        return classify(results)
    }

    companion object {
        fun classify(results: List<ScanResult>): SecuritySignal = when {
            results.any { it.status == org.xsecurity.scanner.engine.ScanStatus.THREATS_FOUND || it.threats.isNotEmpty() } ->
                signal(SecuritySignal.Verdict.KNOWN_BAD, SecuritySignal.Risk.HIGH, "signature_match")
            results.isNotEmpty() && results.all { it.isComplete && !it.isInfected } ->
                signal(SecuritySignal.Verdict.KNOWN_GOOD, SecuritySignal.Risk.LOW, "complete_scan_no_match")
            else -> signal(SecuritySignal.Verdict.UNKNOWN, SecuritySignal.Risk.HIGH, "scan_incomplete")
        }

        private suspend fun scanInstalledPackage(context: Context, packageName: String): List<ScanResult> =
            withContext(Dispatchers.IO) {
                val app = InstalledAppsSource.loadOne(context, packageName)
                    ?: return@withContext emptyList()
                val yara = SignatureStore.fileOrNull(context, SignatureStore.Kind.YARA)
                val clam = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_AV)
                val hashes = SignatureStore.fileOrNull(context, SignatureStore.Kind.CLAM_HASHES)
                val engine = ScanEngines.acquire(
                    yara,
                    clam,
                    hashes,
                    CommunityStore.enabledYaraFiles(context),
                    CommunityStore.enabledHashFiles(context)
                ).getOrNull() ?: return@withContext emptyList()
                app.apkPaths.map { path ->
                    runCatching { engine.scan(java.io.File(path)) }
                        .getOrElse { ScanResult.failed(path, it.message ?: it.javaClass.simpleName) }
                }
            }
    }
}

/** Install-source heuristic. It never treats a store name as a malware verdict. */
class HeuristicRiskProvider : SignalProvider {
    override suspend fun provide(context: Context, event: SecurityEvent, request: SignalRequest): SecuritySignal? {
        val packageName = event.packageName?.takeIf { event.hasRiskTarget() } ?: return null
        if (event.isSystemPackage) return null
        val installer = (event as? SecurityEvent.PackageInstalled)?.installerPackageName
            ?: getInstaller(context, packageName)
        return classifyInstaller(installer)
    }

    companion object {
        private val trustedInstallers = setOf(
            "com.android.vending",
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "org.fdroid.fdroid",
            "com.sec.android.app.samsungapps"
        )

        fun classifyInstaller(installerPackageName: String?): SecuritySignal = when {
            installerPackageName.isNullOrBlank() -> signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.HIGH,
                "installer_unknown_or_sideloaded",
                SecuritySignal.ProviderId.HEURISTIC
            )
            installerPackageName in trustedInstallers -> signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.LOW,
                "installer_recognized",
                SecuritySignal.ProviderId.HEURISTIC
            )
            else -> signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.HIGH,
                "installer_unrecognized",
                SecuritySignal.ProviderId.HEURISTIC
            )
        }

        private fun getInstaller(context: Context, packageName: String): String? = try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (_: SecurityException) {
            null
        } catch (_: RuntimeException) {
            null
        }
    }
}

/** Existing local phishing list + heuristics; only verdict codes leave this provider. */
class PhishingSignalProvider(
    private val readBlocklist: (Context) -> Set<String> = PhishingStore::blocklist
) : SignalProvider {
    override suspend fun provide(context: Context, event: SecurityEvent, request: SignalRequest): SecuritySignal? {
        val text = request.phishingText?.takeIf { it.isNotBlank() } ?: return null
        val findings = PhishingScanner.scanText(text, readBlocklist(context.applicationContext))
        return classify(findings.map { it.verdict })
    }

    companion object {
        fun classify(verdicts: List<PhishingHeuristics.Verdict>): SecuritySignal? = when {
            verdicts.isEmpty() -> null
            verdicts.any { it == PhishingHeuristics.Verdict.MALICIOUS } -> signal(
                SecuritySignal.Verdict.KNOWN_BAD,
                SecuritySignal.Risk.HIGH,
                "phishing_blocklist_match",
                SecuritySignal.ProviderId.PHISHING
            )
            verdicts.any { it == PhishingHeuristics.Verdict.SUSPICIOUS } -> signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.HIGH,
                "phishing_heuristic_warning",
                SecuritySignal.ProviderId.PHISHING
            )
            else -> signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.LOW,
                "phishing_no_heuristic_match",
                SecuritySignal.ProviderId.PHISHING
            )
        }
    }
}

/** Existing privacy scanner + permission-group risk model, scoped to the event package. */
class PrivacySignalProvider : SignalProvider {
    override suspend fun provide(context: Context, event: SecurityEvent, request: SignalRequest): SecuritySignal? {
        val packageName = event.packageName?.takeIf { event.hasRiskTarget() } ?: return null
        if (event.isSystemPackage) return null
        val app = try {
            withContext(Dispatchers.IO) {
                PrivacyScanner.scan(context.applicationContext).firstOrNull { it.packageName == packageName }
            }
        } catch (_: Exception) {
            return signal(
                SecuritySignal.Verdict.UNKNOWN,
                SecuritySignal.Risk.HIGH,
                "privacy_signal_unavailable",
                SecuritySignal.ProviderId.PRIVACY
            )
        } ?: return null
        return classify(PrivacyRisk.groupsFor(app.grantedPermissions))
    }

    companion object {
        fun classify(groups: Set<PrivacyRisk.Group>): SecuritySignal {
            val level = PrivacyRisk.levelFor(groups)
            val risk = if (level == PrivacyRisk.Level.LOW) {
                SecuritySignal.Risk.LOW
            } else {
                // Medium privacy exposure is not proof of malware, but still warrants a prompt.
                SecuritySignal.Risk.HIGH
            }
            return signal(
                verdict = SecuritySignal.Verdict.UNKNOWN,
                risk = risk,
                reason = when (level) {
                    PrivacyRisk.Level.HIGH -> "privacy_sensitive_permissions_high"
                    PrivacyRisk.Level.MEDIUM -> "privacy_sensitive_permissions_medium"
                    PrivacyRisk.Level.LOW -> "privacy_sensitive_permissions_low"
                },
                provider = SecuritySignal.ProviderId.PRIVACY
            )
        }
    }
}

private fun signal(
    verdict: SecuritySignal.Verdict,
    risk: SecuritySignal.Risk,
    reason: String,
    provider: SecuritySignal.ProviderId = SecuritySignal.ProviderId.SCANNER
): SecuritySignal = SecuritySignal(provider, verdict, risk, reason)
