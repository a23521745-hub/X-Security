package org.xsecurity.scanner.autopilot

/**
 * Compact, content-free result emitted by one signal provider. [reasonCode] is a
 * stable identifier (not provider-supplied text) so audit records never contain
 * URLs, message bodies, accessibility text, or other screen content.
 */
data class SecuritySignal(
    val provider: ProviderId,
    val verdict: Verdict,
    val risk: Risk,
    val reasonCode: String
) {
    enum class ProviderId { SCANNER, HEURISTIC, PHISHING, PRIVACY, LIFECYCLE }
    enum class Verdict { KNOWN_BAD, KNOWN_GOOD, UNKNOWN }
    enum class Risk { LOW, HIGH }
}

/** Ephemeral input for providers. It is never serialized or copied into AuditRecord. */
data class SignalRequest(
    val phishingText: String? = null
)
