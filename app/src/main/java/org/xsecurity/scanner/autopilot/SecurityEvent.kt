package org.xsecurity.scanner.autopilot

/**
 * Device-local events consumed by the AutoPilot decision loop.
 *
 * Event payloads deliberately contain identifiers and timestamps only. In particular,
 * user-visible screen text is never part of an event and therefore cannot enter AuditLog.
 */
sealed class SecurityEvent(open val occurredAtMillis: Long) {
    abstract val type: Type
    open val packageName: String? get() = null
    open val isSystemPackage: Boolean get() = false

    enum class Type { PACKAGE_INSTALLED, FOREGROUND_APP, SCAN_DUE, DEFS_STALE, BOOT, MANUAL, FILE_SCAN }

    data class PackageInstalled(
        override val packageName: String,
        override val isSystemPackage: Boolean = false,
        val installerPackageName: String? = null,
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.PACKAGE_INSTALLED
    }

    data class ForegroundApp(
        override val packageName: String,
        override val isSystemPackage: Boolean = false,
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.FOREGROUND_APP
    }

    data class ScanDue(
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.SCAN_DUE
    }

    data class DefsStale(
        val lastSuccessfulUpdateMillis: Long,
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.DEFS_STALE
    }

    data class Boot(
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.BOOT
    }

    /** A user-initiated scan/request; optional target package, never raw screen text. */
    data class Manual(
        override val packageName: String? = null,
        override val isSystemPackage: Boolean = false,
        val origin: String = "manual",
        val includeSystemApps: Boolean = false,
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.MANUAL
    }

    /**
     * Ephemeral completed file scan metadata; path/hash never enter the durable audit record.
     * [path] is the scanned bytes (usually our app-private staged copy); [sourceUri] is where the
     * user's ORIGINAL lives so cut-and-paste quarantine can remove it after the user's tap.
     * Null means the original location is unknown and the record stays ORIGINAL_PRESENT.
     */
    data class FileScan(
        val path: String,
        val sha256: String?,
        val verdict: SecuritySignal.Verdict,
        val engine: String,
        val sourceUri: String? = null,
        override val occurredAtMillis: Long = System.currentTimeMillis()
    ) : SecurityEvent(occurredAtMillis) {
        override val type = Type.FILE_SCAN
        override fun toString(): String = "FileScan(verdict=$verdict, engine=$engine)"
    }

    fun hasRiskTarget(): Boolean = when (this) {
        is PackageInstalled, is ForegroundApp -> !packageName.isNullOrBlank()
        // Manual events may carry an ephemeral phishing payload in SignalRequest, but
        // that payload is not part of this event and is never persisted.
        is Manual, is FileScan -> true
        is ScanDue, is DefsStale, is Boot -> false
    }
}
