package org.xsecurity.scanner.autopilot

/** User-facing rationale categories for Android special access; none are Device Admin. */
enum class AutopilotPermission {
    BATTERY_EXEMPTION,
    OVERLAY,
    USAGE_ACCESS,
    ACCESSIBILITY,

    /**
     * All Files Access (MANAGE_EXTERNAL_STORAGE, API 30+) / legacy WRITE (API <= 29): lets the
     * user's one "Delete now" tap remove a vaulted threat directly instead of through the Android
     * delete dialog. Optional: without it the same tap routes through the system prompt.
     */
    ALL_FILES_ACCESS
}
