package org.xsecurity.scanner.autopilot

/**
 * P0 EMERGENCY BRAKE: a heuristic verdict on a system / updated-system package must never turn
 * into an action.
 *
 * Every scan-result surface (installed-app scan card, scan notifications, quarantine list)
 * consults this together with [SystemPackageSafelist]: a system package is shown as
 * "system app — no action taken" and offers NO Remove/Quarantine/Retry control. The
 * uninstall-intent choke point ([org.xsecurity.scanner.quarantine.QuarantineUserActions])
 * additionally refuses a system package, so a stale or mis-wired UI cannot act either.
 *
 * Pure decision helper (no Android types) so the treatment is unit-tested on the JVM, and the
 * wording keys are pinned so both language files must carry the notice.
 */
object SystemPackageTreatment {
    const val NOTICE_KEY = "scan_result_system_package_notice"
    const val DETAIL_KEY = "scan_result_system_package_detail"

    /** True for system and updated-system packages: report only, never act. */
    fun isSafelisted(isSystemPackage: Boolean): Boolean = isSystemPackage

    /** Removal controls (Remove / uninstall) are offered only for non-safelisted packages. */
    fun allowsRemovalActions(isSystemPackage: Boolean): Boolean = !isSystemPackage

    /** Containment controls (quarantine, restart of a soft quarantine) follow the same rule. */
    fun allowsContainmentActions(isSystemPackage: Boolean): Boolean = !isSystemPackage

    /** Notice to render instead of the actions, or null when the package is actionable. */
    fun noticeKey(isSystemPackage: Boolean): String? = if (isSystemPackage) NOTICE_KEY else null
}
