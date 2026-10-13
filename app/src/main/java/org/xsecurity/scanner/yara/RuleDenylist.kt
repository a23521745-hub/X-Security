package org.xsecurity.scanner.yara

/**
 * Emergency rule denylist — the P0 false-positive brake (v19 live incident: system apps were
 * flagged).
 *
 * A rule whose ID matches [deniedPatterns] is skipped at LOAD time and can never match:
 * the check runs inside [YaraRuleParser], so it covers every source at once — the bundled
 * assets, the signed definitions channel, community YARA files and any user-supplied `.yar`.
 * Skipped IDs are counted ([YaraRuleSet.deniedRuleNames]), listed and reported
 * ([YaraRuleSet.problems] + engine warnings), never dropped silently.
 *
 * Patterns are exact rule IDs, or an ID prefix ending in `*` (the family form).
 */
object RuleDenylist {

    /** Rule IDs (or `prefix*` families) that must never reach a scan. */
    val deniedPatterns: List<String> = listOf(
        // Bank-trojan permission-combo heuristic: benign accessibility/overlay usage in system
        // and updated-system apps matches it, and the v19 incident showed the cost is higher
        // than the detection value. Disabled until the rule is reworked with a narrowing.
        "Android_Suspicious_Accessibility_Overlay_*"
    )

    /** Prefix of the report line written for every skipped rule. */
    const val PROBLEM_PREFIX = "denylist:"

    fun isDenied(ruleName: String?): Boolean {
        val name = ruleName?.trim()?.takeIf { it.isNotEmpty() } ?: return false
        return deniedPatterns.any { pattern ->
            if (pattern.endsWith("*")) {
                // "Foo_*" matches "Foo_Bar" but not "Foo" itself (family pattern, YARA-style).
                val prefix = pattern.dropLast(1)
                name.startsWith(prefix) && name.length > prefix.length
            } else {
                name.equals(pattern, ignoreCase = false)
            }
        }
    }

    /** Human-readable, single-line report entry for a skipped rule ID. */
    fun problem(ruleName: String): String =
        "$PROBLEM_PREFIX $ruleName skipped (emergency false-positive brake; rule ID is denylisted)"
}
