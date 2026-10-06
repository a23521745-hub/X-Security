package org.xsecurity.scanner.autopilot

/** Content-free digest snapshot; only verdict/action counts are aggregated. */
data class AutopilotDigest(
    val windowStartMillis: Long,
    val windowEndMillis: Long,
    val decisions: Int,
    val contained: Int,
    val prompts: Int,
    val warnings: Int
) {
    companion object {
        fun from(records: List<AuditRecord>, startMillis: Long, endMillis: Long): AutopilotDigest {
            val inWindow = records.filter { it.timestampMillis in startMillis..endMillis }
            return AutopilotDigest(
                windowStartMillis = startMillis,
                windowEndMillis = endMillis,
                decisions = inWindow.size,
                contained = inWindow.count {
                    it.decisionAction == PolicyAction.BLOCK_AND_QUARANTINE.name ||
                        it.decisionAction == PolicyAction.BLOCK_CONTENT.name
                },
                prompts = inWindow.count { it.decisionAction == PolicyAction.ASK_USER.name },
                warnings = inWindow.count { it.decisionAction == PolicyAction.RECOMMEND_CONTAINMENT.name }
            )
        }
    }
}
