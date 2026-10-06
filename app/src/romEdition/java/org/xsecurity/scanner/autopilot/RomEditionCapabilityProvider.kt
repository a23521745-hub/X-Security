package org.xsecurity.scanner.autopilot

import android.content.Context
import org.xsecurity.scanner.quarantine.SoftQuarantineResult

/**
 * ROM-edition integration boundary. Future ROM capabilities must be explicit,
 * permissioned by the ROM, per-action audited, and must preserve the package
 * safelist and the no-auto-delete invariant. It must not invoke root/shell as an
 * implicit fallback. These are TODO-only integration points; use the rootless
 * provider until the ROM API and its trust contract are implemented.
 */
class RomEditionCapabilityProvider : CapabilityProvider {
    override fun hasCapability(context: Context, capability: Capability): Boolean =
        TODO("Integrate a documented, ROM-granted capability and preserve rootless fallback behavior")

    override fun quarantine(context: Context, packageName: String, recordId: String): SoftQuarantineResult =
        TODO("Use only the ROM's explicit package-quarantine API; never delete, bypass safelists, or skip audit")
}
