package org.xsecurity.scanner.autopilot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.device.InstalledApp
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * P0 emergency brake regression lock (v19 live incident: system apps flagged).
 *
 * A verdict on a system / updated-system package is a report, never an action: system-package
 * scan results carry the "Sistem uygulaması, işlem yok" treatment in BOTH languages and must
 * never offer a Remove/Quarantine control.
 */
class SystemPackageTreatmentTest {

    @Test
    fun systemAndUpdatedSystemPackagesAreReportOnly() {
        // Flags come from InstalledApp (FLAG_SYSTEM = 1, FLAG_UPDATED_SYSTEM_APP = 1 shl 7).
        assertTrue(InstalledApp(packageName = "a", label = "A", sourceDir = "/x", flags = InstalledApp.FLAG_SYSTEM).isSystem)
        assertTrue(
            InstalledApp(
                packageName = "a", label = "A", sourceDir = "/x",
                flags = InstalledApp.FLAG_UPDATED_SYSTEM_APP
            ).isUpdatedSystem
        )

        val systemFlags = InstalledApp.FLAG_SYSTEM or InstalledApp.FLAG_UPDATED_SYSTEM_APP
        assertTrue(SystemPackageSafelist.isSystemFlags(systemFlags))
        assertFalse(SystemPackageSafelist.isSystemFlags(0))

        assertTrue(SystemPackageTreatment.isSafelisted(true))
        assertFalse(SystemPackageTreatment.allowsRemovalActions(true))
        assertFalse(SystemPackageTreatment.allowsContainmentActions(true))
        assertEquals(SystemPackageTreatment.NOTICE_KEY, SystemPackageTreatment.noticeKey(true))

        assertFalse(SystemPackageTreatment.isSafelisted(false))
        assertTrue(SystemPackageTreatment.allowsRemovalActions(false))
        assertTrue(SystemPackageTreatment.allowsContainmentActions(false))
        assertNull(SystemPackageTreatment.noticeKey(false))
    }

    @Test
    fun noticeIsSymmetricAndTurkishTextSaysNoActionTaken() {
        val en = strings("app/src/main/res/values/strings.xml")
        val tr = strings("app/src/main/res/values-tr/strings.xml")
        for (key in listOf(SystemPackageTreatment.NOTICE_KEY, SystemPackageTreatment.DETAIL_KEY)) {
            assertNotNull("EN missing $key", en[key])
            assertNotNull("TR missing $key", tr[key])
        }
        // The exact treatment demanded by the incident: "sistem uygulaması, işlem yok".
        assertTrue(
            "TR notice must say 'Sistem uygulaması' and 'işlem yok': ${tr.getValue(SystemPackageTreatment.NOTICE_KEY)}",
            tr.getValue(SystemPackageTreatment.NOTICE_KEY).contains("Sistem uygulaması") &&
                tr.getValue(SystemPackageTreatment.NOTICE_KEY).contains("işlem yok")
        )
        assertTrue(
            "TR detail must say 'işlem yok' too: ${tr.getValue(SystemPackageTreatment.DETAIL_KEY)}",
            tr.getValue(SystemPackageTreatment.DETAIL_KEY).contains("işlem yok")
        )
        // Neither text may claim a containment/quarantine happened.
        for (value in listOf(en.getValue(SystemPackageTreatment.NOTICE_KEY), tr.getValue(SystemPackageTreatment.NOTICE_KEY))) {
            assertFalse("must not claim containment: $value", FULL_CLAIM.containsMatchIn(value))
        }
    }

    private fun strings(path: String): Map<String, String> {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(repoFile(path))
        val nodes = document.getElementsByTagName("string")
        val result = LinkedHashMap<String, String>()
        for (index in 0 until nodes.length) {
            val node = nodes.item(index)
            result[node.attributes.getNamedItem("name").nodeValue] = node.textContent
        }
        return result
    }

    private fun repoFile(path: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".")
        while (dir != null) {
            val candidate = File(dir, path)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        throw AssertionError("repository file not found: $path (user.dir=${System.getProperty("user.dir")})")
    }

    private companion object {
        val FULL_CLAIM = Regex("\\b(quarantined|contained|neutrali[sz]ed)\\b|karantinaya alın|karantinada", RegexOption.IGNORE_CASE)
    }
}
