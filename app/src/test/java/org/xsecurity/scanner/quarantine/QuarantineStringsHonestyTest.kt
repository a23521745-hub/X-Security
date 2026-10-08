package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * HONESTY RULE on the real resources: EN and TR carry the same keys, every key used by
 * [QuarantineWording] exists in both, texts for ORIGINAL_PRESENT states say the original is still
 * on the device and never claim a quarantine/containment, and only ORIGINAL_REMOVED texts do.
 * Claiming a full quarantine while the original is intact is a release-blocking defect.
 */
class QuarantineStringsHonestyTest {
    private val en by lazy { strings("app/src/main/res/values/strings.xml") }
    private val tr by lazy { strings("app/src/main/res/values-tr/strings.xml") }

    @Test
    fun englishAndTurkishStringSetsAreSymmetric() {
        assertEquals("keys missing in TR: ${en.keys - tr.keys}", emptySet<String>(), en.keys - tr.keys)
        assertEquals("keys missing in EN: ${tr.keys - en.keys}", emptySet<String>(), tr.keys - en.keys)
    }

    @Test
    fun everyWordingKeyExistsInBothLanguages() {
        for (key in QuarantineWording.allKeys) {
            assertTrue("EN missing $key", en.containsKey(key))
            assertTrue("TR missing $key", tr.containsKey(key))
        }
    }

    @Test
    fun originalPresentTextsNeverClaimQuarantineAndSayTheOriginalIsStillThere() {
        for (key in QuarantineWording.originalPresentKeys) {
            val english = en.getValue(key)
            val turkish = tr.getValue(key)
            assertFalse("EN '$key' claims containment: $english", EN_FULL_CLAIM.containsMatchIn(english))
            assertFalse("TR '$key' claims containment: $turkish", TR_FULL_CLAIM.containsMatchIn(turkish))
            assertTrue("EN '$key' must say the original is still on the device: $english", EN_STILL_PRESENT.containsMatchIn(english))
            assertTrue("TR '$key' must say the original is still on the device: $turkish", TR_STILL_PRESENT.containsMatchIn(turkish))
        }
    }

    @Test
    fun failureHintsNeverClaimContainmentEither() {
        for (key in QuarantineWording.hintKeys) {
            assertFalse("EN '$key': ${en.getValue(key)}", EN_FULL_CLAIM.containsMatchIn(en.getValue(key)))
            assertFalse("TR '$key': ${tr.getValue(key)}", TR_FULL_CLAIM.containsMatchIn(tr.getValue(key)))
        }
    }

    @Test
    fun originalRemovedTextsSayTheOriginalWasRemoved() {
        for (key in QuarantineWording.originalRemovedKeys) {
            val english = en.getValue(key)
            val turkish = tr.getValue(key)
            assertTrue("EN '$key' must mention the removed original: $english", EN_REMOVED.containsMatchIn(english))
            assertTrue("TR '$key' must mention the removed original: $turkish", TR_REMOVED.containsMatchIn(turkish))
            assertFalse("EN '$key' must not hedge with 'still': $english", EN_STILL_PRESENT.containsMatchIn(english))
        }
    }

    @Test
    fun deleteNowActionIsTheTurkishSimdiSil() {
        assertEquals("Delete now", en.getValue(QuarantineWording.KEY_ACTION_DELETE_NOW))
        assertEquals("Şimdi Sil", tr.getValue(QuarantineWording.KEY_ACTION_DELETE_NOW))
    }

    @Test
    fun wordingMapsEveryDisplayStateHonestly() {
        // PRESENT display states map to present keys, the only full claim maps to a removed key.
        assertTrue(QuarantineWording.stateKey(QuarantineDisplayState.FILE_COPY_SAVED_ORIGINAL_PRESENT) in QuarantineWording.originalPresentKeys)
        assertTrue(QuarantineWording.stateKey(QuarantineDisplayState.FILE_COPY_DELETED_ORIGINAL_PRESENT) in QuarantineWording.originalPresentKeys)
        assertTrue(QuarantineWording.stateKey(QuarantineDisplayState.FILE_QUARANTINED_ORIGINAL_REMOVED) in QuarantineWording.originalRemovedKeys)
        for (display in QuarantineDisplayState.values()) {
            val key = QuarantineWording.stateKey(display) ?: continue
            if (QuarantineHonesty.claimsFullQuarantine(display)) assertTrue(key in QuarantineWording.originalRemovedKeys)
            else assertTrue(key in QuarantineWording.originalPresentKeys)
        }
        // Notification wording follows the record's residue, never the bare state.
        val present = QuarantineRecord(
            id = "a", packageName = QuarantineHonesty.FILE_VAULT_PACKAGE, label = "x", sha256 = null, verdict = "KNOWN_BAD",
            engine = "YARA", detectedAtMillis = 1, updatedAtMillis = 1, state = QuarantineState.QUARANTINED,
            residue = OriginalResidue.ORIGINAL_PRESENT
        )
        assertEquals(QuarantineWording.KEY_NOTIF_STAGED_TITLE, QuarantineWording.notificationKeys(present).first)
        assertEquals(
            QuarantineWording.KEY_NOTIF_REMOVED_TITLE,
            QuarantineWording.notificationKeys(present.copy(residue = OriginalResidue.ORIGINAL_REMOVED)).first
        )
        assertEquals(QuarantineWording.KEY_NOTIF_STAGED_TITLE, QuarantineWording.notificationKeys(present.copy(residue = null)).first)
    }

    @Test
    fun identityAndDetailKeysExistInBothLanguages() {
        // P0: the list shows real name/path/size/date; every identity field of the detail
        // view exists in EN and TR, and the origin vocabulary covers all origin values.
        for (key in QuarantineWording.recordIdentityKeys + QuarantineFormat.originKeys.values) {
            assertTrue("EN missing $key", en.containsKey(key))
            assertTrue("TR missing $key", tr.containsKey(key))
        }
        for (origin in listOf(
            QuarantineFormat.ORIGIN_DOWNLOAD_WATCH,
            QuarantineFormat.ORIGIN_FILE_PICKER,
            QuarantineFormat.ORIGIN_UNKNOWN,
            null
        )) {
            val key = QuarantineFormat.originKey(origin)
            assertTrue("missing origin text for '$origin'", en.containsKey(key) && tr.containsKey(key))
        }
        // Detail must name the SHA-256 explicitly (that is the only place the hash is shown).
        assertTrue(en.getValue(QuarantineWording.KEY_DETAIL_SHA256).contains("SHA-256"))
        for (key in QuarantineWording.recordIdentityKeys) {
            assertTrue("empty text for $key", en.getValue(key).isNotBlank() && tr.getValue(key).isNotBlank())
        }
    }

    @Test
    fun byteSizeFormattingIsReadableAndNeverNegative() {
        assertEquals("512 B", QuarantineFormat.formatBytes(512L, java.util.Locale.US))
        assertEquals("1.5 KB", QuarantineFormat.formatBytes(1536L, java.util.Locale.US))
        assertEquals("2.0 MB", QuarantineFormat.formatBytes(2L * 1024L * 1024L, java.util.Locale.US))
        assertNull(QuarantineFormat.formatBytes(null))
        assertNull(QuarantineFormat.formatBytes(-1L))
    }

    private fun strings(path: String): Map<String, String> {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(repoFile(path))
        val nodes = document.getElementsByTagName("string")
        val result = LinkedHashMap<String, String>()
        for (index in 0 until nodes.length) {
            val node = nodes.item(index)
            val name = node.attributes.getNamedItem("name").nodeValue
            result[name] = node.textContent
        }
        return result
    }

    /** Unit test working directory is the module directory (app/); walk up to the repository root. */
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
        val EN_FULL_CLAIM = Regex("\\b(quarantined|contained|neutrali[sz]ed)\\b", RegexOption.IGNORE_CASE)
        val TR_FULL_CLAIM = Regex("karantinaya alın|karantinada|dosya kaldırıldı|dosya silindi|etkisiz hale", RegexOption.IGNORE_CASE)
        val EN_STILL_PRESENT = Regex("original.*\\bstill\\b|\\bstill\\b.*original", RegexOption.IGNORE_CASE)
        val TR_STILL_PRESENT = Regex("orijinal.*(hâlâ|hala|duruyor)|(hâlâ|hala).*orijinal", RegexOption.IGNORE_CASE)
        val EN_REMOVED = Regex("original.*\\bremoved\\b|\\bremoved\\b.*original", RegexOption.IGNORE_CASE)
        val TR_REMOVED = Regex("orijinal.*(kaldırıldı|silindi)|(kaldırıldı|silindi).*orijinal", RegexOption.IGNORE_CASE)
    }
}
