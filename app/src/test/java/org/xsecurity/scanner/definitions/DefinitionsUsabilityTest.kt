package org.xsecurity.scanner.definitions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ApkScannerEngine
import java.io.File

/**
 * ALI-18 review: trial-load'un "motor acildi" demesi yetmez; dosyasi olan her
 * katman kullanilabilir sayida kural/imza vermeli, yoksa guncelleme reddedilir.
 */
class DefinitionsUsabilityTest {

    private fun tempFile(suffix: String, content: String): File {
        val file = File.createTempFile("xsec-usability-", suffix)
        file.deleteOnExit()
        file.writeText(content)
        return file
    }

    private val validYara = "rule Ok { strings: \$a = \"NEEDLE\" condition: any of them }"
    private val validNdb = "Test.Inner:0:*:494E4E45522D4E4545444C45\n"

    @Test
    fun emptyYaraWithValidClamIsRejected() {
        val engine = ApkScannerEngine.load(
            tempFile(".yar", ""),
            tempFile(".ndb", validNdb)
        ).getOrThrow()

        val reason = DefinitionsController.checkEffectiveUsability(
            engine, hasYaraFile = true, hasClamFile = true, hasHashFile = false
        )

        assertTrue(
            "YARA bosken guncelleme reddedilmeli, bos gecti",
            reason.orEmpty().contains("YARA")
        )
    }

    @Test
    fun emptyClamWithValidYaraIsRejected() {
        val engine = ApkScannerEngine.load(
            tempFile(".yar", validYara),
            tempFile(".ndb", "")
        ).getOrThrow()

        val reason = DefinitionsController.checkEffectiveUsability(
            engine, hasYaraFile = true, hasClamFile = true, hasHashFile = false
        )

        assertTrue(
            "ClamAV bosken guncelleme reddedilmeli, bos gecti",
            reason.orEmpty().contains("ClamAV")
        )
    }

    @Test
    fun validSetPassesAndMissingKindIsNotRequired() {
        val engine = ApkScannerEngine.load(
            tempFile(".yar", validYara),
            tempFile(".ndb", validNdb)
        ).getOrThrow()

        assertNull(
            DefinitionsController.checkEffectiveUsability(
                engine, hasYaraFile = true, hasClamFile = true, hasHashFile = false
            )
        )
        // Dosyasi olmayan katman aranmaz.
        assertNull(
            DefinitionsController.checkEffectiveUsability(
                engine, hasYaraFile = true, hasClamFile = false, hasHashFile = false
            )
        )
        assertEquals(1, engine.yaraRules.size)
        assertEquals(1, engine.clamAvSignatureCount)
    }
}
