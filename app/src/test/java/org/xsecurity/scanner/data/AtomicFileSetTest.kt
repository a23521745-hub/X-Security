package org.xsecurity.scanner.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * ALI-18 #2: tanim seti atomik kurulum + geri alma kilidi.
 *
 * Kapatilan delik: tek-tek kurulumda sonraki dosya patlarsa karisik set
 * (ve `delete()+renameTo()` sirasinda aktif dosyanin tamamen silinmesi).
 */
class AtomicFileSetTest {

    private fun workDir(): File =
        Files.createTempDirectory("xsec-atomic-").toFile()

    private fun staged(dir: File, name: String, content: String): File {
        val temp = File.createTempFile("xsec-staged-", ".tmp", dir)
        temp.deleteOnExit()
        temp.writeText(content)
        return temp
    }

    @Test
    fun happyPathSwapsAllFilesAndCleansBackups() {
        val dir = workDir()
        try {
            File(dir, "rules.yar").writeText("OLD-YARA")
            File(dir, "signatures.ndb").writeText("OLD-NDB")

            val outcome = AtomicFileSet.installSet(
                dir,
                mapOf(
                    "rules.yar" to staged(dir, "rules.yar", "NEW-YARA"),
                    "signatures.ndb" to staged(dir, "signatures.ndb", "NEW-NDB")
                )
            )

            assertTrue(outcome is AtomicFileSet.Outcome.Committed)
            assertEquals("NEW-YARA", File(dir, "rules.yar").readText())
            assertEquals("NEW-NDB", File(dir, "signatures.ndb").readText())
            assertTrue(
                "yedek kalmamali: ${dir.listFiles()?.map { it.name }}",
                dir.listFiles().orEmpty().none { it.name.endsWith(".bak") }
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun midFailureRollsBackAndNeverDeletesActiveFile() {
        val dir = workDir()
        try {
            File(dir, "rules.yar").writeText("OLD-YARA")
            // Ikinci hedef bloke: ayni yolda DIZIN var -> renameTo patlar.
            File(dir, "signatures.ndb").mkdir()

            val outcome = AtomicFileSet.installSet(
                dir,
                mapOf(
                    "rules.yar" to staged(dir, "rules.yar", "NEW-YARA"),
                    "signatures.ndb" to staged(dir, "signatures.ndb", "NEW-NDB")
                )
            )

            assertTrue(outcome is AtomicFileSet.Outcome.RolledBack)
            // Birinci dosya coktan takas edilmisti: orijinal baytlar geri gelmeli.
            assertEquals("OLD-YARA", File(dir, "rules.yar").readText())
            // Aktif dosya ASLA silinmemeli; bloke hedef oldugu gibi durmali.
            assertTrue(File(dir, "signatures.ndb").isDirectory)
            assertTrue(
                "yedek kalmamali: ${dir.listFiles()?.map { it.name }}",
                dir.listFiles().orEmpty().none { it.name.endsWith(".bak") }
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rollbackDeletesTargetsCreatedByFailedInstall() {
        val dir = workDir()
        try {
            // rules.yar onceden YOK (yeni kurulum); ikinci hedef bloke.
            File(dir, "signatures.ndb").mkdir()

            val outcome = AtomicFileSet.installSet(
                dir,
                mapOf(
                    "rules.yar" to staged(dir, "rules.yar", "NEW-YARA"),
                    "signatures.ndb" to staged(dir, "signatures.ndb", "NEW-NDB")
                )
            )

            assertTrue(outcome is AtomicFileSet.Outcome.RolledBack)
            assertFalse(
                "basarisiz kurulumun olusturdugu hedef kalmamali",
                File(dir, "rules.yar").exists()
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun staleBackupIsReplaced() {
        val dir = workDir()
        try {
            File(dir, "rules.yar").writeText("OLD")
            File(dir, "rules.yar.bak").writeText("STALE-BACKUP")

            val outcome = AtomicFileSet.installSet(
                dir,
                mapOf("rules.yar" to staged(dir, "rules.yar", "NEW"))
            )

            assertTrue(outcome is AtomicFileSet.Outcome.Committed)
            assertEquals("NEW", File(dir, "rules.yar").readText())
            assertFalse(File(dir, "rules.yar.bak").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun emptyStagedSetIsNoop() {
        val dir = workDir()
        try {
            assertTrue(AtomicFileSet.installSet(dir, emptyMap()) is AtomicFileSet.Outcome.Committed)
        } finally {
            dir.deleteRecursively()
        }
    }
}
