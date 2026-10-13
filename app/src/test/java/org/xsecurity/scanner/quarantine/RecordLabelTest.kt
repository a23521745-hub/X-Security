package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * P0 record identity regression lock.
 *
 * The v19 incident: quarantine file records were listed under a vault entry name, the staged
 * copy name (`<sha256>.apk`) or a hash — with a forced `.apk` extension even for non-APK files.
 * These tests pin the rule: the label is the REAL file name with the file's OWN extension, a
 * placeholder is never shown, and legacy rows are backfilled from sourcePath / sourceUri.
 */
class RecordLabelTest {

    private fun record(
        label: String,
        sha256: String? = "a".repeat(64),
        vaultFileName: String? = "f-1.xsv",
        sourcePath: String? = null,
        sourceUri: String? = null
    ) = QuarantineRecord(
        id = "f-1",
        packageName = QuarantineHonesty.FILE_VAULT_PACKAGE,
        label = label,
        sha256 = sha256,
        verdict = "KNOWN_BAD",
        engine = "YARA",
        detectedAtMillis = 1L,
        updatedAtMillis = 1L,
        vaultFileName = vaultFileName,
        sourcePath = sourcePath,
        sourceUri = sourceUri
    )

    @Test
    fun realNameIsUsedAsIsWithItsOwnExtension() {
        val label = RecordLabel.derive("/storage/emulated/0/Download/photo.zip", null)
        assertEquals("photo.zip", label)
        assertEquals("photo.zip", RecordLabel.displayName(record("photo.zip", sourcePath = "/storage/emulated/0/Download/photo.zip")))
    }

    @Test
    fun extensionIsNeverForcedToApk() {
        // A file that is not an APK keeps its real extension; a file without an extension keeps none.
        assertEquals("invoice.pdf", RecordLabel.derive("/sdcard/Documents/invoice.pdf", null))
        assertEquals("noextension", RecordLabel.derive("/sdcard/Download/noextension", null))
        assertEquals("photo.zip", RecordLabel.fromUri("content://com.android.externalstorage.documents/document/primary%3ADownload%2Fphoto.zip"))
        assertFalse(RecordLabel.derive("/sdcard/Download/photo.zip", null)!!.endsWith(".apk"))
        assertNull(RecordLabel.fromUri("content://com.android.providers.downloads.documents/document/msd%3A1234"))
    }

    @Test
    fun hashAndVaultNamesArePlaceholdersAndNeverShown() {
        val sha = "b".repeat(64)
        // The staged scan copy name (`<sha256>.apk`) is exactly the forced-extension bug.
        assertTrue(RecordLabel.isPlaceholder("$sha.apk", sha, "f-1.xsv"))
        assertTrue(RecordLabel.isPlaceholder("$sha.xsv", sha, "f-1.xsv"))
        assertTrue(RecordLabel.isPlaceholder(sha, sha, null))
        assertTrue(RecordLabel.isPlaceholder("f-1.xsv", sha, "f-1.xsv"))
        assertTrue(RecordLabel.isPlaceholder("file-vault", sha, null))
        assertTrue(RecordLabel.isPlaceholder("", sha, null))
        assertTrue(RecordLabel.isPlaceholder(RecordLabel.UNKNOWN_FILENAME, sha, null))
        assertFalse(RecordLabel.isPlaceholder("holiday-photo.png", sha, "f-1.xsv"))

        // displayName() refuses to show any of them.
        assertNull(RecordLabel.displayName(record("$sha.apk")))
        assertNull(RecordLabel.displayName(record(sha)))
        assertNull(RecordLabel.displayName(record("f-1.xsv")))
        assertEquals("report.docx", RecordLabel.displayName(record("report.docx")))
    }

    @Test
    fun labelIsNeverTheVaultNameOrTheHash() {
        val sha = "c".repeat(64)
        for (label in listOf("$sha.apk", sha, "f-9.xsv", "file-vault")) {
            val shown = RecordLabel.displayName(record(label, sha256 = sha, vaultFileName = "f-9.xsv"))
            assertNull("placeholder '$label' must not be shown", shown)
        }
    }

    @Test
    fun backfillRecoversTheRealNameFromSourcePathOrUri() {
        val sha = "d".repeat(64)
        // Legacy row: label was the hash with a forced .apk; the original path is known.
        assertEquals(
            "setup.exe",
            RecordLabel.backfill("$sha.apk", sha, "f-2.xsv", "/storage/emulated/0/Download/setup.exe", null)
        )
        // Legacy row with only a SAF content URI.
        assertEquals(
            "notes.txt",
            RecordLabel.backfill(
                "f-2.xsv".uppercase(),
                sha,
                "f-2.xsv",
                null,
                "content://com.android.externalstorage.documents/document/primary%3ADocuments%2Fnotes.txt"
            )
        )
        // A real label is left alone, and an unknown location cannot improve anything.
        assertNull(RecordLabel.backfill("holiday.jpg", sha, "f-2.xsv", "/sdcard/Download/a.apk", null))
        assertNull(RecordLabel.backfill("$sha.apk", sha, "f-2.xsv", null, null))
    }
}
