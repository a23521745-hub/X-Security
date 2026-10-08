package org.xsecurity.scanner.quarantine

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xsecurity.scanner.core.Digest
import java.io.File

@RunWith(AndroidJUnit4::class)
class FileVaultRoundTripTest {
    @Test fun encryptedStoreCanBeRestoredExactly() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val input = "known-bad test fixture — content stays local".toByteArray()
        val source = File(context.cacheDir, "vault-source-${System.nanoTime()}").apply { writeBytes(input) }
        val restored = File(context.cacheDir, "vault-restored-${System.nanoTime()}")
        try {
            val stored = FileVault.store(context, source, "test-${System.nanoTime()}")
            FileVault.restoreTo(context, stored.fileName, restored)
            assertArrayEquals(input, restored.readBytes())
        } finally {
            source.delete()
            restored.delete()
        }
    }

    /** The gate before an original is ever removed: the vault entry must decrypt to the scanned hash. */
    @Test fun verifyChecksTheDecryptedHashWithoutWritingPlaintextAndDeleteRemovesTheEntry() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val input = "cut-and-paste fixture".toByteArray()
        val source = File(context.cacheDir, "vault-verify-${System.nanoTime()}").apply { writeBytes(input) }
        try {
            val stored = FileVault.store(context, source, "verify-${System.nanoTime()}")
            assertEquals(Digest.sha256Hex(input), stored.sha256)
            assertTrue(FileVault.exists(context, stored.fileName))
            assertTrue(FileVault.verify(context, stored.fileName, stored.sha256))
            assertTrue(FileVault.verify(context, stored.fileName, null))
            assertFalse(FileVault.verify(context, stored.fileName, "00".repeat(32)))
            assertFalse(FileVault.verify(context, "missing-entry.xsv", stored.sha256))
            assertTrue(FileVault.delete(context, stored.fileName))
            assertFalse(FileVault.exists(context, stored.fileName))
            assertFalse(FileVault.verify(context, stored.fileName, stored.sha256))
        } finally {
            source.delete()
        }
    }
}
