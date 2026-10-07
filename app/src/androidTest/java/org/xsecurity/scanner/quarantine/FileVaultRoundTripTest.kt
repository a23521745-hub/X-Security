package org.xsecurity.scanner.quarantine

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
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
}
