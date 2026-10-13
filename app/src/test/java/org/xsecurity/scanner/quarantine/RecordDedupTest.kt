package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * P0 record dedup regression lock: scanning the same file (same sha256 + same sourcePath)
 * twice must leave exactly ONE record — the second scan updates the existing row
 * (new timestamp/state) instead of appending a second one.
 */
class RecordDedupTest {

    private val sha = "e".repeat(64)
    private val path = "/storage/emulated/0/Download/suspicious.apk"

    private fun record(
        id: String = "f-1",
        sha256: String? = sha,
        sourcePath: String? = path,
        sourceUri: String? = "file://$path",
        state: QuarantineState = QuarantineState.QUARANTINED
    ) = QuarantineRecord(
        id = id,
        packageName = QuarantineHonesty.FILE_VAULT_PACKAGE,
        label = "suspicious.apk",
        sha256 = sha256,
        verdict = "KNOWN_BAD",
        engine = "YARA",
        detectedAtMillis = 1_000L,
        updatedAtMillis = 1_000L,
        state = state,
        vaultFileName = "$id.xsv",
        residue = OriginalResidue.ORIGINAL_PRESENT,
        sourcePath = sourcePath,
        sourceUri = sourceUri
    )

    /** Simulates the staging path: apply the observation to the store (list) it would write to. */
    private fun applyObservation(
        store: MutableList<QuarantineRecord>,
        sha256: String?,
        sourcePath: String?,
        sourceUri: String?,
        nowMillis: Long
    ): String {
        val existing = RecordDedup.findExisting(store, sha256, sourcePath, sourceUri)
        val id = existing?.id ?: "f-${store.size + 1}"
        val updated = if (existing != null) {
            RecordDedup.reobserved(
                existing = existing,
                sha256 = sha256,
                label = "suspicious.apk",
                engine = "YARA",
                sizeBytes = 4096L,
                scanOrigin = QuarantineFormat.ORIGIN_FILE_PICKER,
                vaultFileName = "$id.xsv",
                sourcePath = sourcePath,
                sourceUri = sourceUri,
                nowMillis = nowMillis
            )
        } else {
            record(id = id, sha256 = sha256, sourcePath = sourcePath, sourceUri = sourceUri).copy(
                detectedAtMillis = nowMillis,
                updatedAtMillis = nowMillis
            )
        }
        store.removeAll { it.id == id }
        store.add(0, updated)
        return id
    }

    @Test
    fun sameFileScannedTwiceLeavesExactlyOneRecord() {
        val store = mutableListOf<QuarantineRecord>()
        val firstId = applyObservation(store, sha, path, "file://$path", nowMillis = 1_000L)
        val secondId = applyObservation(store, sha, path, "file://$path", nowMillis = 2_000L)

        assertEquals(1, store.size)
        assertEquals(firstId, secondId)
        val record = store.single()
        assertEquals(QuarantineState.QUARANTINED, record.state)
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, record.residue)
        assertEquals(2_000L, record.updatedAtMillis)
        assertEquals(2_000L, record.detectedAtMillis)
        assertEquals(4096L, record.sizeBytes)
        assertTrue(QuarantineHonesty.originalRemovalPending(record))
    }

    @Test
    fun rescanAfterTerminalStateReusesTheSameRow() {
        // A row that was restored/deleted by the user is still the same case and is updated,
        // never duplicated; re-staging only recreates the vault copy.
        val store = mutableListOf(record(state = QuarantineState.DELETED))
        val id = applyObservation(store, sha, path, "file://$path", nowMillis = 5_000L)
        assertEquals("f-1", id)
        assertEquals(1, store.size)
        assertEquals(QuarantineState.QUARANTINED, store.single().state)
        assertNull("a re-detection clears the previous cut result", store.single().cutResult)
    }

    @Test
    fun sameBytesAtADifferentPathStaysASeparateRecord() {
        val store = mutableListOf(record())
        val second = "/storage/emulated/0/Download/copy.apk"
        applyObservation(store, sha, second, "file://$second", nowMillis = 3_000L)
        assertEquals(2, store.size)
        assertNotEquals(store[0].id, store[1].id)
    }

    @Test
    fun differentBytesAtTheSamePathStaysASeparateRecord() {
        val store = mutableListOf(record())
        applyObservation(store, "f".repeat(64), path, "file://$path", nowMillis = 3_000L)
        assertEquals(2, store.size)
    }

    @Test
    fun identityFallsBackToTheSourceUriAndRequiresAHash() {
        assertEquals(
            "$sha|path:$path",
            RecordDedup.identity(sha, path, "file://$path")
        )
        assertEquals("$sha|uri:content://x/1", RecordDedup.identity(sha, null, "content://x/1"))
        assertNull(RecordDedup.identity(null, path, "file://$path"))
        assertNull(RecordDedup.identity(sha, null, null))
        assertTrue(RecordDedup.isSameCase(record(), sha.uppercase(), path, null))
        assertFalse(RecordDedup.isSameCase(record(), sha, null, "content://other/9"))
    }

    @Test
    fun packageRecordsAreNeverDeduplicatedIntoFileRecords() {
        val packageRecord = QuarantineRecord(
            id = "q-1",
            packageName = "com.evil.spy",
            label = "Spy",
            sha256 = sha,
            verdict = "KNOWN_BAD",
            engine = "YARA",
            detectedAtMillis = 1L,
            updatedAtMillis = 1L,
            sourcePath = path
        )
        assertFalse(RecordDedup.isSameCase(packageRecord, sha, path, "file://$path"))
        assertNull(RecordDedup.findExisting(listOf(packageRecord), sha, path, "file://$path"))
    }
}
