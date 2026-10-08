package org.xsecurity.scanner.device

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DownloadWatchPolicyTest {

    @Test
    fun acceptsApkBundlesOnly() {
        assertTrue(DownloadWatchPolicy.isCandidateName("app.apk"))
        assertTrue(DownloadWatchPolicy.isCandidateName("App-Release.APK"))
        assertTrue(DownloadWatchPolicy.isCandidateName("bundle.apks"))
        assertTrue(DownloadWatchPolicy.isCandidateName("game.xapk"))
        assertFalse(DownloadWatchPolicy.isCandidateName("photo.jpg"))
        assertFalse(DownloadWatchPolicy.isCandidateName("archive.zip"))
        assertFalse(DownloadWatchPolicy.isCandidateName(""))
        assertFalse(DownloadWatchPolicy.isCandidateName(null))
    }

    @Test
    fun skipsBrowserTemporariesAndHiddenFiles() {
        assertFalse(DownloadWatchPolicy.isCandidateName("app.apk.crdownload"))
        assertFalse(DownloadWatchPolicy.isCandidateName("app.apk.part"))
        assertFalse(DownloadWatchPolicy.isCandidateName("app.apk.tmp"))
        assertFalse(DownloadWatchPolicy.isCandidateName("app.apk.download"))
        assertFalse(DownloadWatchPolicy.isCandidateName(".hidden.apk"))
    }

    @Test
    fun onlyCloseWriteOrMovedToTriggerScan() {
        assertTrue(DownloadWatchPolicy.shouldScan(DownloadWatchPolicy.EVENT_CLOSE_WRITE, "a.apk"))
        assertTrue(DownloadWatchPolicy.shouldScan(DownloadWatchPolicy.EVENT_MOVED_TO, "a.apk"))
        // CREATE (0x100) / MODIFY (0x2): dosya henuz yazilmakta, taranmaz.
        assertFalse(DownloadWatchPolicy.shouldScan(0x100, "a.apk"))
        assertFalse(DownloadWatchPolicy.shouldScan(0x2, "a.apk"))
        assertFalse(DownloadWatchPolicy.shouldScan(DownloadWatchPolicy.EVENT_CLOSE_WRITE, "a.txt"))
        // FileObserver ust bitleri (0x40000000 ISDIR gibi) maskeyi bozmaz.
        assertTrue(DownloadWatchPolicy.shouldScan(DownloadWatchPolicy.EVENT_CLOSE_WRITE or 0x40000000, "a.apk"))
    }

    @Test
    fun deduplicatorSuppressesRepeatsWithinWindowOnly() {
        val dedup = DownloadWatchPolicy.Deduplicator(windowMillis = 1_000L)
        assertTrue(dedup.accept("/d/a.apk", 10L, 100L, now = 0L))
        assertFalse(dedup.accept("/d/a.apk", 10L, 100L, now = 500L))
        // Icerik degisti (boyut/mtime farkli): yeni dosya sayilir.
        assertTrue(dedup.accept("/d/a.apk", 11L, 101L, now = 600L))
        // Pencere doldu: ayni anahtar yeniden kabul edilir.
        assertTrue(dedup.accept("/d/a.apk", 10L, 100L, now = 5_000L))
    }
}
