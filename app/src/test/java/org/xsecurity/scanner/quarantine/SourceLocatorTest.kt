package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.quarantine.SourceLocator.MediaCollection

class SourceLocatorTest {
    @Test
    fun fileUrisYieldDecodedAbsolutePaths() {
        val ref = SourceLocator.parse("file:///storage/emulated/0/Download/bad%20file.apk")!!
        assertTrue(ref.isFile)
        assertEquals("/storage/emulated/0/Download/bad file.apk", ref.path)
        assertNull(ref.mediaId)
        assertFalse(ref.isDocument)
    }

    @Test
    fun externalStorageDocumentsSplitVolumeAndRelativePath() {
        val primary = SourceLocator.parse(
            "content://com.android.externalstorage.documents/document/primary%3ADownload%2Fevil.apk"
        )!!
        assertEquals("primary", primary.volume)
        assertEquals("Download/evil.apk", primary.relativePath)
        assertTrue(primary.isDocument)
        assertNull(primary.path)

        val sdCard = SourceLocator.parse(
            "content://com.android.externalstorage.documents/tree/1A2B-3C4D%3A/document/1A2B-3C4D%3AApps%2Fx.apk"
        )!!
        assertEquals("1A2B-3C4D", sdCard.volume)
        assertEquals("Apps/x.apk", sdCard.relativePath)
    }

    @Test
    fun downloadsProviderIdsAreMappedToPathsOrMediaIds() {
        val raw = SourceLocator.parse(
            "content://com.android.providers.downloads.documents/document/raw%3A%2Fstorage%2Femulated%2F0%2FDownload%2Fa.apk"
        )!!
        assertEquals("/storage/emulated/0/Download/a.apk", raw.path)

        val msf = SourceLocator.parse("content://com.android.providers.downloads.documents/document/msf%3A1234")!!
        assertEquals(1234L, msf.mediaId)
        assertEquals(MediaCollection.DOWNLOADS, msf.mediaCollection)

        val legacy = SourceLocator.parse("content://com.android.providers.downloads.documents/document/77")!!
        assertEquals(77L, legacy.legacyDownloadId)
        assertNull(legacy.mediaId)

        val directory = SourceLocator.parse("content://com.android.providers.downloads.documents/document/msd%3A9")!!
        assertNull(directory.mediaId)
        assertNull(directory.path)
    }

    @Test
    fun mediaDocumentsAndMediaStoreUrisExposeRowIds() {
        val doc = SourceLocator.parse("content://com.android.providers.media.documents/document/document%3A456")!!
        assertEquals(456L, doc.mediaId)
        assertEquals(MediaCollection.FILES, doc.mediaCollection)

        val image = SourceLocator.parse("content://com.android.providers.media.documents/document/image%3A12")!!
        assertEquals(MediaCollection.IMAGES, image.mediaCollection)

        val downloads = SourceLocator.parse("content://media/external/downloads/789")!!
        assertEquals(789L, downloads.mediaId)
        assertEquals(MediaCollection.DOWNLOADS, downloads.mediaCollection)
        assertFalse(downloads.isDocument)

        val files = SourceLocator.parse("content://media/external_primary/file/12")!!
        assertEquals(12L, files.mediaId)
        assertEquals(MediaCollection.FILES, files.mediaCollection)

        val video = SourceLocator.parse("content://media/external/video/media/5")!!
        assertEquals(MediaCollection.VIDEO, video.mediaCollection)
        assertEquals(5L, video.mediaId)
    }

    @Test
    fun unknownProvidersStillReportSchemeAuthorityAndDocumentness() {
        val ref = SourceLocator.parse("content://org.example.files/document/abc")!!
        assertTrue(ref.isContent)
        assertEquals("org.example.files", ref.authority)
        assertTrue(ref.isDocument)
        assertNull(ref.path)
        assertNull(ref.mediaId)
    }

    @Test
    fun garbageIsRejectedQuietly() {
        assertNull(SourceLocator.parse(null))
        assertNull(SourceLocator.parse("   "))
        assertNull(SourceLocator.parse("no-scheme"))
        assertNull(SourceLocator.parse("content:relative"))
    }

    @Test
    fun percentDecodingIsStrictAndUtf8Aware() {
        assertEquals("a+b c", SourceLocator.percentDecode("a+b%20c"))
        assertEquals("ü.apk", SourceLocator.percentDecode("%C3%BC.apk"))
        assertEquals("100%", SourceLocator.percentDecode("100%"))
        assertEquals("%zz", SourceLocator.percentDecode("%zz"))
    }

    @Test
    fun appPrivatePrefixCheckIsSegmentAware() {
        val roots = listOf("/data/user/0/org.xsecurity.scanner/cache", "/data/user/0/org.xsecurity.scanner/files/")
        assertTrue(SourceLocator.isUnder("/data/user/0/org.xsecurity.scanner/cache/scans/x.apk", roots))
        assertTrue(SourceLocator.isUnder("/data/user/0/org.xsecurity.scanner/files", roots))
        assertFalse(SourceLocator.isUnder("/data/user/0/org.xsecurity.scanner/cache2/x.apk", roots))
        assertFalse(SourceLocator.isUnder("/storage/emulated/0/Download/x.apk", roots))
    }
}
