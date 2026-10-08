package org.xsecurity.scanner.quarantine

/**
 * Pure parser for the URI under which a scanned file was originally reached (SAF picker,
 * Download watcher, share). It extracts what the Android adapter needs to find the original
 * again: an absolute path when it can be derived without platform queries, a MediaStore row
 * id, or a SAF document hint. No `android.net.Uri` so the mapping is unit-tested on the JVM.
 */
object SourceLocator {
    enum class MediaCollection { FILES, DOWNLOADS, IMAGES, VIDEO, AUDIO }

    data class SourceRef(
        val raw: String,
        val scheme: String?,
        val authority: String?,
        /** Absolute file path when derivable (file://, raw: download ids). */
        val path: String?,
        /** External-storage document volume ("primary" or "XXXX-XXXX"). */
        val volume: String?,
        /** Path relative to the volume root ("Download/x.apk"). */
        val relativePath: String?,
        val mediaCollection: MediaCollection?,
        val mediaId: Long?,
        /** Legacy DownloadProvider public id (content://downloads/public_downloads/<id>). */
        val legacyDownloadId: Long?,
        /** SAF document URI (content://…/document/…): DocumentsContract.deleteDocument may apply. */
        val isDocument: Boolean
    ) {
        val isFile: Boolean get() = scheme == "file"
        val isContent: Boolean get() = scheme == "content"
    }

    const val AUTHORITY_EXTERNAL_STORAGE = "com.android.externalstorage.documents"
    const val AUTHORITY_DOWNLOADS_DOCUMENTS = "com.android.providers.downloads.documents"
    const val AUTHORITY_MEDIA_DOCUMENTS = "com.android.providers.media.documents"
    const val AUTHORITY_MEDIA = "media"

    fun parse(uri: String?): SourceRef? {
        val raw = uri?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val schemeEnd = raw.indexOf(':')
        if (schemeEnd <= 0) return null
        val scheme = raw.substring(0, schemeEnd).lowercase()
        val remainder = raw.substring(schemeEnd + 1)
        return when (scheme) {
            "file" -> parseFile(raw, remainder)
            "content" -> parseContent(raw, remainder)
            else -> SourceRef(raw, scheme, null, null, null, null, null, null, null, false)
        }
    }

    private fun parseFile(raw: String, remainder: String): SourceRef {
        // file:///abs/path  or  file:/abs/path  or file://localhost/abs/path
        var rest = remainder
        if (rest.startsWith("//")) {
            rest = rest.substring(2)
            val slash = rest.indexOf('/')
            rest = if (slash >= 0) rest.substring(slash) else "/"
        }
        val decoded = percentDecode(rest.substringBefore('?').substringBefore('#'))
        val path = if (decoded.startsWith("/")) decoded else "/$decoded"
        return SourceRef(raw, "file", null, path, null, null, null, null, null, false)
    }

    private fun parseContent(raw: String, remainder: String): SourceRef? {
        if (!remainder.startsWith("//")) return null
        val withoutSlashes = remainder.substring(2).substringBefore('?').substringBefore('#')
        val slash = withoutSlashes.indexOf('/')
        val authority = (if (slash >= 0) withoutSlashes.substring(0, slash) else withoutSlashes).lowercase()
        val segments = if (slash >= 0) {
            withoutSlashes.substring(slash + 1).split('/').filter { it.isNotEmpty() }.map(::percentDecode)
        } else {
            emptyList()
        }
        val isDocument = segments.contains("document")
        val documentId = documentId(segments)
        return when (authority) {
            AUTHORITY_EXTERNAL_STORAGE -> {
                val separator = documentId?.indexOf(':') ?: -1
                val volume = if (documentId != null && separator > 0) documentId.substring(0, separator) else null
                val relative = if (documentId != null && separator >= 0) documentId.substring(separator + 1).trimStart('/') else null
                SourceRef(raw, "content", authority, null, volume, relative?.takeIf { it.isNotEmpty() }, null, null, null, isDocument)
            }
            AUTHORITY_DOWNLOADS_DOCUMENTS -> {
                when {
                    documentId == null -> SourceRef(raw, "content", authority, null, null, null, null, null, null, isDocument)
                    documentId.startsWith("raw:") -> {
                        val path = documentId.removePrefix("raw:").takeIf { it.startsWith("/") }
                        SourceRef(raw, "content", authority, path, null, null, null, null, null, isDocument)
                    }
                    documentId.startsWith("msf:") -> {
                        val id = documentId.removePrefix("msf:").toLongOrNull()
                        SourceRef(raw, "content", authority, null, null, null, id?.let { MediaCollection.DOWNLOADS }, id, null, isDocument)
                    }
                    documentId.startsWith("msd:") -> {
                        // Downloads directory ids: no single file behind them.
                        SourceRef(raw, "content", authority, null, null, null, null, null, null, isDocument)
                    }
                    else -> {
                        val legacyId = documentId.toLongOrNull()
                        SourceRef(raw, "content", authority, null, null, null, null, null, legacyId, isDocument)
                    }
                }
            }
            AUTHORITY_MEDIA_DOCUMENTS -> {
                val separator = documentId?.indexOf(':') ?: -1
                val type = if (documentId != null && separator > 0) documentId.substring(0, separator) else null
                val id = if (documentId != null && separator >= 0) documentId.substring(separator + 1).toLongOrNull() else null
                val collection = when (type) {
                    "image", "images" -> MediaCollection.IMAGES
                    "video" -> MediaCollection.VIDEO
                    "audio" -> MediaCollection.AUDIO
                    "document", "downloads", "file" -> MediaCollection.FILES
                    else -> if (id != null) MediaCollection.FILES else null
                }
                SourceRef(raw, "content", authority, null, null, null, if (id != null) collection else null, id, null, isDocument)
            }
            AUTHORITY_MEDIA -> {
                // content://media/<volume>/<collection>[/media]/<id>
                val id = segments.lastOrNull()?.toLongOrNull()
                val collection = when (segments.getOrNull(1)) {
                    "downloads" -> MediaCollection.DOWNLOADS
                    "images" -> MediaCollection.IMAGES
                    "video" -> MediaCollection.VIDEO
                    "audio" -> MediaCollection.AUDIO
                    "file" -> MediaCollection.FILES
                    else -> null
                }
                SourceRef(raw, "content", authority, null, null, null, if (id != null) collection else null, id, null, false)
            }
            else -> SourceRef(raw, "content", authority, null, null, null, null, null, null, isDocument)
        }
    }

    /** `…/document/<id>` wins over `…/tree/<id>` when both are present. */
    private fun documentId(segments: List<String>): String? {
        val index = segments.lastIndexOf("document")
        if (index >= 0 && index + 1 < segments.size) return segments[index + 1]
        return null
    }

    /** Strict RFC 3986 percent-decoding (no '+' to space) with UTF-8 multibyte support. */
    fun percentDecode(value: String): String {
        if (!value.contains('%')) return value
        val bytes = java.io.ByteArrayOutputStream(value.length)
        var index = 0
        while (index < value.length) {
            val char = value[index]
            if (char == '%' && index + 2 < value.length) {
                val hex = value.substring(index + 1, index + 3)
                val byte = hex.toIntOrNull(16)
                if (byte != null) {
                    bytes.write(byte)
                    index += 3
                    continue
                }
            }
            val encoded = char.toString().toByteArray(Charsets.UTF_8)
            bytes.write(encoded, 0, encoded.size)
            index++
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    /** Whether [path] lives under one of [roots] (normalised prefix match on path segments). */
    fun isUnder(path: String, roots: Collection<String>): Boolean {
        val normalised = normalise(path)
        return roots.any { root ->
            val base = normalise(root)
            normalised == base || normalised.startsWith("$base/")
        }
    }

    private fun normalise(path: String): String = path.trimEnd('/').ifEmpty { "/" }
}
