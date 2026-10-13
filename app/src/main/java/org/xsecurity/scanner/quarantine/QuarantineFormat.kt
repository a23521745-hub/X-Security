package org.xsecurity.scanner.quarantine

import java.util.Locale

/**
 * Presentation helpers shared by the quarantine list and the record detail view.
 * Pure Kotlin so sizes and the scan-origin mapping are unit-tested on the JVM.
 */
object QuarantineFormat {

    /** Where the scan was triggered from — stored on the record and shown in the detail view. */
    const val ORIGIN_DOWNLOAD_WATCH = "download_watch"
    const val ORIGIN_FILE_PICKER = "file_picker"
    const val ORIGIN_UNKNOWN = "unknown"

    /** `KB`/`MB`/`GB` with 1024-based steps; null when the size is not known. */
    fun formatBytes(bytes: Long?, locale: Locale = Locale.getDefault()): String? {
        if (bytes == null || bytes < 0L) return null
        if (bytes < 1024L) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var unit = -1
        while (value >= 1024.0 && unit < units.lastIndex) {
            value /= 1024.0
            unit++
        }
        return String.format(locale, "%.1f %s", value, units[unit])
    }

    /** Raw trigger value -> one of the three known origins; anything else reads as unknown. */
    fun normalizeOrigin(raw: String?): String = when (raw?.trim()?.lowercase(Locale.ROOT)) {
        ORIGIN_DOWNLOAD_WATCH, "realtime", "download" -> ORIGIN_DOWNLOAD_WATCH
        ORIGIN_FILE_PICKER, "picker", "manual", "share" -> ORIGIN_FILE_PICKER
        else -> ORIGIN_UNKNOWN
    }

    /** String-resource KEY for an origin; resolution to `R.string` happens in the UI layer. */
    fun originKey(origin: String?): String = when (normalizeOrigin(origin)) {
        ORIGIN_DOWNLOAD_WATCH -> ORIGIN_KEY_DOWNLOAD_WATCH
        ORIGIN_FILE_PICKER -> ORIGIN_KEY_FILE_PICKER
        else -> ORIGIN_KEY_UNKNOWN
    }

    const val ORIGIN_KEY_DOWNLOAD_WATCH = "quarantine_origin_download_watch"
    const val ORIGIN_KEY_FILE_PICKER = "quarantine_origin_file_picker"
    const val ORIGIN_KEY_UNKNOWN = "quarantine_origin_unknown"

    /** Every origin value the detail view can show, with its resource key. */
    val originKeys: Map<String, String> = mapOf(
        ORIGIN_DOWNLOAD_WATCH to ORIGIN_KEY_DOWNLOAD_WATCH,
        ORIGIN_FILE_PICKER to ORIGIN_KEY_FILE_PICKER,
        ORIGIN_UNKNOWN to ORIGIN_KEY_UNKNOWN
    )

    /** Vault entry shown as the record's vault id; falls back to the record id. */
    fun vaultId(record: QuarantineRecord): String = record.vaultFileName ?: record.id
}
