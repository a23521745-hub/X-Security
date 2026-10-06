package org.xsecurity.scanner.phishing

/**
 * Oltalama blok listesi bicimi (**saf** ayristirici + eslesme, test edilir).
 *
 * Bicim (satir basina bir alan adi):
 * ```
 * # yorum satiri
 * olta-ornegi.example   # satir-sonu yorum da olur
 * ```
 * Girdi kucuk harfe cevrilir, gecersiz satirlar sessizce atilir. Eslesme tam
 * alan adi + ust alan adidir (`a.b.kotu.example`, `kotu.example` kaydina uyar).
 */
object PhishingBlocklist {

    /** APK'ya gomulu listenin assets yolu. */
    const val ASSET_PATH = "phishing-blocklist.txt"

    /** Tek listede tutulacak en fazla kayit (bellek tavani). */
    const val MAX_ENTRIES = 50_000

    fun parse(raw: String): Set<String> {
        val out = LinkedHashSet<String>()
        raw.lineSequence().forEach { line ->
            if (out.size >= MAX_ENTRIES) return out
            val entry = line.substringBefore('#').trim().lowercase()
            if (entry.isEmpty()) return@forEach
            if (isValidEntry(entry)) out += entry
        }
        return out
    }

    fun isValidEntry(entry: String): Boolean {
        if (entry.isEmpty() || entry.length > 253) return false
        if (!entry.contains('.')) return false
        for (char in entry) {
            if (char == '.' || char == '-' || char.isLetterOrDigit()) continue
            return false
        }
        return entry.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 &&
                !label.startsWith('-') && !label.endsWith('-')
        }
    }

    /**
     * Saf: host listedeki bir kayda uyuyor mu (tam ya da alt alan adi)?
     * `a.b.kotu.example` -> `b.kotu.example` -> `kotu.example` sirasiyla denenir.
     */
    fun matches(host: String?, entries: Set<String>): Boolean {
        if (host.isNullOrEmpty() || entries.isEmpty()) return false
        val clean = host.lowercase().trimEnd('.')
        if (clean.isEmpty() || clean in entries) return clean in entries
        var parent = clean.substringAfter('.', "")
        while (parent.contains('.')) {
            if (parent in entries) return true
            parent = parent.substringAfter('.', "")
        }
        return parent.isNotEmpty() && parent in entries
    }
}
