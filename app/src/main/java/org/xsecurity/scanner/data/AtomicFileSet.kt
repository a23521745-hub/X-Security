package org.xsecurity.scanner.data

import java.io.File
import java.io.IOException

/**
 * Cok-dosyalı tanim seti icin atomik takas + geri alma (ALI-18 #2).
 *
 * Sorun: manifestteki dosyalar tek tek aktif hedefe tasiniyordu; sonraki
 * dosyanin kurulumu patlarsa onceki yeni, kalanlar eski surumde kaliyordu
 * (karisik imza seti). Daha kotusu `delete() + renameTo()` sirasi, rename
 * basarisiz olursa aktif dosyayi tamamen siliyordu.
 *
 * Kural: takas oncesi her hedefin `.bak` yedegi alinir; herhangi bir adim
 * patlarsa yedeklerden geri yuklenir ve varsa yeni olusturulan hedefler
 * silinir (kurulum ya hep ya hic). Basarida yedekler temizlenir.
 *
 * Kapsam notu: geri alma **sürec-ici** hatalari kapsar. `renameTo` adimlari
 * milisaniyeler surdugu icin islem sirasinda process/OS cokmesi penceresi
 * cok dardir; o arti durumda tutarlilik, kurulum oncesi trial-load
 * (bkz. `DefinitionsController`) ve sonraki calistirmadaki motor yuklemesiyle
 * yakalanir. Kalici journal FAZ B disi birakildi.
 *
 * Saf JVM'dir (Context yok) — birim testleri bu nesneyi hedefler.
 */
object AtomicFileSet {

    const val BACKUP_SUFFIX = ".bak"

    sealed class Outcome {
        /** Tum dosyalar takas edildi, yedekler temizlendi. */
        object Committed : Outcome()

        /** Hata oldu; eski dosyalar geri yuklendi (veya hic dokunulmadi). */
        data class RolledBack(val reason: String) : Outcome()
    }

    /**
     * [staged]: hedef-dosya-adi -> kurulumu hazir, dogrulanmis gecici dosya.
     * Tum hedefler [directory] altinda olmalidir.
     */
    fun installSet(directory: File, staged: Map<String, File>): Outcome {
        if (staged.isEmpty()) return Outcome.Committed
        val preExisting = staged.keys
            .filter { File(directory, it).isFile }
            .toSet()
        val backedUp = ArrayList<Pair<File, File>>(staged.size) // (hedef, yedek)
        try {
            for ((name, temp) in staged) {
                if (!temp.isFile || temp.length() <= 0L) {
                    throw IOException("Staged file is empty or missing: ${temp.absolutePath}")
                }
                val target = File(directory, name)
                val backup = File(directory, name + BACKUP_SUFFIX)
                if (backup.isFile || backup.isDirectory) {
                    // Onceki calistirmadan kalma bayat yedek; yeni yedek oncesi temizlenir.
                    runCatching { backup.delete() }
                }
                if (target.isFile) {
                    if (!target.renameTo(backup)) {
                        throw IOException("Could not back up active file: ${target.absolutePath}")
                    }
                    backedUp += target to backup
                }
                if (!temp.renameTo(target)) {
                    throw IOException("Could not move staged file into place: ${target.absolutePath}")
                }
            }
            // Commit: yedekler artik gereksiz.
            for ((_, backup) in backedUp) runCatching { backup.delete() }
            return Outcome.Committed
        } catch (error: Throwable) {
            rollback(directory, backedUp, preExisting, staged.keys)
            return Outcome.RolledBack(error.message ?: error.javaClass.simpleName)
        }
    }

    data class RecoverOutcome(val recovered: List<String>, val ambiguous: List<String>)

    /**
     * Yarim kalmis takasin izlerini toparlar (process/OS cokmesi sonrasi,
     * ALI-18 review).
     *
     * - Hedef YOK + yedek VAR: kesin durum, yedek geri yuklenir.
     * - Hedef VAR + yedek VAR: belirsiz (son takas tamamlanip yedek silinememis
     *   olabilir); karar cagiranin oracle'ina birakilir, isimler raporlanir.
     */
    fun recover(directory: File, names: Collection<String>): RecoverOutcome {
        val recovered = ArrayList<String>()
        val ambiguous = ArrayList<String>()
        for (name in names) {
            val target = File(directory, name)
            val backup = File(directory, name + BACKUP_SUFFIX)
            if (!backup.isFile) continue
            if (!target.isFile) {
                if (backup.renameTo(target)) recovered += name
            } else {
                ambiguous += name
            }
        }
        return RecoverOutcome(recovered, ambiguous)
    }

    private fun rollback(
        directory: File,
        backedUp: List<Pair<File, File>>,
        preExisting: Set<String>,
        names: Set<String>
    ) {
        // Yedegi alinan hedefleri geri koy.
        for ((target, backup) in backedUp) {
            runCatching {
                if (target.isFile) target.delete()
                if (backup.isFile) {
                    if (!backup.renameTo(target)) {
                        // renameTo basarisizsa kopya ile kurtar (hedef kaybolmasin).
                        backup.copyTo(target, overwrite = true)
                    }
                    runCatching { backup.delete() }
                }
            }
        }
        // Bu kurulumda YENI olusturulan hedefleri sil (onceden yoktular).
        for (name in names) {
            if (name in preExisting) continue
            if (backedUp.any { it.first.name == name }) continue
            runCatching { File(directory, name).takeIf { it.isFile }?.delete() }
        }
        // Artik yedek kalmamali.
        for ((_, backup) in backedUp) runCatching { backup.delete() }
    }
}
