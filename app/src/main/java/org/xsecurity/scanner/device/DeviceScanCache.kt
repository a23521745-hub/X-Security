package org.xsecurity.scanner.device

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Cihaz taramasi onbellegi: motor degismedigi ve uygulama degismedigi surece ayni
 * uygulamayi yeniden taramayin der.
 *
 * Kalicilik: `filesDir/device-scan-cache.json`, icerigi
 * `{ "fingerprint": "<motor parmak izi>", "scannerVersion": <uygulama surum kodu>,
 *   "apps": { "<paket>": { versionCode, lastUpdateTime, entry } } }`.
 *
 *  - `fingerprint` [org.xsecurity.scanner.engine.ApkScannerEngine.fingerprint]'dir
 *    (imza dosyalarinin yol+boyut+mtime zinciri). Imza veritabani degisince parmak
 *    izi de degisir ve **tumu** onbellek gecerli sayilmaz — yeniden tarama dogru
 *    davranistir.
 *  - `scannerVersion` uygulama surum kodudur (ALI-18 review): motor/tespit mantigi
 *    uygulama guncellemesiyle degisebilir; imza parmak izi ayni kalsa bile eski
 *    surumun sonuclari yeniden kullanilmaz. Anahtari olmayan eski onbellekler
 *    ilk turda miss sayilir (guvenli yon).
 *  - Uygulama anahtari `(versionCode, lastUpdateTime)` ikilidir: surum atlayan veya
 *    yerinde guncellenen APK yeniden taranir.
 *  - Kayit `entry-lite`'tir: [DeviceScanStore.encodeEntry] codec'iyle uretilen
 *    ayni AppScanEntry JSON'u, boylece onbellegi isleyen uygulama ozet kartinda ve
 *    tarama gecmisinde tazesinden ayirt edilemez derecede tam veri tasir.
 *  - Kaydetme atomiktir (tmp + rename); bozuk/yarim dosya null olarak okunur ve
 *    tarama onbellegsiz devam eder.
 */
object DeviceScanCache {

    const val FILE_NAME = "device-scan-cache.json"

    data class CachedApp(
        val versionCode: Long,
        val lastUpdateTime: Long,
        val entry: AppScanEntry
    )

    data class Snapshot(
        val fingerprint: String,
        val apps: Map<String, CachedApp>,
        /** Uygulama surum kodu (motor/tespit mantigi surumu vekili). */
        val scannerVersion: Long
    )

    fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    /** Dosya yok/bozuksa `null` — onbellek sadece hiza yarar, dogruluk kaynagi degildir. */
    fun load(file: File): Snapshot? {
        if (!file.isFile) return null
        val root = try {
            JSONObject(file.readText())
        } catch (_: Exception) {
            return null
        }
        val fingerprint = root.optString("fingerprint", "")
        if (fingerprint.isEmpty()) return null
        val appsObject = root.optJSONObject("apps") ?: return null
        val apps = LinkedHashMap<String, CachedApp>()
        for (key in appsObject.keys()) {
            val item = appsObject.optJSONObject(key) ?: continue
            val cachedApp = decodeCachedApp(item) ?: continue
            apps[key] = cachedApp
        }
        return Snapshot(fingerprint, apps, root.optLong("scannerVersion", -1L))
    }

    /** Atomik yazi: once `.tmp`, sonra rename (rename basaramazsa kopya). */
    fun save(file: File, snapshot: Snapshot) {
        val directory = file.parentFile
        if (directory != null && !directory.isDirectory && !directory.mkdirs()) return
        val tmp = File(directory, file.name + ".tmp")
        tmp.writeText(encode(snapshot))
        if (!tmp.renameTo(file)) {
            runCatching {
                if (file.exists()) file.delete()
                if (!tmp.renameTo(file)) tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
        }
    }

    /**
     * Onbellek islemi kontrolu: parmak izi AYNI, tarayici surumu AYNI ve paketin
     * surum kodu + guncelleme zamani AYNI ise onceden taranmis girdi doner;
     * aksi halde `null` (yeniden tara).
     */
    fun hitFor(
        snapshot: Snapshot?,
        engineFingerprint: String,
        scannerVersion: Long,
        app: InstalledApp
    ): AppScanEntry? {
        if (snapshot == null) return null
        if (snapshot.fingerprint != engineFingerprint) return null
        if (snapshot.scannerVersion != scannerVersion) return null
        val cached = snapshot.apps[app.packageName] ?: return null
        if (cached.versionCode != app.versionCode) return null
        if (cached.lastUpdateTime != app.lastUpdateTime) return null
        return cached.entry
    }

    /**
     * Kaldirilmis paketleri onbellegi dusur: gosterilen (halen kurulu) paket kumesi
     * disindaki kayitlar atilir.
     */
    fun prune(snapshot: Snapshot, currentPackages: Set<String>): Map<String, CachedApp> =
        snapshot.apps.filterKeys { it in currentPackages }

    fun encode(snapshot: Snapshot): String {
        val apps = JSONObject()
        for ((packageName, cached) in snapshot.apps) {
            val item = JSONObject()
            item.put("versionCode", cached.versionCode)
            item.put("lastUpdateTime", cached.lastUpdateTime)
            item.put("entry", JSONObject(DeviceScanStore.encodeEntry(cached.entry)))
            apps.put(packageName, item)
        }
        val root = JSONObject()
        root.put("fingerprint", snapshot.fingerprint)
        root.put("scannerVersion", snapshot.scannerVersion)
        root.put("apps", apps)
        return root.toString()
    }

    private fun decodeCachedApp(item: JSONObject): CachedApp? {
        val entryRaw = item.optJSONObject("entry") ?: return null
        val entry = DeviceScanStore.decodeEntry(entryRaw.toString()) ?: return null
        return CachedApp(
            versionCode = item.optLong("versionCode"),
            lastUpdateTime = item.optLong("lastUpdateTime"),
            entry = entry
        )
    }
}
