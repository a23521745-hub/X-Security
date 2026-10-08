package org.xsecurity.scanner.quarantine

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/** Private on-device SQLite metadata store. File contents themselves live only in FileVault. */
internal class QuarantineDatabase(context: Context) :
    SQLiteOpenHelper(context.applicationContext, DATABASE_NAME, null, DATABASE_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE $TABLE_RECORDS (
                id TEXT PRIMARY KEY NOT NULL,
                package_name TEXT NOT NULL,
                label TEXT NOT NULL,
                sha256 TEXT,
                verdict TEXT NOT NULL,
                engine TEXT NOT NULL,
                detected_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                failure_code TEXT,
                vault_file TEXT,
                restore_info TEXT,
                bypass_until INTEGER,
                residue TEXT,
                source_uri TEXT,
                source_path TEXT,
                cut_result TEXT,
                size_bytes INTEGER,
                scan_origin TEXT
            )""".trimIndent()
        )
        db.execSQL(
            """CREATE TABLE $TABLE_BYPASSES (
                package_name TEXT PRIMARY KEY NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                reason_code TEXT NOT NULL
            )""".trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Schema changes are additive; never clear audit/quarantine data here.
        if (oldVersion < 2) {
            // v2: cut-and-paste quarantine. Legacy file rows have NULL residue, which the honesty
            // layer reads as ORIGINAL_PRESENT (nothing was ever removed before v2).
            for (column in listOf("residue", "source_uri", "source_path", "cut_result")) {
                runCatching { db.execSQL("ALTER TABLE $TABLE_RECORDS ADD COLUMN $column TEXT") }
            }
        }
        if (oldVersion < 3) {
            // v3: record identity (P0). `size_bytes`/`scan_origin` are new fields; labels that are
            // only a vault name / staged copy name / hash are backfilled from the recorded original
            // location, so the list shows the real file name with the file's own extension.
            for (column in listOf("size_bytes INTEGER", "scan_origin TEXT")) {
                runCatching { db.execSQL("ALTER TABLE $TABLE_RECORDS ADD COLUMN $column") }
            }
            backfillFileLabels(db)
        }
    }

    /**
     * Backfill of legacy file-record labels (v3). Only rows whose label is a placeholder are
     * touched, and only when the original location yields a real filename; nothing else is read
     * or rewritten. Uses the same pure rule as the live path ([RecordLabel]).
     */
    private fun backfillFileLabels(db: SQLiteDatabase) {
        runCatching {
            db.query(
                TABLE_RECORDS,
                arrayOf("id", "label", "sha256", "vault_file", "source_path", "source_uri"),
                "package_name = ?",
                arrayOf(QuarantineHonesty.FILE_VAULT_PACKAGE)
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getString(0)
                    val label = if (cursor.isNull(1)) null else cursor.getString(1)
                    val sha256 = if (cursor.isNull(2)) null else cursor.getString(2)
                    val vaultFile = if (cursor.isNull(3)) null else cursor.getString(3)
                    val sourcePath = if (cursor.isNull(4)) null else cursor.getString(4)
                    val sourceUri = if (cursor.isNull(5)) null else cursor.getString(5)
                    val backfilled = RecordLabel.backfill(label, sha256, vaultFile, sourcePath, sourceUri)
                        ?: continue
                    db.execSQL("UPDATE $TABLE_RECORDS SET label = ? WHERE id = ?", arrayOf(backfilled, id))
                }
            }
        }
    }

    fun save(record: QuarantineRecord) {
        writableDatabase.insertWithOnConflict(TABLE_RECORDS, null, record.values(), SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun find(id: String): QuarantineRecord? = readableDatabase.query(
        TABLE_RECORDS,
        null,
        "id = ?",
        arrayOf(id),
        null,
        null,
        null,
        "1"
    ).use { cursor -> if (cursor.moveToFirst()) cursor.record() else null }

    fun findByPackage(packageName: String): List<QuarantineRecord> = readableDatabase.query(
        TABLE_RECORDS,
        null,
        "package_name = ?",
        arrayOf(packageName),
        null,
        null,
        "detected_at DESC"
    ).use { cursor -> buildList { while (cursor.moveToNext()) add(cursor.record()) } }

    fun all(): List<QuarantineRecord> = readableDatabase.query(
        TABLE_RECORDS,
        null,
        null,
        null,
        null,
        null,
        "detected_at DESC"
    ).use { cursor -> buildList { while (cursor.moveToNext()) add(cursor.record()) } }

    fun saveBypass(bypass: QuarantineBypass) {
        val values = ContentValues().apply {
            put("package_name", bypass.packageName)
            put("issued_at", bypass.issuedAtMillis)
            put("expires_at", bypass.expiresAtMillis)
            put("reason_code", bypass.reasonCode)
        }
        writableDatabase.insertWithOnConflict(TABLE_BYPASSES, null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun activeBypass(packageName: String, nowMillis: Long): QuarantineBypass? = readableDatabase.query(
        TABLE_BYPASSES,
        null,
        "package_name = ? AND expires_at > ?",
        arrayOf(packageName, nowMillis.toString()),
        null,
        null,
        "expires_at DESC",
        "1"
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else QuarantineBypass(
            packageName = cursor.getString(cursor.getColumnIndexOrThrow("package_name")),
            issuedAtMillis = cursor.getLong(cursor.getColumnIndexOrThrow("issued_at")),
            expiresAtMillis = cursor.getLong(cursor.getColumnIndexOrThrow("expires_at")),
            reasonCode = cursor.getString(cursor.getColumnIndexOrThrow("reason_code"))
        )
    }

    private fun QuarantineRecord.values(): ContentValues = ContentValues().apply {
        put("id", id)
        put("package_name", packageName)
        put("label", label)
        put("sha256", sha256)
        put("verdict", verdict)
        put("engine", engine)
        put("detected_at", detectedAtMillis)
        put("updated_at", updatedAtMillis)
        put("state", state.name)
        put("failure_code", failureCode)
        put("vault_file", vaultFileName)
        put("restore_info", restoreInfo)
        if (bypassUntilMillis == null) putNull("bypass_until") else put("bypass_until", bypassUntilMillis)
        put("residue", residue?.name)
        put("source_uri", sourceUri)
        put("source_path", sourcePath)
        put("cut_result", cutResult)
        if (sizeBytes == null) putNull("size_bytes") else put("size_bytes", sizeBytes)
        put("scan_origin", scanOrigin)
    }

    private fun android.database.Cursor.record(): QuarantineRecord {
        val stateValue = getString(getColumnIndexOrThrow("state"))
        val bypassIndex = getColumnIndexOrThrow("bypass_until")
        return QuarantineRecord(
            id = getString(getColumnIndexOrThrow("id")),
            packageName = getString(getColumnIndexOrThrow("package_name")),
            label = getString(getColumnIndexOrThrow("label")),
            sha256 = nullableString("sha256"),
            verdict = getString(getColumnIndexOrThrow("verdict")),
            engine = getString(getColumnIndexOrThrow("engine")),
            detectedAtMillis = getLong(getColumnIndexOrThrow("detected_at")),
            updatedAtMillis = getLong(getColumnIndexOrThrow("updated_at")),
            state = runCatching { QuarantineState.valueOf(stateValue) }.getOrDefault(QuarantineState.FAILED),
            failureCode = nullableString("failure_code"),
            vaultFileName = nullableString("vault_file"),
            restoreInfo = nullableString("restore_info"),
            bypassUntilMillis = if (isNull(bypassIndex)) null else getLong(bypassIndex),
            residue = nullableString("residue")?.let { value -> OriginalResidue.values().firstOrNull { it.name == value } },
            sourceUri = nullableString("source_uri"),
            sourcePath = nullableString("source_path"),
            cutResult = nullableString("cut_result"),
            sizeBytes = nullableLong("size_bytes"),
            scanOrigin = nullableString("scan_origin")
        )
    }

    private fun android.database.Cursor.nullableString(column: String): String? {
        val index = getColumnIndexOrThrow(column)
        return if (isNull(index)) null else getString(index)
    }

    private fun android.database.Cursor.nullableLong(column: String): Long? {
        val index = getColumnIndexOrThrow(column)
        return if (isNull(index)) null else getLong(index)
    }

    companion object {
        private const val DATABASE_NAME = "autopilot-quarantine.db"
        private const val DATABASE_VERSION = 3
        private const val TABLE_RECORDS = "quarantine_records"
        private const val TABLE_BYPASSES = "quarantine_bypasses"
    }
}
