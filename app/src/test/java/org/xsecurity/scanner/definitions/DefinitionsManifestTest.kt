package org.xsecurity.scanner.definitions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DefinitionsManifestTest {

    private val sha = "a".repeat(64)

    private fun manifest(
        schemaVersion: Int = 1,
        defVersion: Int = 3,
        minApp: Long = 8,
        kind: String = "YARA",
        sha256: String = sha,
        size: Long = 100,
        files: String? = null
    ): ByteArray = """
        {
          "schemaVersion": $schemaVersion,
          "defVersion": $defVersion,
          "minAppVersionCode": $minApp,
          "generatedAt": "2026-08-29T12:00:00Z",
          "files": ${files ?: """[{
            "kind": "$kind",
            "name": "rules.yar",
            "url": "https://updates.example.com/rules.yar",
            "sha256": "$sha256",
            "sizeBytes": $size
          }]"""}
        }
    """.trimIndent().toByteArray()

    @Test
    fun validManifestParsesAllFields() {
        val parsed = DefinitionsManifest.parse(manifest())

        assertEquals(1, parsed.schemaVersion)
        assertEquals(3, parsed.defVersion)
        assertEquals(8L, parsed.minAppVersionCode)
        assertEquals("2026-08-29T12:00:00Z", parsed.generatedAt)
        assertEquals(1, parsed.files.size)
        val file = parsed.files.single()
        assertEquals(org.xsecurity.scanner.data.SignatureStore.Kind.YARA, file.kind)
        assertEquals("rules.yar", file.name)
        assertEquals("https://updates.example.com/rules.yar", file.url)
        assertEquals(sha, file.sha256)
        assertEquals(100L, file.sizeBytes)
    }

    @Test
    fun roundTripThroughJsonKeepsSemantics() {
        val parsed = DefinitionsManifest.parse(manifest())
        val reparsed = DefinitionsManifest.fromJson(parsed.toJson())

        assertEquals(parsed.defVersion, reparsed.defVersion)
        assertEquals(parsed.files, reparsed.files)
    }

    @Test(expected = IllegalArgumentException::class)
    fun unknownSchemaVersionIsRejected() {
        DefinitionsManifest.parse(manifest(schemaVersion = 2))
    }

    @Test(expected = IllegalArgumentException::class)
    fun nonPositiveDefVersionIsRejected() {
        DefinitionsManifest.parse(manifest(defVersion = 0))
    }

    @Test(expected = IllegalArgumentException::class)
    fun unknownKindIsRejected() {
        DefinitionsManifest.parse(manifest(kind = "MAGIC"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun duplicateKindIsRejected() {
        val twoFiles = """
            [
              {"kind": "YARA", "name": "rules.yar", "url": "https://updates.example.com/a",
               "sha256": "$sha", "sizeBytes": 10},
              {"kind": "YARA", "name": "rules2.yar", "url": "https://updates.example.com/b",
               "sha256": "$sha", "sizeBytes": 10}
            ]
        """.trimIndent()
        DefinitionsManifest.parse(manifest(files = twoFiles))
    }

    @Test(expected = IllegalArgumentException::class)
    fun malformedSha256IsRejected() {
        DefinitionsManifest.parse(manifest(sha256 = "ZZ".repeat(32)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun emptyFilesArrayIsRejected() {
        DefinitionsManifest.parse(manifest(files = "[]"))
    }
}
