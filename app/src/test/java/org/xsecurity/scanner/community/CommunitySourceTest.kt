package org.xsecurity.scanner.community

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CommunitySourceTest {

    private fun validJson(vararg overrides: Pair<String, String>): String {
        val root = JSONObject()
            .put("schemaVersion", 1)
            .put(
                "sources",
                org.json.JSONArray().put(
                    JSONObject()
                        .put("id", "test-source")
                        .put("kind", "HSB_FROM_CSV")
                        .put("label", "Test")
                        .put("url", "https://raw.githubusercontent.com/a/b/c.csv")
                        .put("namePrefix", "X.")
                        .put("maxEntries", 1000)
                        .put("enabledByDefault", true)
                        .put("license", "CC0")
                        .put("attribution", "someone")
                )
            )
        for ((key, value) in overrides) {
            root.getJSONArray("sources").getJSONObject(0).put(key, value)
        }
        return root.toString()
    }

    @Test
    fun parsesAValidRegistry() {
        val sources = CommunitySource.fromJson(validJson())
        assertEquals(1, sources.size)
        val source = sources.single()
        assertEquals("test-source", source.id)
        assertEquals(CommunitySource.Kind.HSB_FROM_CSV, source.kind)
        assertEquals("X.", source.namePrefix)
        assertTrue(source.enabledByDefault)
    }

    @Test
    fun unknownSchemaVersionIsRejected() {
        try {
            CommunitySource.fromJson(validJson().replace("\"schemaVersion\":1", "\"schemaVersion\":2"))
            throw AssertionError("desteklenmeyen schemaVersion reddedilmeli")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("schemaVersion"))
        }
    }

    @Test
    fun unknownKindIsRejected() {
        try {
            CommunitySource.fromJson(validJson("kind" to "EXE"))
            throw AssertionError("bilinmeyen tur reddedilmeli")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("kind"))
        }
    }

    @Test
    fun nonHttpsUrlIsRejected() {
        try {
            CommunitySource.fromJson(validJson("url" to "http://example.com/x.csv"))
            throw AssertionError("https olmayan URL reddedilmeli")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("https"))
        }
    }

    @Test
    fun duplicateIdsAreRejected() {
        val entry = JSONObject(validJson()).getJSONArray("sources").getJSONObject(0)
        val root = JSONObject().put("schemaVersion", 1).put("sources", org.json.JSONArray().put(entry).put(entry))
        try {
            CommunitySource.fromJson(root.toString())
            throw AssertionError("tekrar eden kimlik reddedilmeli")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("tekrar"))
        }
    }

    @Test
    fun outOfRangeMaxEntriesIsRejected() {
        try {
            CommunitySource.fromJson(validJson("maxEntries" to "0"))
            throw AssertionError("0 giris tavani reddedilmeli")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("maxEntries"))
        }
    }
}
