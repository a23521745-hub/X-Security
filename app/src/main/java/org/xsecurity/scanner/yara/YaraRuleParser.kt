package org.xsecurity.scanner.yara

import java.io.File

class YaraRuleParser {
    fun parse(ruleFile: File): List<YaraRule> {
        if (!ruleFile.exists()) return emptyList()

        val rules = mutableListOf<YaraRule>()
        var currentRuleName: String? = null
        val currentStrings = mutableListOf<ByteArray>()

        ruleFile.useLines { lines ->
            lines.forEach { rawLine ->
                val line = rawLine.trim()
                when {
                    line.startsWith("rule ") -> {
                        flushRule(currentRuleName, currentStrings, rules)
                        currentRuleName = extractRuleName(line)
                    }
                    line.startsWith("$") && line.contains("=") -> {
                        val literal = extractQuotedLiteral(line.substringAfter("=").trim())
                        if (!literal.isNullOrEmpty()) {
                            currentStrings.add(literal.encodeToByteArray())
                        }
                    }
                    line == "}" -> {
                        flushRule(currentRuleName, currentStrings, rules)
                        currentRuleName = null
                    }
                }
            }
        }

        flushRule(currentRuleName, currentStrings, rules)
        return rules
    }

    private fun flushRule(name: String?, strings: MutableList<ByteArray>, output: MutableList<YaraRule>) {
        if (name != null && strings.isNotEmpty()) {
            output.add(YaraRule(name = name, stringLiterals = strings.toList()))
        }
        strings.clear()
    }

    private fun extractRuleName(ruleLine: String): String? {
        val remainder = ruleLine.removePrefix("rule ").trim()
        if (remainder.isEmpty()) return null

        val head = remainder.substringBefore('{').trim()
        return head.substringBefore(':').trim().ifEmpty { null }
    }

    private fun extractQuotedLiteral(value: String): String? {
        if (!value.startsWith('"')) return null

        val out = StringBuilder()
        var escaping = false
        for (i in 1 until value.length) {
            val c = value[i]
            if (escaping) {
                out.append(
                    when (c) {
                        'n' -> '\n'
                        't' -> '\t'
                        'r' -> '\r'
                        '"' -> '"'
                        '\\' -> '\\'
                        else -> c
                    }
                )
                escaping = false
            } else if (c == '\\') {
                escaping = true
            } else if (c == '"') {
                return out.toString()
            } else {
                out.append(c)
            }
        }

        return null
    }
}
