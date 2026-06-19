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
                        currentRuleName = line.removePrefix("rule ").substringBefore("{").trim()
                    }
                    line.startsWith("$") && line.contains("=") -> {
                        val literal = line.substringAfter("=").trim()
                            .trim('"')
                        if (literal.isNotEmpty()) {
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
}
