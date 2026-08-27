package org.xsecurity.scanner.yara

/**
 * YARA `condition:` bloğunun desteklenen alt kumesi.
 *
 * [evaluate] girdileri:
 *  - `matched`: kuralin eslesen string identifierlari (`$` olmadan),
 *  - `allStrings`: kuralda tanimli butun string identifierlari.
 */
sealed class YaraCondition {
    abstract fun evaluate(matched: Set<String>, allStrings: Set<String>): Boolean

    object AnyOfThem : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) = matched.isNotEmpty()
    }

    object AllOfThem : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) =
            allStrings.isNotEmpty() && matched.containsAll(allStrings)
    }

    object NoneOfThem : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) = matched.isEmpty()
    }

    /** `N of them` */
    class CountOfThem(val count: Int) : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) = matched.size >= count
    }

    /** `any|all|none of ($a, $b*)` ve `N of ($a*)` */
    class OfThem(
        val mode: Mode,
        val count: Int,
        /** identifier veya onek-secici (`a*`) */
        val selectors: List<String>
    ) : YaraCondition() {

        enum class Mode { ANY, ALL, NONE, COUNT }

        override fun evaluate(matched: Set<String>, allStrings: Set<String>): Boolean {
            val selected = resolve(allStrings)
            return when (mode) {
                Mode.ANY -> selected.any { it in matched }
                Mode.ALL -> selected.isNotEmpty() && selected.all { it in matched }
                Mode.NONE -> selected.none { it in matched }
                Mode.COUNT -> selected.count { it in matched } >= count
            }
        }

        private fun resolve(allStrings: Set<String>): Set<String> {
            val out = LinkedHashSet<String>()
            for (selector in selectors) {
                if (selector.endsWith('*')) {
                    val prefix = selector.dropLast(1)
                    for (name in allStrings) if (name.startsWith(prefix)) out += name
                } else {
                    out += selector
                }
            }
            return out
        }
    }

    /** `$a and $b and not $c` */
    class AndTerms(val terms: List<Term>) : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) =
            terms.all { it.test(matched) }
    }

    /** `$a or $b or $c` */
    class OrTerms(val terms: List<Term>) : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) =
            terms.any { it.test(matched) }
    }

    /** Hicbir string'in eslesmesi beklenmeyen, daima yanlis kosul. */
    object Never : YaraCondition() {
        override fun evaluate(matched: Set<String>, allStrings: Set<String>) = false
    }
}

class Term(val identifier: String, val negated: Boolean = false) {
    fun test(matched: Set<String>): Boolean = if (negated) identifier !in matched else identifier in matched
}
