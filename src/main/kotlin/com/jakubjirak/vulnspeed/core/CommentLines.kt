/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

/**
 * Line-level comment detection, so rules do not report code that is commented
 * out or quoted in documentation. A line counts as a comment only when it holds
 * nothing but comment text:
 *
 * - C-family languages (Java, Kotlin, JS/TS, Swift, C/C++, Go, Rust): `//` lines and
 *   every line of a `/* … */` block (including KDoc / Javadoc)
 * - Python: `#` lines and docstrings — triple-quoted strings that start a line
 * - YAML, `.properties`, Dockerfile: `#` lines (`.properties` also `!`)
 *
 * Trailing comments after code are not stripped: the code part is still scanned.
 */
object CommentLines {

    private val HASH_COMMENT_LANGUAGES = setOf(SourceLanguages.YAML, SourceLanguages.DOCKERFILE, SourceLanguages.PROPERTIES)

    /** Returns one flag per entry of [lines]: true when that line is entirely a comment. */
    fun mask(lines: List<String>, language: String): BooleanArray = when (language) {
        SourceLanguages.PYTHON -> pythonMask(lines)
        in HASH_COMMENT_LANGUAGES -> BooleanArray(lines.size) { index ->
            val trimmed = lines[index].trimStart()
            trimmed.startsWith("#") || (language == SourceLanguages.PROPERTIES && trimmed.startsWith("!"))
        }
        in SourceLanguages.CODE -> cFamilyMask(lines)
        else -> BooleanArray(lines.size)
    }

    private fun cFamilyMask(lines: List<String>): BooleanArray {
        val mask = BooleanArray(lines.size)
        var inBlock = false
        lines.forEachIndexed { index, line ->
            val trimmed = line.trim()
            if (inBlock) {
                mask[index] = true
                if (trimmed.contains("*/")) inBlock = false
            } else if (trimmed.startsWith("//")) {
                mask[index] = true
            } else if (trimmed.startsWith("/*")) {
                mask[index] = true
                inBlock = !trimmed.substring(2).contains("*/")
            }
        }
        return mask
    }

    private val DOCSTRING_START = Regex("""^[rRuUbB]?("{3}|'{3})""")

    /**
     * Tracks triple-quoted strings: a docstring (triple quote at the start of a line) is
     * masked until it closes; any other multi-line triple-quoted string (`q = """…`) is
     * code and stays scanned, but is tracked so its closing quote is not mistaken for a
     * docstring opening.
     */
    private fun pythonMask(lines: List<String>): BooleanArray {
        val mask = BooleanArray(lines.size)
        var closing: String? = null
        var inDocstring = false
        lines.forEachIndexed { index, line ->
            val trimmed = line.trim()
            val open = closing
            if (open != null) {
                mask[index] = inDocstring
                if (trimmed.contains(open)) closing = null
                return@forEachIndexed
            }
            if (trimmed.startsWith("#")) {
                mask[index] = true
                return@forEachIndexed
            }
            val start = DOCSTRING_START.find(trimmed)
            if (start != null) {
                val quote = start.groupValues[1]
                mask[index] = true
                if (!trimmed.substring(start.range.last + 1).contains(quote)) {
                    closing = quote
                    inDocstring = true
                }
                return@forEachIndexed
            }
            closing = unclosedTripleQuote(trimmed)
            inDocstring = false
        }
        return mask
    }

    /** The triple quote left open at the end of [line], if any. */
    private fun unclosedTripleQuote(line: String): String? =
        listOf("\"\"\"", "'''").firstOrNull { quote -> line.windowed(quote.length).count { it == quote } % 2 == 1 }
}
