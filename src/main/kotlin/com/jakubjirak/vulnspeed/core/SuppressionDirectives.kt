/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

/**
 * Inline suppression for VulnSpeed findings, following the convention of
 * `eslint-disable` / `noqa` / `nosec`:
 *
 * - `// vulnspeed-ignore` on the same line or on a comment line directly above
 *   suppresses every finding on that line
 * - `// vulnspeed-ignore: SQL_001, XSS_001` suppresses only the listed rules
 * - `// vulnspeed-ignore-file` within the first five lines suppresses the whole file
 *
 * Any common comment style is recognized: slashes, hash, dashes, semicolon,
 * block comments, and HTML comments.
 */
object SuppressionDirectives {

    const val DIRECTIVE = "vulnspeed-ignore"
    const val FILE_DIRECTIVE = "vulnspeed-ignore-file"

    /** Number of leading lines searched for a file-level suppression. */
    const val FILE_DIRECTIVE_SEARCH_LINES = 5

    private val COMMENT_PREFIXES = listOf("//", "#", "--", ";", "/*", "*", "<!--")

    /** True when the whole file is opted out via [FILE_DIRECTIVE] near the top. */
    fun isFileSuppressed(lines: List<String>): Boolean =
        lines.take(FILE_DIRECTIVE_SEARCH_LINES).any { it.contains(FILE_DIRECTIVE) }

    /**
     * True when the finding for [ruleId] on the line at [lineIndex] (0-based) is
     * suppressed — either by a trailing directive on the same line or by a
     * comment-only directive line directly above it.
     */
    fun isSuppressed(lines: List<String>, lineIndex: Int, ruleId: String): Boolean {
        val line = lines.getOrNull(lineIndex) ?: return false
        if (lineDirectiveSuppresses(line, ruleId)) return true

        val previous = lines.getOrNull(lineIndex - 1) ?: return false
        return isCommentLine(previous) && lineDirectiveSuppresses(previous, ruleId)
    }

    /**
     * True when [text] carries a line-level directive matching [ruleId]: a bare
     * `vulnspeed-ignore` matches everything, `vulnspeed-ignore: A, B` matches the
     * listed rule ids (case-insensitive). The file-level directive never matches here.
     */
    fun lineDirectiveSuppresses(text: String, ruleId: String): Boolean {
        var searchFrom = 0
        while (true) {
            val at = text.indexOf(DIRECTIVE, searchFrom)
            if (at < 0) return false
            val rest = text.substring(at + DIRECTIVE.length)
            searchFrom = at + DIRECTIVE.length

            if (rest.startsWith("-file")) continue
            if (!rest.startsWith(":")) return true

            val ruleList = rest.removePrefix(":")
                .takeWhile { it != '\n' }
                .split(',', ' ', '\t', ';')
                .map { it.trim().trimEnd('*', '/', '-', '>') }
                .filter { it.isNotEmpty() }
            if (ruleList.isEmpty()) return true
            if (ruleList.any { it.equals(ruleId, ignoreCase = true) }) return true
        }
    }

    /** True when the trimmed line starts with a known comment marker. */
    fun isCommentLine(line: String): Boolean {
        val trimmed = line.trimStart()
        return COMMENT_PREFIXES.any { trimmed.startsWith(it) }
    }
}
