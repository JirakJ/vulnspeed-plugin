/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SuppressionDirectivesTest {

    // --- same-line directives ---

    @Test
    fun `bare directive on same line suppresses any rule`() {
        val lines = listOf("""val q = "SELECT * FROM t WHERE id=" + id // vulnspeed-ignore""")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 0, "SQL_001"))
        assertTrue(SuppressionDirectives.isSuppressed(lines, 0, "XSS_001"))
    }

    @Test
    fun `directive with rule list suppresses only listed rules`() {
        val lines = listOf("dangerous() // vulnspeed-ignore: SQL_001, XSS_001")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 0, "SQL_001"))
        assertTrue(SuppressionDirectives.isSuppressed(lines, 0, "XSS_001"))
        assertFalse(SuppressionDirectives.isSuppressed(lines, 0, "CMD_001"))
    }

    @Test
    fun `rule list matching is case-insensitive`() {
        val lines = listOf("dangerous() // vulnspeed-ignore: sql_001")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 0, "SQL_001"))
    }

    @Test
    fun `hash comment directive works for python`() {
        val lines = listOf("query = \"SELECT \" + uid  # vulnspeed-ignore")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 0, "SQL_001"))
    }

    @Test
    fun `line without directive is not suppressed`() {
        val lines = listOf("val q = \"SELECT * FROM t\" + id")
        assertFalse(SuppressionDirectives.isSuppressed(lines, 0, "SQL_001"))
    }

    // --- previous-line directives ---

    @Test
    fun `comment-only directive on previous line suppresses next line`() {
        val lines = listOf("// vulnspeed-ignore", "dangerous()")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 1, "SQL_001"))
    }

    @Test
    fun `previous line directive with rule list filters rules`() {
        val lines = listOf("# vulnspeed-ignore: CMD_003", "os.system(\"ls \" + arg)")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 1, "CMD_003"))
        assertFalse(SuppressionDirectives.isSuppressed(lines, 1, "SQL_001"))
    }

    @Test
    fun `directive on previous code line does not suppress`() {
        val lines = listOf("val a = b // vulnspeed-ignore", "dangerous()")
        assertFalse(SuppressionDirectives.isSuppressed(lines, 1, "SQL_001"))
    }

    @Test
    fun `block comment directive on previous line suppresses`() {
        val lines = listOf("/* vulnspeed-ignore */", "dangerous()")
        assertTrue(SuppressionDirectives.isSuppressed(lines, 1, "SQL_001"))
    }

    @Test
    fun `directive two lines above does not suppress`() {
        val lines = listOf("// vulnspeed-ignore", "ok()", "dangerous()")
        assertFalse(SuppressionDirectives.isSuppressed(lines, 2, "SQL_001"))
    }

    // --- file-level directive ---

    @Test
    fun `file directive within first five lines suppresses file`() {
        val lines = listOf("// generated code", "// vulnspeed-ignore-file", "code()", "more()")
        assertTrue(SuppressionDirectives.isFileSuppressed(lines))
    }

    @Test
    fun `file directive after line five is ignored`() {
        val lines = List(6) { "code$it()" } + "// vulnspeed-ignore-file"
        assertFalse(SuppressionDirectives.isFileSuppressed(lines))
    }

    @Test
    fun `file directive does not act as line directive`() {
        assertFalse(SuppressionDirectives.lineDirectiveSuppresses("// vulnspeed-ignore-file", "SQL_001"))
    }

    @Test
    fun `plain file is not file-suppressed`() {
        assertFalse(SuppressionDirectives.isFileSuppressed(listOf("package a", "fun main() {}")))
    }

    // --- edge cases ---

    @Test
    fun `empty rule list after colon suppresses everything`() {
        assertTrue(SuppressionDirectives.lineDirectiveSuppresses("x // vulnspeed-ignore:", "SQL_001"))
    }

    @Test
    fun `out of range line index returns false`() {
        assertFalse(SuppressionDirectives.isSuppressed(emptyList(), 0, "SQL_001"))
        assertFalse(SuppressionDirectives.isSuppressed(listOf("a"), 5, "SQL_001"))
    }

    @Test
    fun `rule list inside block comment closer is parsed`() {
        assertTrue(SuppressionDirectives.lineDirectiveSuppresses("/* vulnspeed-ignore: SQL_001 */", "SQL_001"))
    }

    @Test
    fun `isCommentLine recognizes common styles`() {
        assertTrue(SuppressionDirectives.isCommentLine("  // c"))
        assertTrue(SuppressionDirectives.isCommentLine("# c"))
        assertTrue(SuppressionDirectives.isCommentLine("\t-- c"))
        assertTrue(SuppressionDirectives.isCommentLine("* c"))
        assertTrue(SuppressionDirectives.isCommentLine("<!-- c"))
        assertFalse(SuppressionDirectives.isCommentLine("val a = 1"))
    }
}
