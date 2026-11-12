/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.cli.CliFixtures
import com.jakubjirak.vulnspeed.model.Severity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class HeadlessProjectScannerTest {

    @TempDir
    lateinit var dir: Path

    @Test
    fun `reports only the unsuppressed finding in included files`() {
        CliFixtures.vulnerableProject(dir)

        val outcome = HeadlessProjectScanner().scan(dir)
        val sql = outcome.result.vulnerabilities.filter { it.ruleId == "SQL_001" }

        assertEquals(1, sql.size, "only App.java should report SQL_001: $sql")
        assertTrue(sql.single().filePath.endsWith("/src/main/java/App.java"))
        assertEquals(3, sql.single().line)
        assertEquals(Severity.CRITICAL, sql.single().severity)
        assertTrue(outcome.result.vulnerabilities.none { "node_modules" in it.filePath || "/build/" in it.filePath })
        assertTrue(outcome.result.vulnerabilities.none { "/.git/" in it.filePath })
    }

    @Test
    fun `counts scanned files and lines, ignoring excluded dirs and unsupported extensions`() {
        CliFixtures.vulnerableProject(dir)

        val outcome = HeadlessProjectScanner().scan(dir)

        // App, Accepted, OptedOut, Clean — not notes.txt, build/, node_modules/, .git/
        assertEquals(4, outcome.filesFound)
        assertEquals(4, outcome.result.stats.filesScanned)
        assertTrue(outcome.result.stats.linesOfCode > 0)
        assertFalse(outcome.truncated)
        assertEquals(outcome.result.vulnerabilities.size, outcome.result.stats.totalVulns)
    }

    @Test
    fun `file paths are absolute and use forward slashes`() {
        CliFixtures.vulnerableProject(dir)

        val path = HeadlessProjectScanner().scan(dir).result.vulnerabilities.first().filePath

        assertTrue(Path.of(path).isAbsolute)
        assertFalse(path.contains('\\'))
    }

    @Test
    fun `files above the max file size are skipped and counted`() {
        CliFixtures.write(dir, "Big.java", CliFixtures.SQL_LINE + "\n" + "x".repeat(2048))
        CliFixtures.write(dir, "Small.java", CliFixtures.SQL_LINE + "\n")

        val outcome = HeadlessProjectScanner(maxFileSizeKb = 1).scan(dir)

        assertEquals(1, outcome.filesSkippedTooLarge)
        assertEquals(1, outcome.result.stats.filesScanned)
        assertTrue(outcome.result.vulnerabilities.all { it.filePath.endsWith("Small.java") })
    }

    @Test
    fun `max files truncates deterministically and reports it`() {
        CliFixtures.write(dir, "a/A.java", CliFixtures.SQL_LINE)
        CliFixtures.write(dir, "b/B.java", CliFixtures.SQL_LINE)
        CliFixtures.write(dir, "c/C.java", CliFixtures.SQL_LINE)

        val outcome = HeadlessProjectScanner(maxFiles = 2).scan(dir)

        assertTrue(outcome.truncated)
        assertEquals(3, outcome.filesFound)
        assertEquals(2, outcome.result.stats.filesScanned)
        assertTrue(outcome.result.vulnerabilities.none { it.filePath.endsWith("C.java") })
    }

    @Test
    fun `findings are ordered by severity then path and line`() {
        CliFixtures.write(dir, "b/B.java", CliFixtures.SQL_LINE + "\n" + CliFixtures.SQL_LINE)
        CliFixtures.write(dir, "a/A.java", "Random r = new Random();\n" + CliFixtures.SQL_LINE)

        val findings = HeadlessProjectScanner().scan(dir).result.vulnerabilities
        val sorted = findings.sortedWith(compareBy({ it.severity.ordinal }, { it.filePath }, { it.line }, { it.column }))

        assertEquals(sorted, findings)
    }

    @Test
    fun `empty or missing project yields an empty result`() {
        val empty = HeadlessProjectScanner().scan(dir)
        assertEquals(0, empty.result.stats.filesScanned)
        assertTrue(empty.result.vulnerabilities.isEmpty())

        val missing = HeadlessProjectScanner().scan(dir.resolve("nope"))
        assertEquals(0, missing.filesFound)
    }

    @Test
    fun `invalid UTF-8 content is scanned without failing`() {
        val file = dir.resolve("Bin.java")
        Files.write(file, byteArrayOf(0xC3.toByte(), 0x28, 0x0A) + CliFixtures.SQL_LINE.toByteArray())

        val outcome = HeadlessProjectScanner().scan(dir)

        assertEquals(1, outcome.result.stats.filesScanned)
        assertTrue(outcome.result.vulnerabilities.any { it.ruleId == "SQL_001" })
    }
}
