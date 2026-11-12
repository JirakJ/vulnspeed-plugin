/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.cli.CliFixtures
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RuleScannerTest {

    private val scanner = RuleScanner()

    @Test
    fun `ships a non-trivial ruleset with unique ids`() {
        assertTrue(scanner.rules.size >= 80, "ruleset shrank unexpectedly: ${scanner.rules.size}")
        assertEquals(scanner.rules.size, scanner.rules.map { it.id }.toSet().size)
    }

    @Test
    fun `every rule pattern compiles`() {
        val errors = mutableListOf<String>()
        val reporting = RuleScanner { errors.add(it) }
        reporting.scanContent(CliFixtures.SQL_LINE, "/p/A.java", "java", ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB)
        assertEquals(emptyList<String>(), errors)
    }

    @Test
    fun `scanContent reports SQL injection with stats`() {
        val result = scanner.scanContent(CliFixtures.SQL_LINE, "/p/A.java", "java", ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB)

        assertTrue(result.vulnerabilities.any { it.ruleId == "SQL_001" && it.line == 1 && it.filePath == "/p/A.java" })
        assertEquals(1, result.stats.filesScanned)
        assertEquals(result.vulnerabilities.size, result.stats.totalVulns)
    }

    @Test
    fun `clean source has no findings`() {
        val result = scanner.scanContent(CliFixtures.CLEAN_SOURCE, "/p/Clean.java", "java", ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB)

        assertEquals(emptyList<Any>(), result.vulnerabilities)
    }

    @Test
    fun `content above the max size is skipped`() {
        val result = scanner.scanContent(CliFixtures.SQL_LINE + "x".repeat(2048), "/p/A.java", "java", maxFileSizeKb = 1)

        assertEquals(0, result.stats.filesScanned)
        assertTrue(result.vulnerabilities.isEmpty())
    }

    @Test
    fun `language is derived from the file extension`() {
        assertEquals("java", RuleScanner.languageFor("A.java"))
        assertEquals("kotlin", RuleScanner.languageFor("build.gradle.kts"))
        assertEquals("python", RuleScanner.languageFor("x.PY"))
        assertEquals("cpp", RuleScanner.languageFor("a.cc"))
        assertEquals("go", RuleScanner.languageFor("main.go"))
        assertEquals("rust", RuleScanner.languageFor("lib.rs"))
        assertEquals("unknown", RuleScanner.languageFor("Makefile"))
    }
}
