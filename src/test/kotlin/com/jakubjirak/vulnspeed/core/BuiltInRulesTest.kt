/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.nio.charset.StandardCharsets

/**
 * Table-driven precision tests: every shipped rule has at least one sample it must
 * report and one near-miss it must not report (`src/test/resources/rule-samples.txt`).
 * Samples run through the full [RuleScanner.scanContent] pipeline, so language
 * scoping, comment skipping, file-context gates and test-file skipping all apply.
 */
class BuiltInRulesTest {

    private val scanner = RuleScanner()

    private data class Sample(val ruleId: String, val path: String, val content: String, val positive: Boolean)

    private val samples: List<Sample> by lazy { parseSamples() }

    private fun parseSamples(): List<Sample> {
        val text = javaClass.getResourceAsStream("/rule-samples.txt")!!.readBytes().toString(StandardCharsets.UTF_8)
        val result = mutableListOf<Sample>()
        var ruleId: String? = null
        var path: String? = null
        for (line in text.lines()) {
            when {
                line.startsWith("### ") -> {
                    ruleId = line.removePrefix("### ").trim()
                    path = null
                }
                line.startsWith("file: ") -> path = line.removePrefix("file: ").trim()
                line.startsWith("+ ") || line.startsWith("- ") -> {
                    val id = checkNotNull(ruleId) { "sample outside a rule block: $line" }
                    val file = checkNotNull(path) { "sample for $id has no file: line" }
                    result.add(Sample(id, file, line.substring(2).replace("\\n", "\n"), positive = line.startsWith("+")))
                }
            }
        }
        return result
    }

    private fun findings(sample: Sample): List<String> {
        val path = "/proj/" + sample.path
        val errors = mutableListOf<String>()
        val result = RuleScanner { errors.add(it) }
            .scanContent(sample.content, path, RuleScanner.languageFor(path), ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB)
        assertEquals(emptyList<String>(), errors, "rule errors")
        return result.vulnerabilities.map { it.ruleId }
    }

    @TestFactory
    fun `every sample is classified correctly`(): List<DynamicTest> = samples.map { sample ->
        val kind = if (sample.positive) "reports" else "ignores"
        DynamicTest.dynamicTest("${sample.ruleId} $kind ${sample.path}: ${sample.content.lineSequence().last().trim()}") {
            val found = findings(sample)
            if (sample.positive) {
                assertTrue(sample.ruleId in found, "${sample.ruleId} expected in $found for:\n${sample.content}")
            } else {
                assertFalse(sample.ruleId in found, "${sample.ruleId} must not fire for:\n${sample.content}")
            }
        }
    }

    @Test
    fun `every rule has at least one positive and one negative sample`() {
        val missing = scanner.rules.flatMap { rule ->
            val own = samples.filter { it.ruleId == rule.id }
            listOfNotNull(
                "${rule.id} (+)".takeIf { own.none { it.positive } },
                "${rule.id} (-)".takeIf { own.none { !it.positive } },
            )
        }
        assertEquals(emptyList<String>(), missing)
    }

    @Test
    fun `samples only reference shipped rules`() {
        val ids = scanner.rules.map { it.id }.toSet()
        assertEquals(emptySet<String>(), samples.map { it.ruleId }.toSet() - ids)
    }

    @Test
    fun `every rule is scoped, compiles and carries metadata`() {
        scanner.rules.forEach { rule ->
            Regex(rule.pattern)
            rule.excludePattern?.let { Regex(it) }
            rule.requiresInFile?.let { Regex(it) }
            rule.excludeIfFileContains?.let { Regex(it) }
            assertTrue(rule.cwe > 0, "${rule.id} has no CWE")
            assertTrue(rule.owasp.isNotBlank(), "${rule.id} has no OWASP category")
            assertTrue(rule.matchAnywhere || rule.languages.isNotEmpty(), "${rule.id} runs on every file type")
            assertTrue(rule.languages.all { it in SourceLanguages.CODE + SourceLanguages.CONFIG }, "${rule.id} has an unknown language")
        }
    }

    @Test
    fun `every rule has a fix suggestion`() {
        val missing = scanner.rules.filter { FixSuggestions.forRule(it.id) == null }.map { it.id }
        assertEquals(emptyList<String>(), missing)
    }
}
