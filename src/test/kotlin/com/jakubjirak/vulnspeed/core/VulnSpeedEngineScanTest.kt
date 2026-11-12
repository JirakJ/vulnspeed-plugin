/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.lang.reflect.Method

/**
 * Behavioral tests for the engine's scan loop: snippet extraction, inline
 * suppression, and the secrets ruleset wiring.
 */
class VulnSpeedEngineScanTest {

    private val engine = VulnSpeedEngine()

    private val testRule = Rule(
        id = "SQL_001",
        name = "SQL Injection",
        description = "test rule",
        severity = Severity.CRITICAL,
        cwe = 89,
        owasp = "A03:2021 - Injection",
        pattern = """SELECT.*\+\s*\w+"""
    )

    @Suppress("UNCHECKED_CAST")
    private fun scan(content: String, rule: Rule = testRule): List<Vulnerability> {
        val method: Method = RuleScanner::class.java.getDeclaredMethod(
            "scanWithRule", String::class.java, String::class.java, Rule::class.java, String::class.java
        )
        method.isAccessible = true
        return method.invoke(engine.scanner, content, "/test/File.java", rule, "java") as List<Vulnerability>
    }

    private fun invokeParseVulnType(ruleId: String): VulnerabilityType {
        val method: Method = RuleScanner::class.java.getDeclaredMethod("parseVulnType", String::class.java)
        method.isAccessible = true
        return method.invoke(engine.scanner, ruleId) as VulnerabilityType
    }

    @Suppress("UNCHECKED_CAST")
    private fun defaultRules(): List<Rule> {
        val method: Method = RuleScanner::class.java.getDeclaredMethod("loadDefaultRules")
        method.isAccessible = true
        return method.invoke(engine.scanner) as List<Rule>
    }

    // --- regression: snippet extraction at line start ---

    @Test
    fun `finding at column 1 is reported instead of crashing snippet extraction`() {
        // Match starts at column 1 — the old minOf(0, first - 10) produced a
        // negative substring index, threw, and silently dropped all findings.
        val vulns = scan("""SELECT * FROM users WHERE id=" + userId""")
        assertEquals(1, vulns.size)
        assertEquals(1, vulns.first().column)
        assertTrue(vulns.first().codeSnippet.startsWith("SELECT"))
    }

    @Test
    fun `finding later in the line keeps 10-char context prefix`() {
        val vulns = scan("""        q = "SELECT x FROM t WHERE a=" + b""")
        assertEquals(1, vulns.size)
        assertTrue(vulns.first().codeSnippet.contains("SELECT"))
    }

    @Test
    fun `multiple findings on separate lines are all reported`() {
        val content = """
            SELECT a FROM t WHERE x=" + p1
            ok line
            SELECT b FROM u WHERE y=" + p2
        """.trimIndent()
        val vulns = scan(content)
        assertEquals(2, vulns.size)
        assertEquals(listOf(1, 3), vulns.map { it.line })
    }

    // --- suppression integration ---

    @Test
    fun `same-line vulnspeed-ignore suppresses finding`() {
        val vulns = scan("""SELECT a FROM t WHERE x=" + p // vulnspeed-ignore""")
        assertTrue(vulns.isEmpty())
    }

    @Test
    fun `rule-specific suppression keeps other rules`() {
        val suppressedForOther = scan("""SELECT a FROM t WHERE x=" + p // vulnspeed-ignore: XSS_001""")
        assertEquals(1, suppressedForOther.size, "SQL finding must survive XSS-only suppression")

        val suppressed = scan("""SELECT a FROM t WHERE x=" + p // vulnspeed-ignore: SQL_001""")
        assertTrue(suppressed.isEmpty())
    }

    @Test
    fun `previous-line comment directive suppresses finding`() {
        val content = "// vulnspeed-ignore\nSELECT a FROM t WHERE x=\" + p"
        assertTrue(scan(content).isEmpty())
    }

    @Test
    fun `file-level directive suppresses all findings`() {
        val content = "// vulnspeed-ignore-file\nSELECT a FROM t WHERE x=\" + p\nSELECT b FROM u WHERE y=\" + q"
        assertTrue(scan(content).isEmpty())
    }

    // --- secrets ruleset wiring ---

    @Test
    fun `default rules include the secrets ruleset`() {
        val ids = defaultRules().map { it.id }
        SecretsRules.RULES.forEach { rule ->
            assertTrue(rule.id in ids, "${rule.id} missing from default rules")
        }
    }

    @Test
    fun `default rule ids are unique`() {
        val ids = defaultRules().map { it.id }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun `SECRET rules map to HARDCODED_CREDENTIALS type`() {
        assertEquals(VulnerabilityType.HARDCODED_CREDENTIALS, invokeParseVulnType("SECRET_AWS_001"))
        assertEquals(VulnerabilityType.HARDCODED_CREDENTIALS, invokeParseVulnType("SECRET_URL_001"))
        assertEquals(VulnerabilityType.HARDCODED_CREDENTIALS, invokeParseVulnType("SECRET_JWT_001"))
    }

    @Test
    fun `scanning an AWS key with the secrets rule yields a finding with fix suggestion`() {
        val rule = SecretsRules.RULES.first { it.id == "SECRET_AWS_001" }
        val vulns = scan("""String key = "AKIAIOSFODNN7EXAMPLE";""", rule)
        assertEquals(1, vulns.size)
        val v = vulns.first()
        assertEquals(VulnerabilityType.HARDCODED_CREDENTIALS, v.type)
        assertEquals(798, v.cwe)
        assertNotNull(v.fixSuggestion)
        assertEquals("Remove Hardcoded Secret", v.fixSuggestion!!.title)
    }

    @Test
    fun `secret finding can be suppressed inline`() {
        val rule = SecretsRules.RULES.first { it.id == "SECRET_AWS_001" }
        val vulns = scan("""String key = "AKIAIOSFODNN7EXAMPLE"; // vulnspeed-ignore: SECRET_AWS_001""", rule)
        assertTrue(vulns.isEmpty())
    }
}
