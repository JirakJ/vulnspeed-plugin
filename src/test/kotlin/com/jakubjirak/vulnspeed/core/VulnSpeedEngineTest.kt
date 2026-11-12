/*
 * Copyright (c) 2025 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.lang.reflect.Method

class VulnSpeedEngineTest {

    private fun createEngine(): VulnSpeedEngine {
        return VulnSpeedEngine()
    }

    private fun invokeParseVulnType(engine: VulnSpeedEngine, ruleId: String): VulnerabilityType {
        val method: Method = RuleScanner::class.java.getDeclaredMethod(
            "parseVulnType", String::class.java
        )
        method.isAccessible = true
        return method.invoke(engine.scanner, ruleId) as VulnerabilityType
    }

    private fun invokeScanWithRule(
        engine: VulnSpeedEngine,
        content: String,
        filePath: String,
        rule: Rule,
        language: String
    ): List<Vulnerability> {
        val method: Method = RuleScanner::class.java.getDeclaredMethod(
            "scanWithRule", String::class.java, String::class.java, Rule::class.java, String::class.java
        )
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(engine.scanner, content, filePath, rule, language) as List<Vulnerability>
    }

    private fun invokeGenerateFixSuggestion(engine: VulnSpeedEngine, rule: Rule): FixSuggestion? {
        val method: Method = RuleScanner::class.java.getDeclaredMethod(
            "generateFixSuggestion", Rule::class.java
        )
        method.isAccessible = true
        return method.invoke(engine.scanner, rule) as? FixSuggestion
    }

    @Suppress("UNUSED_PARAMETER")
    private fun invokeIsSupportedFile(engine: VulnSpeedEngine, filename: String): Boolean =
        ScanPolicy.isSupportedFile(filename)

    @Test
    fun `parseVulnType maps SQL rule to SQL_INJECTION`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.SQL_INJECTION, invokeParseVulnType(engine, "SQL_001"))
    }

    @Test
    fun `parseVulnType maps XSS rule to XSS`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.XSS, invokeParseVulnType(engine, "XSS_001"))
    }

    @Test
    fun `parseVulnType maps CRYPTO rule to WEAK_CRYPTO`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.WEAK_CRYPTO, invokeParseVulnType(engine, "CRYPTO_001"))
    }

    @Test
    fun `parseVulnType maps CMD rule to COMMAND_INJECTION`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.COMMAND_INJECTION, invokeParseVulnType(engine, "CMD_001"))
    }

    @Test
    fun `parseVulnType maps PATH rule to PATH_TRAVERSAL`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.PATH_TRAVERSAL, invokeParseVulnType(engine, "PATH_001"))
    }

    @Test
    fun `parseVulnType maps AUTH rule to AUTHENTICATION`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.AUTHENTICATION, invokeParseVulnType(engine, "AUTH_001"))
    }

    @Test
    fun `parseVulnType maps unknown rule to INFORMATION_DISCLOSURE`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.INFORMATION_DISCLOSURE, invokeParseVulnType(engine, "UNKNOWN_RULE"))
    }

    @Test
    fun `parseVulnType maps XXE rule to XXE`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.XXE, invokeParseVulnType(engine, "XXE_001"))
    }

    @Test
    fun `parseVulnType maps CSRF rule to CSRF`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.CSRF, invokeParseVulnType(engine, "CSRF_001"))
    }

    @Test
    fun `parseVulnType maps BUFFER rule to BUFFER_OVERFLOW`() {
        val engine = createEngine()
        assertEquals(VulnerabilityType.BUFFER_OVERFLOW, invokeParseVulnType(engine, "BUFFER_001"))
    }

    @Test
    fun `scanWithRule finds SQL injection pattern`() {
        val engine = createEngine()
        val rule = Rule(
            id = "SQL_001",
            name = "SQL Injection",
            description = "SQL injection via concatenation",
            severity = Severity.CRITICAL,
            cwe = 89,
            owasp = "A03:2021",
            pattern = """(SELECT|INSERT|UPDATE|DELETE).*['"\s]+\+\s*\w+"""
        )
        val code = """String query = "SELECT * FROM users WHERE id = " + userId;"""

        val vulns = invokeScanWithRule(engine, code, "/Test.java", rule, "java")

        assertEquals(1, vulns.size)
        assertEquals("SQL_001", vulns[0].ruleId)
        assertEquals(Severity.CRITICAL, vulns[0].severity)
        assertEquals(1, vulns[0].line)
        assertEquals("/Test.java", vulns[0].filePath)
        assertEquals(89, vulns[0].cwe)
    }

    @Test
    fun `scanWithRule returns empty for no match`() {
        val engine = createEngine()
        val rule = Rule(
            id = "SQL_001", name = "SQL Injection", description = "desc",
            severity = Severity.CRITICAL, cwe = 89, owasp = "A03:2021",
            pattern = """(SELECT|INSERT|UPDATE|DELETE).*['"\s]+\+\s*\w+"""
        )
        val code = """System.out.println("Hello World");"""

        val vulns = invokeScanWithRule(engine, code, "/Safe.java", rule, "java")
        assertTrue(vulns.isEmpty())
    }

    @Test
    fun `scanWithRule finds multiple matches across lines`() {
        val engine = createEngine()
        val rule = Rule(
            id = "XSS_001", name = "XSS", description = "XSS via innerHTML",
            severity = Severity.HIGH, cwe = 79, owasp = "A03:2021",
            pattern = """\.innerHTML\s*=\s*[\w\s]+"""
        )
        // Prefix with enough chars so that match.range.first - 10 >= 0
        val code = """
            var target1 = element.innerHTML = userInput
            var target2 = other.innerHTML = data
        """.trimIndent()

        val vulns = invokeScanWithRule(engine, code, "/test.js", rule, "javascript")
        assertEquals(2, vulns.size)
        assertEquals(1, vulns[0].line)
        assertEquals(2, vulns[1].line)
    }

    @Test
    fun `scanWithRule skips disabled rules`() {
        val engine = createEngine()
        // The method itself doesn't check enabled, but the loadDefaultRules filters do
        // We test that scanWithRule works with invalid regex gracefully
        val rule = Rule(
            id = "BAD", name = "Bad", description = "desc",
            severity = Severity.LOW, cwe = 0, owasp = "",
            pattern = """[invalid regex"""
        )

        val vulns = invokeScanWithRule(engine, "anything", "/test.java", rule, "java")
        assertTrue(vulns.isEmpty()) // Invalid regex is caught
    }

    @Test
    fun `generateFixSuggestion returns SQL fix for SQL rule`() {
        val engine = createEngine()
        val rule = Rule("SQL_001", "SQL Injection", "desc", Severity.CRITICAL, 89, "A03", ".*")
        val fix = invokeGenerateFixSuggestion(engine, rule)

        assertNotNull(fix)
        assertEquals("Use Parameterized Queries", fix!!.title)
        assertTrue(fix.references.isNotEmpty())
    }

    @Test
    fun `generateFixSuggestion returns XSS fix for XSS rule`() {
        val engine = createEngine()
        val rule = Rule("XSS_001", "XSS", "desc", Severity.HIGH, 79, "A03", ".*")
        val fix = invokeGenerateFixSuggestion(engine, rule)

        assertNotNull(fix)
        assertEquals("Sanitize User Input", fix!!.title)
    }

    @Test
    fun `generateFixSuggestion returns crypto fix for CRYPTO rule`() {
        val engine = createEngine()
        val rule = Rule("CRYPTO_001", "Weak Crypto", "desc", Severity.HIGH, 327, "A02", ".*")
        val fix = invokeGenerateFixSuggestion(engine, rule)

        assertNotNull(fix)
        assertTrue(fix!!.title.contains("Cryptographic"))
    }

    @Test
    fun `generateFixSuggestion returns null for unmatched rule prefix`() {
        val engine = createEngine()
        val rule = Rule("UNKNOWN_999", "Unknown", "desc", Severity.LOW, 0, "", ".*")
        val fix = invokeGenerateFixSuggestion(engine, rule)

        assertNull(fix)
    }

    @Test
    fun `isSupportedFile returns true for supported extensions`() {
        val engine = createEngine()
        assertTrue(invokeIsSupportedFile(engine, "Main.java"))
        assertTrue(invokeIsSupportedFile(engine, "App.kt"))
        assertTrue(invokeIsSupportedFile(engine, "script.py"))
        assertTrue(invokeIsSupportedFile(engine, "index.js"))
        assertTrue(invokeIsSupportedFile(engine, "types.ts"))
        assertTrue(invokeIsSupportedFile(engine, "main.go"))
        assertTrue(invokeIsSupportedFile(engine, "lib.rs"))
        assertTrue(invokeIsSupportedFile(engine, "main.c"))
        assertTrue(invokeIsSupportedFile(engine, "util.h"))
        assertTrue(invokeIsSupportedFile(engine, "algo.cpp"))
        assertTrue(invokeIsSupportedFile(engine, "app.swift"))
    }

    @Test
    fun `isSupportedFile returns false for unsupported extensions`() {
        val engine = createEngine()
        assertFalse(invokeIsSupportedFile(engine, "readme.md"))
        assertFalse(invokeIsSupportedFile(engine, "style.css"))
        assertFalse(invokeIsSupportedFile(engine, "data.json"))
        assertFalse(invokeIsSupportedFile(engine, "config.xml"))
    }

    @Test
    fun `getScanResult returns null for unknown scanId`() {
        val engine = createEngine()
        assertNull(engine.getScanResult("nonexistent-id"))
    }

    @Test
    fun `engine closes without error`() {
        val engine = createEngine()
        assertDoesNotThrow { engine.close() }
    }
}
