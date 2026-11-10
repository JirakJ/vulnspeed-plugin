/*
 * Copyright (c) 2025 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.model

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ModelsTest {

    @Test
    fun `Severity enum has 5 levels in correct order`() {
        val values = Severity.values()
        assertEquals(5, values.size)
        assertEquals(Severity.CRITICAL, values[0])
        assertEquals(Severity.HIGH, values[1])
        assertEquals(Severity.MEDIUM, values[2])
        assertEquals(Severity.LOW, values[3])
        assertEquals(Severity.INFO, values[4])
    }

    @Test
    fun `VulnerabilityType enum has all expected types`() {
        val types = VulnerabilityType.values()
        assertTrue(types.size >= 27)
        assertNotNull(VulnerabilityType.SQL_INJECTION)
        assertNotNull(VulnerabilityType.XSS)
        assertNotNull(VulnerabilityType.COMMAND_INJECTION)
        assertNotNull(VulnerabilityType.PATH_TRAVERSAL)
        assertNotNull(VulnerabilityType.CSRF)
        assertNotNull(VulnerabilityType.SECRET_EXPOSURE)
        assertNotNull(VulnerabilityType.IAC_VULNERABILITY)
    }

    @Test
    fun `Vulnerability data class stores all fields`() {
        val vuln = Vulnerability(
            id = "vuln-1",
            ruleId = "SQL_001",
            ruleName = "SQL Injection",
            type = VulnerabilityType.SQL_INJECTION,
            severity = Severity.CRITICAL,
            cwe = 89,
            filePath = "/src/Main.java",
            line = 42,
            column = 10,
            message = "SQL injection detected",
            codeSnippet = "query + userInput",
            confidence = 0.9f,
            owasp = "A03:2021",
            fixSuggestion = null,
            isFalsePositive = false,
            tags = listOf("java", "SQL_001")
        )

        assertEquals("vuln-1", vuln.id)
        assertEquals("SQL_001", vuln.ruleId)
        assertEquals(VulnerabilityType.SQL_INJECTION, vuln.type)
        assertEquals(Severity.CRITICAL, vuln.severity)
        assertEquals(89, vuln.cwe)
        assertEquals(42, vuln.line)
        assertEquals(10, vuln.column)
        assertEquals(0.9f, vuln.confidence)
        assertFalse(vuln.isFalsePositive)
        assertEquals(2, vuln.tags.size)
    }

    @Test
    fun `Vulnerability has sensible defaults`() {
        val vuln = Vulnerability(
            id = "v1", ruleId = "R1", ruleName = "Rule",
            type = VulnerabilityType.XSS, severity = Severity.HIGH,
            cwe = 79, filePath = "/test.js", line = 1, column = 1,
            message = "XSS", codeSnippet = "innerHTML"
        )

        assertEquals(1.0f, vuln.confidence)
        assertEquals("", vuln.owasp)
        assertNull(vuln.fixSuggestion)
        assertFalse(vuln.isFalsePositive)
        assertTrue(vuln.tags.isEmpty())
    }

    @Test
    fun `FixSuggestion data class stores all fields`() {
        val fix = FixSuggestion(
            title = "Use Parameterized Queries",
            description = "Prevents SQL injection",
            code = "PreparedStatement stmt = ...",
            references = listOf("https://owasp.org")
        )

        assertEquals("Use Parameterized Queries", fix.title)
        assertEquals(1, fix.references.size)
    }

    @Test
    fun `FixSuggestion has default empty references`() {
        val fix = FixSuggestion("title", "desc", "code")
        assertTrue(fix.references.isEmpty())
    }

    @Test
    fun `ScanResult data class stores all fields`() {
        val stats = ScanStats(5, 1, 2, 1, 1, 10, 500L)
        val result = ScanResult(
            scanId = "scan-1",
            timestamp = System.currentTimeMillis(),
            durationMs = 150L,
            vulnerabilities = emptyList(),
            stats = stats
        )

        assertEquals("scan-1", result.scanId)
        assertEquals(150L, result.durationMs)
        assertEquals(5, result.stats.totalVulns)
    }

    @Test
    fun `ScanStats counts are correct`() {
        val stats = ScanStats(
            totalVulns = 10,
            criticalCount = 2,
            highCount = 3,
            mediumCount = 3,
            lowCount = 2,
            filesScanned = 50,
            linesOfCode = 5000L
        )

        assertEquals(10, stats.totalVulns)
        assertEquals(2, stats.criticalCount)
        assertEquals(3, stats.highCount)
        assertEquals(50, stats.filesScanned)
        assertEquals(5000L, stats.linesOfCode)
    }

    @Test
    fun `Rule data class stores all fields with default enabled`() {
        val rule = Rule(
            id = "SQL_001",
            name = "SQL Injection",
            description = "SQL injection via string concatenation",
            severity = Severity.CRITICAL,
            cwe = 89,
            owasp = "A03:2021",
            pattern = """SELECT.*\+\s*\w+"""
        )

        assertEquals("SQL_001", rule.id)
        assertTrue(rule.enabled)
        assertEquals(Severity.CRITICAL, rule.severity)
    }

    @Test
    fun `Rule can be disabled`() {
        val rule = Rule(
            id = "TEST", name = "Test", description = "desc",
            severity = Severity.LOW, cwe = 0, owasp = "", pattern = ".*",
            enabled = false
        )

        assertFalse(rule.enabled)
    }

    @Test
    fun `DeviceInfo data class stores all fields`() {
        val info = DeviceInfo(
            backend = "CUDA",
            deviceName = "RTX 4090",
            computeUnits = 128,
            maxMemoryMb = 24576L,
            supportsFloat64 = true
        )

        assertEquals("CUDA", info.backend)
        assertEquals("RTX 4090", info.deviceName)
        assertEquals(128, info.computeUnits)
        assertTrue(info.supportsFloat64)
    }

    @Test
    fun `Vulnerability equality works by data class semantics`() {
        val v1 = Vulnerability(
            "id1", "R1", "Rule1", VulnerabilityType.XSS, Severity.HIGH,
            79, "/test.js", 1, 1, "msg", "code"
        )
        val v2 = v1.copy()

        assertEquals(v1, v2)
        assertEquals(v1.hashCode(), v2.hashCode())
    }

    @Test
    fun `Vulnerability copy with changes works`() {
        val v1 = Vulnerability(
            "id1", "R1", "Rule1", VulnerabilityType.XSS, Severity.HIGH,
            79, "/test.js", 1, 1, "msg", "code"
        )
        val v2 = v1.copy(severity = Severity.CRITICAL, isFalsePositive = true)

        assertEquals(Severity.CRITICAL, v2.severity)
        assertTrue(v2.isFalsePositive)
        assertEquals("id1", v2.id)
    }
}
