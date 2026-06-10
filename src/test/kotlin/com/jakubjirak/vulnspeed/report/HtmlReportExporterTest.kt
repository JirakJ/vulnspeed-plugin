/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.model.ScanStats
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class HtmlReportExporterTest {

    private fun vuln(
        ruleId: String = "SQL_001",
        ruleName: String = "SQL Injection",
        severity: Severity = Severity.CRITICAL,
        message: String = "User input concatenated into SQL",
        snippet: String = "query + userId",
        file: String = "/src/Main.java",
        line: Int = 42
    ) = Vulnerability(
        id = "test-id",
        ruleId = ruleId,
        ruleName = ruleName,
        type = VulnerabilityType.SQL_INJECTION,
        severity = severity,
        cwe = 89,
        filePath = file,
        line = line,
        column = 1,
        message = message,
        codeSnippet = snippet,
        confidence = 0.9f,
        owasp = "A03:2021 - Injection",
        fixSuggestion = null,
        tags = emptyList()
    )

    private fun result(vulns: List<Vulnerability>) = ScanResult(
        scanId = "scan-1",
        timestamp = 1750000000000L,
        durationMs = 123,
        vulnerabilities = vulns,
        stats = ScanStats(
            totalVulns = vulns.size,
            criticalCount = vulns.count { it.severity == Severity.CRITICAL },
            highCount = vulns.count { it.severity == Severity.HIGH },
            mediumCount = vulns.count { it.severity == Severity.MEDIUM },
            lowCount = vulns.count { it.severity == Severity.LOW },
            filesScanned = 3,
            linesOfCode = 1500
        )
    )

    @Test
    fun `produces complete html document`() {
        val html = HtmlReportExporter().export(result(listOf(vuln())), "my-project", "1.0.0")
        assertTrue(html.startsWith("<!DOCTYPE html>"))
        assertTrue(html.contains("</html>"))
        assertTrue(html.contains("<style>"))
        assertTrue(html.contains("VulnSpeed Security Report"))
    }

    @Test
    fun `report contains project name and tool version`() {
        val html = HtmlReportExporter().export(result(emptyList()), "my-project", "2026.6.0")
        assertTrue(html.contains("my-project"))
        assertTrue(html.contains("VulnSpeed 2026.6.0"))
    }

    @Test
    fun `summary cards reflect stats`() {
        val vulns = listOf(
            vuln(severity = Severity.CRITICAL),
            vuln(severity = Severity.HIGH),
            vuln(severity = Severity.HIGH)
        )
        val html = HtmlReportExporter().export(result(vulns), "p")
        assertTrue(html.contains(">3</span><span class=\"label\">Total findings</span>"))
        assertTrue(html.contains(">1</span><span class=\"label\">Critical</span>"))
        assertTrue(html.contains(">2</span><span class=\"label\">High</span>"))
        assertTrue(html.contains(">1500</span><span class=\"label\">Lines of code</span>"))
    }

    @Test
    fun `findings render as table rows with cwe links`() {
        val html = HtmlReportExporter().export(result(listOf(vuln())), "p")
        assertTrue(html.contains("<td><span class=\"badge critical\">CRITICAL</span></td>"))
        assertTrue(html.contains("https://cwe.mitre.org/data/definitions/89.html"))
        assertTrue(html.contains("/src/Main.java"))
        assertTrue(html.contains(":42"))
        assertTrue(html.contains("A03:2021 - Injection"))
    }

    @Test
    fun `empty scan renders clean banner without table`() {
        val html = HtmlReportExporter().export(result(emptyList()), "p")
        assertTrue(html.contains("No vulnerabilities found"))
        assertFalse(html.contains("<tbody>"))
    }

    @Test
    fun `html in finding fields is escaped`() {
        val nasty = vuln(
            ruleName = "<script>alert(1)</script>",
            message = "uses <b>bold</b> & \"quotes\"",
            snippet = "if (a < b && c > d)",
            file = "/src/<evil>.java"
        )
        val html = HtmlReportExporter().export(result(listOf(nasty)), "<proj>")
        assertFalse(html.contains("<script>alert(1)</script>"))
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))
        assertTrue(html.contains("uses &lt;b&gt;bold&lt;/b&gt; &amp; &quot;quotes&quot;"))
        assertTrue(html.contains("if (a &lt; b &amp;&amp; c &gt; d)"))
        assertTrue(html.contains("&lt;proj&gt;"))
    }

    @Test
    fun `escape handles all special characters`() {
        assertEquals("&amp;&lt;&gt;&quot;&#39;", HtmlReportExporter.escape("&<>\"'"))
        assertEquals("plain text", HtmlReportExporter.escape("plain text"))
        assertEquals("", HtmlReportExporter.escape(""))
    }

    @Test
    fun `severity badges cover all levels`() {
        val vulns = listOf(
            vuln(severity = Severity.CRITICAL),
            vuln(severity = Severity.HIGH),
            vuln(severity = Severity.MEDIUM),
            vuln(severity = Severity.LOW)
        )
        val html = HtmlReportExporter().export(result(vulns), "p")
        assertTrue(html.contains("badge critical"))
        assertTrue(html.contains("badge high"))
        assertTrue(html.contains("badge medium"))
        assertTrue(html.contains("badge low"))
    }

    @Test
    fun `report has no external resource references`() {
        val html = HtmlReportExporter().export(result(listOf(vuln())), "p")
        assertFalse(html.contains("<link"))
        assertFalse(html.contains("<script src"))
        assertFalse(html.contains("@import"))
    }
}
