/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

import com.google.gson.Gson
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SarifReportExporterTest {

    private val exporter = SarifReportExporter()
    private val root = "/tmp/project"
    private val version = "2026.4.2"

    private fun v(
        ruleId: String = "SQLI-001",
        ruleName: String = "SQL Injection",
        type: VulnerabilityType = VulnerabilityType.SQL_INJECTION,
        severity: Severity = Severity.HIGH,
        cwe: Int = 89,
        filePath: String = "/tmp/project/src/Foo.java",
        line: Int = 10,
        column: Int = 5,
        message: String = "SQL injection vulnerability detected",
        codeSnippet: String = "stmt.execute(query)",
        owasp: String = "A03:2021"
    ) = Vulnerability(
        id = "$ruleId-$line",
        ruleId = ruleId,
        ruleName = ruleName,
        type = type,
        severity = severity,
        cwe = cwe,
        filePath = filePath,
        line = line,
        column = column,
        message = message,
        codeSnippet = codeSnippet,
        owasp = owasp
    )

    @Suppress("UNCHECKED_CAST")
    private fun parse(json: String): Map<String, Any> =
        Gson().fromJson(json, Map::class.java) as Map<String, Any>

    @Test
    fun `empty findings produces valid SARIF with zero results`() {
        val json = exporter.export(emptyList(), version, root)
        val map = parse(json)
        assertEquals("2.1.0", map["version"])
        assertEquals(
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
            map["\$schema"]
        )
        val runs = map["runs"] as List<*>
        assertEquals(1, runs.size)
        val run = runs[0] as Map<*, *>
        val driver = (run["tool"] as Map<*, *>)["driver"] as Map<*, *>
        assertEquals("VulnSpeed", driver["name"])
        assertEquals(version, driver["version"])
        assertEquals("https://github.com/JirakJ/vulnspeed-plugin", driver["informationUri"])
        assertTrue((driver["rules"] as List<*>).isEmpty())
        assertTrue((run["results"] as List<*>).isEmpty())
    }

    @Test
    fun `single finding produces matching rule and result`() {
        val json = exporter.export(listOf(v()), version, root)
        val map = parse(json)
        val run = (map["runs"] as List<*>)[0] as Map<*, *>
        val rules = ((run["tool"] as Map<*, *>)["driver"] as Map<*, *>)["rules"] as List<*>
        val results = run["results"] as List<*>
        assertEquals(1, rules.size)
        assertEquals(1, results.size)
        val rule = rules[0] as Map<*, *>
        assertEquals("SQLI-001", rule["id"])
        assertEquals("https://cwe.mitre.org/data/definitions/89.html", rule["helpUri"])
        assertEquals("error", (rule["defaultConfiguration"] as Map<*, *>)["level"])
        val result = results[0] as Map<*, *>
        assertEquals("SQLI-001", result["ruleId"])
        assertEquals("error", result["level"])
        val loc = (((result["locations"] as List<*>)[0] as Map<*, *>)["physicalLocation"]) as Map<*, *>
        val uri = (loc["artifactLocation"] as Map<*, *>)["uri"]
        assertEquals("src/Foo.java", uri)
        val region = loc["region"] as Map<*, *>
        assertEquals(10.0, region["startLine"])
        assertEquals(10.0, region["endLine"])
        assertEquals(5.0, region["startColumn"])
        assertEquals(6.0, region["endColumn"])
        assertNotNull((result["partialFingerprints"] as Map<*, *>)["vulnspeed/v1"])
    }

    @Test
    fun `multiple findings sharing ruleId produce a single deduped rule`() {
        val findings = listOf(
            v(line = 10),
            v(line = 42, message = "another spot"),
            v(ruleId = "XSS-001", ruleName = "XSS", cwe = 79, severity = Severity.MEDIUM, line = 7)
        )
        val rules = exporter.buildRules(findings)
        assertEquals(2, rules.size)
        assertEquals(setOf("SQLI-001", "XSS-001"), rules.map { it.id }.toSet())

        val json = exporter.export(findings, version, root)
        val map = parse(json)
        val run = (map["runs"] as List<*>)[0] as Map<*, *>
        val emittedRules = ((run["tool"] as Map<*, *>)["driver"] as Map<*, *>)["rules"] as List<*>
        assertEquals(2, emittedRules.size)
        assertEquals(3, (run["results"] as List<*>).size)
    }

    @Test
    fun `severity mapping covers all levels`() {
        assertEquals("error", exporter.severityToLevel(Severity.CRITICAL))
        assertEquals("error", exporter.severityToLevel(Severity.HIGH))
        assertEquals("warning", exporter.severityToLevel(Severity.MEDIUM))
        assertEquals("note", exporter.severityToLevel(Severity.LOW))
        assertEquals("note", exporter.severityToLevel(Severity.INFO))
    }

    @Test
    fun `cwe uri for known id links to MITRE definition page`() {
        assertEquals("https://cwe.mitre.org/data/definitions/89.html", exporter.cweUri(89))
        assertEquals("https://cwe.mitre.org/data/definitions/79.html", exporter.cweUri(79))
    }

    @Test
    fun `cwe uri falls back for unknown or non-positive ids`() {
        assertEquals("https://cwe.mitre.org/data/definitions/", exporter.cweUri(0))
        assertEquals("https://cwe.mitre.org/data/definitions/", exporter.cweUri(-1))
    }

    @Test
    fun `uri escaping handles spaces and unicode`() {
        val encoded = exporter.toUriPath("src/hello world/úñíçødé.kt")
        assertFalse(encoded.contains(' '))
        assertTrue(encoded.contains("hello%20world"))
        assertTrue(encoded.contains("%C3%BA") || encoded.contains("%c3%bc") || encoded.contains("%C3"))
        assertTrue(encoded.startsWith("src/"))
    }

    @Test
    fun `uri escaping preserves forward slashes and safe chars`() {
        assertEquals("a/b/c.txt", exporter.toUriPath("a/b/c.txt"))
        assertEquals("a/b/c-d_e.f~g", exporter.toUriPath("a/b/c-d_e.f~g"))
    }

    @Test
    fun `json escaping handles quotes backslashes newlines and control chars`() {
        val nasty = "He said \"hi\"\nline2\tTab\\back\u0001ctl"
        val finding = v(message = nasty, codeSnippet = nasty)
        val json = exporter.export(listOf(finding), version, root)
        // Must still parse.
        val map = parse(json)
        val run = (map["runs"] as List<*>)[0] as Map<*, *>
        val result = (run["results"] as List<*>)[0] as Map<*, *>
        val text = (result["message"] as Map<*, *>)["text"] as String
        assertEquals(nasty, text)
    }

    @Test
    fun `fingerprint is deterministic for same inputs`() {
        val f1 = exporter.fingerprint("SQLI-001", "src/Foo.java", 10, "msg")
        val f2 = exporter.fingerprint("SQLI-001", "src/Foo.java", 10, "msg")
        assertEquals(f1, f2)
        assertEquals(64, f1.length) // sha256 hex
    }

    @Test
    fun `fingerprint differs when any component differs`() {
        val base = exporter.fingerprint("SQLI-001", "src/Foo.java", 10, "msg")
        assertNotEquals(base, exporter.fingerprint("SQLI-002", "src/Foo.java", 10, "msg"))
        assertNotEquals(base, exporter.fingerprint("SQLI-001", "src/Bar.java", 10, "msg"))
        assertNotEquals(base, exporter.fingerprint("SQLI-001", "src/Foo.java", 11, "msg"))
        assertNotEquals(base, exporter.fingerprint("SQLI-001", "src/Foo.java", 10, "other"))
    }

    @Test
    fun `output is valid JSON parseable by Gson`() {
        val findings = (1..5).map { v(line = it * 10) }
        val json = exporter.export(findings, version, root)
        assertNotNull(Gson().fromJson(json, Map::class.java))
    }

    @Test
    fun `schema spot-check contains all required SARIF keys`() {
        val json = exporter.export(listOf(v()), version, root)
        assertTrue(json.contains("\"\$schema\""))
        assertTrue(json.contains("\"version\":\"2.1.0\""))
        assertTrue(json.contains("\"runs\":["))
        assertTrue(json.contains("\"tool\":{"))
        assertTrue(json.contains("\"driver\":{"))
        assertTrue(json.contains("\"rules\":["))
        assertTrue(json.contains("\"results\":["))
        assertTrue(json.contains("\"ruleId\":"))
        assertTrue(json.contains("\"locations\":["))
        assertTrue(json.contains("\"physicalLocation\":"))
        assertTrue(json.contains("\"artifactLocation\":"))
        assertTrue(json.contains("\"region\":"))
        assertTrue(json.contains("\"startLine\":"))
        assertTrue(json.contains("\"partialFingerprints\":"))
    }

    @Test
    fun `path outside project root is emitted unchanged`() {
        val absolute = "/elsewhere/foo.kt"
        val rel = exporter.relativize(absolute, root)
        assertEquals(absolute, rel)
    }

    @Test
    fun `path inside project root is made relative`() {
        assertEquals("src/Foo.kt", exporter.relativize("/tmp/project/src/Foo.kt", "/tmp/project"))
        assertEquals("src/Foo.kt", exporter.relativize("/tmp/project/src/Foo.kt", "/tmp/project/"))
    }

    @Test
    fun `severity score covers all levels`() {
        assertEquals("9.5", exporter.severityToScore(Severity.CRITICAL))
        assertEquals("8.0", exporter.severityToScore(Severity.HIGH))
        assertEquals("5.0", exporter.severityToScore(Severity.MEDIUM))
        assertEquals("3.0", exporter.severityToScore(Severity.LOW))
        assertEquals("1.0", exporter.severityToScore(Severity.INFO))
    }

    @Test
    fun `rule index is emitted in result and matches rule position`() {
        val findings = listOf(
            v(ruleId = "A", line = 1),
            v(ruleId = "B", line = 2),
            v(ruleId = "A", line = 3)
        )
        val json = exporter.export(findings, version, root)
        val map = parse(json)
        val run = (map["runs"] as List<*>)[0] as Map<*, *>
        val results = run["results"] as List<*>
        assertEquals(0.0, (results[0] as Map<*, *>)["ruleIndex"])
        assertEquals(1.0, (results[1] as Map<*, *>)["ruleIndex"])
        assertEquals(0.0, (results[2] as Map<*, *>)["ruleIndex"])
    }

    @Test
    fun `line and column are clamped to minimum 1`() {
        val json = exporter.export(listOf(v(line = 0, column = 0)), version, root)
        val map = parse(json)
        val run = (map["runs"] as List<*>)[0] as Map<*, *>
        val result = (run["results"] as List<*>)[0] as Map<*, *>
        val region = (((result["locations"] as List<*>)[0] as Map<*, *>)["physicalLocation"] as Map<*, *>)["region"] as Map<*, *>
        assertEquals(1.0, region["startLine"])
        assertEquals(1.0, region["startColumn"])
    }
}
