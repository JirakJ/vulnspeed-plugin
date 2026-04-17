/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.sbom

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.jakubjirak.vulnspeed.model.FixSuggestion
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class CycloneDxSbomExporterTest {

    private val exporter = CycloneDxSbomExporter()
    private val app = AppMetadata(
        name = "demo-app",
        version = "1.2.3",
        bomRef = "app:demo-app",
        toolVersion = "2026.4.3"
    )

    private fun vuln(
        ruleId: String = "SQLI-001",
        severity: Severity = Severity.HIGH,
        cwe: Int = 89,
        filePath: String = "/proj/src/Foo.java",
        message: String = "SQL injection",
        fix: FixSuggestion? = null,
        tags: List<String> = emptyList()
    ) = Vulnerability(
        id = "$ruleId-1",
        ruleId = ruleId,
        ruleName = ruleId,
        type = VulnerabilityType.SQL_INJECTION,
        severity = severity,
        cwe = cwe,
        filePath = filePath,
        line = 1,
        column = 1,
        message = message,
        codeSnippet = "bad code",
        fixSuggestion = fix,
        tags = tags
    )

    private fun parse(json: String): JsonObject = JsonParser.parseString(json).asJsonObject

    @Test
    fun `empty inputs produce a valid minimal CycloneDX document`() {
        val json = exporter.export(emptyList(), emptyList(), app)
        val obj = parse(json) // must be Gson-parseable

        assertEquals("CycloneDX", obj.get("bomFormat").asString)
        assertEquals("1.5", obj.get("specVersion").asString)
        assertTrue(obj.get("serialNumber").asString.startsWith("urn:uuid:"))
        assertEquals(1, obj.get("version").asInt)

        val metadata = obj.getAsJsonObject("metadata")
        assertTrue(metadata.has("timestamp"))
        val toolComponents = metadata.getAsJsonObject("tools").getAsJsonArray("components")
        assertEquals(1, toolComponents.size())
        val tool = toolComponents[0].asJsonObject
        assertEquals("VulnSpeed", tool.get("name").asString)
        assertEquals("application", tool.get("type").asString)
        assertEquals("JirakJ", tool.get("publisher").asString)
        assertEquals("2026.4.3", tool.get("version").asString)

        val appComp = metadata.getAsJsonObject("component")
        assertEquals("application", appComp.get("type").asString)
        assertEquals("app:demo-app", appComp.get("bom-ref").asString)

        assertEquals(0, obj.getAsJsonArray("components").size())
        assertEquals(0, obj.getAsJsonArray("vulnerabilities").size())
    }

    @Test
    fun `single component and vuln - required keys and license shape`() {
        val comp = Component(
            bomRef = "pkg:maven/com.google.code.gson/gson@2.10.1",
            type = Component.Type.LIBRARY,
            name = "com.google.code.gson:gson",
            version = "2.10.1",
            purl = "pkg:maven/com.google.code.gson/gson@2.10.1",
            licenses = listOf("Apache-2.0"),
            hashes = mapOf("SHA-256" to "deadbeef")
        )
        val v = vuln(filePath = "/proj/gson/Demo.java", cwe = 89, severity = Severity.CRITICAL)

        val json = exporter.export(listOf(comp), listOf(v), app)
        val obj = parse(json)

        val comps = obj.getAsJsonArray("components")
        assertEquals(1, comps.size())
        val c = comps[0].asJsonObject
        assertEquals("library", c.get("type").asString)
        assertEquals(comp.bomRef, c.get("bom-ref").asString)
        assertEquals(comp.purl, c.get("purl").asString)

        val licArr = c.getAsJsonArray("licenses")
        assertEquals(1, licArr.size())
        assertEquals("Apache-2.0", licArr[0].asJsonObject.getAsJsonObject("license").get("id").asString)

        val hashArr = c.getAsJsonArray("hashes")
        assertEquals("SHA-256", hashArr[0].asJsonObject.get("alg").asString)
        assertEquals("deadbeef", hashArr[0].asJsonObject.get("content").asString)

        val vulns = obj.getAsJsonArray("vulnerabilities")
        assertEquals(1, vulns.size())
        val vo = vulns[0].asJsonObject
        assertEquals("CWE-89", vo.get("id").asString)
        assertEquals("VulnSpeed", vo.getAsJsonObject("source").get("name").asString)

        // CVSS rating emission
        val rating = vo.getAsJsonArray("ratings")[0].asJsonObject
        assertEquals("critical", rating.get("severity").asString)
        assertEquals("CVSSv3.1", rating.get("method").asString)
        assertEquals(9.8, rating.get("score").asDouble, 0.0001)

        // affects resolves to matching component by path token "gson"
        val ref = vo.getAsJsonArray("affects")[0].asJsonObject.get("ref").asString
        assertEquals(comp.bomRef, ref)
    }

    @Test
    fun `INFO severity emits no CVSS score`() {
        val v = vuln(severity = Severity.INFO, cwe = 0, filePath = "")
        val json = exporter.export(emptyList(), listOf(v), app)
        val rating = parse(json).getAsJsonArray("vulnerabilities")[0]
            .asJsonObject.getAsJsonArray("ratings")[0].asJsonObject
        assertEquals("info", rating.get("severity").asString)
        assertFalse(rating.has("score"))
        assertFalse(rating.has("method"))
    }

    @Test
    fun `affects falls back to application bom-ref when no component matches`() {
        val v = vuln(filePath = "/proj/src/NoMatch.java")
        val json = exporter.export(emptyList(), listOf(v), app)
        val ref = parse(json).getAsJsonArray("vulnerabilities")[0]
            .asJsonObject.getAsJsonArray("affects")[0].asJsonObject.get("ref").asString
        assertEquals("app:demo-app", ref)
    }

    @Test
    fun `serial number is stable for identical inputs and changes when inputs differ`() {
        val c1 = Component("pkg:npm/a@1", Component.Type.LIBRARY, "a", "1", "pkg:npm/a@1")
        val c2 = Component("pkg:npm/b@2", Component.Type.LIBRARY, "b", "2", "pkg:npm/b@2")

        val serialA = parse(exporter.export(listOf(c1, c2), emptyList(), app)).get("serialNumber").asString
        val serialA2 = parse(exporter.export(listOf(c2, c1), emptyList(), app)).get("serialNumber").asString
        assertEquals(serialA, serialA2, "order-independent stability")

        val c3 = Component("pkg:npm/c@3", Component.Type.LIBRARY, "c", "3", "pkg:npm/c@3")
        val serialB = parse(exporter.export(listOf(c1, c3), emptyList(), app)).get("serialNumber").asString
        assertNotEquals(serialA, serialB, "serial must change for different component set")

        assertTrue(serialA.matches(Regex("urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")))
    }

    @Test
    fun `multiple components preserve insertion order`() {
        val components = listOf(
            Component("pkg:maven/g/a@1", Component.Type.LIBRARY, "g:a", "1", "pkg:maven/g/a@1"),
            Component("pkg:maven/g/b@1", Component.Type.LIBRARY, "g:b", "1", "pkg:maven/g/b@1"),
            Component("pkg:maven/g/c@1", Component.Type.LIBRARY, "g:c", "1", "pkg:maven/g/c@1")
        )
        val arr = parse(exporter.export(components, emptyList(), app)).getAsJsonArray("components")
        assertEquals(3, arr.size())
        assertEquals("g:a", arr[0].asJsonObject.get("name").asString)
        assertEquals("g:c", arr[2].asJsonObject.get("name").asString)
    }

    @Test
    fun `vuln recommendation is emitted when fix suggestion provided, CVE tag preferred over CWE`() {
        val v = vuln(
            cwe = 89,
            fix = FixSuggestion(title = "Use prepared statements", description = "Bind parameters", code = ""),
            tags = listOf("cve-2024-12345")
        )
        val obj = parse(exporter.export(emptyList(), listOf(v), app))
            .getAsJsonArray("vulnerabilities")[0].asJsonObject
        assertEquals("CVE-2024-12345", obj.get("id").asString)
        assertTrue(obj.get("recommendation").asString.contains("Use prepared statements"))
    }

    @Test
    fun `schema spot-check - all required keys present`() {
        val json = exporter.export(emptyList(), emptyList(), app)
        val obj = parse(json)
        listOf("bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "vulnerabilities")
            .forEach { assertTrue(obj.has(it), "missing key: $it") }
        val md = obj.getAsJsonObject("metadata")
        listOf("timestamp", "tools", "component").forEach { assertTrue(md.has(it), "metadata missing: $it") }
        assertTrue(md.getAsJsonObject("tools").has("components"))
    }
}
