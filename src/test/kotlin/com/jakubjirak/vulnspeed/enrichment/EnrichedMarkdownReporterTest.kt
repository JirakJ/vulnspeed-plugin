/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

class EnrichedMarkdownReporterTest {

    private fun v(
        ruleId: String = "CVE-2021-44228",
        severity: Severity = Severity.HIGH,
        line: Int = 10,
    ) = Vulnerability(
        id = "x",
        ruleId = ruleId,
        ruleName = ruleId,
        type = VulnerabilityType.VULNERABLE_COMPONENTS,
        severity = severity,
        cwe = 502,
        filePath = "pom.xml",
        line = line,
        column = 0,
        message = "pipe | in msg",
        codeSnippet = "",
    )

    private fun md() = CveMetadata(
        cveId = "CVE-2021-44228",
        cvssScore = 10.0,
        cvssVector = "CVSS:3.1/AV:N",
        severity = "CRITICAL",
        cweIds = listOf("CWE-502"),
        published = Instant.parse("2021-12-10T00:00:00Z"),
        modified = Instant.parse("2021-12-20T00:00:00Z"),
        summary = "Log4Shell",
        references = listOf("https://example.com/a"),
        fixedVersions = listOf("Maven:log4j:2.17.0"),
        affectedRanges = listOf(AffectedRange("Maven", "log4j", "2.0", "2.17.0")),
        source = "OSV",
    )

    @Test
    fun `renders summary, enriched and raw sections`() {
        val list = listOf(
            EnrichedVulnerability(v(), md()),
            EnrichedVulnerability(v(ruleId = "INTERNAL", severity = Severity.LOW), null),
        )
        val out = EnrichedMarkdownReporter.render(list, toolVersion = "2026.4.5")

        assertTrue(out.contains("# VulnSpeed"))
        assertTrue(out.contains("## Summary"))
        assertTrue(out.contains("Enriched with CVE metadata: 1"))
        assertTrue(out.contains("CVE-2021-44228"))
        assertTrue(out.contains("CWE-502"))
        assertTrue(out.contains("2.17.0"))
        assertTrue(out.contains("Findings without CVE Metadata"))
        assertTrue(out.contains("2026.4.5"))
        // pipes in messages must be escaped
        if (!out.contains("pipe \\| in msg")) {
            throw AssertionError("Output did not contain expected escaped pipe. Got:\n$out")
        }
    }

    @Test
    fun `handles empty enriched input`() {
        val out = EnrichedMarkdownReporter.render(emptyList())
        assertTrue(out.contains("No findings could be enriched"))
    }
}
