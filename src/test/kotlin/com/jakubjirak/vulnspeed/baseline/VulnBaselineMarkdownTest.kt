/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VulnBaselineMarkdownTest {

    private fun v(
        ruleId: String = "R1",
        severity: Severity = Severity.HIGH,
        message: String = "msg",
        filePath: String = "src/A.java",
    ): Vulnerability = Vulnerability(
        id = "id",
        ruleId = ruleId,
        ruleName = ruleId,
        type = VulnerabilityType.SQL_INJECTION,
        severity = severity,
        cwe = 89,
        filePath = filePath,
        line = 1,
        column = 1,
        message = message,
        codeSnippet = "",
    )

    private fun diff(
        new: List<Vulnerability> = emptyList(),
        fixed: List<VulnBaselineEntry> = emptyList(),
        persisted: List<Vulnerability> = emptyList(),
    ): VulnBaselineDiff {
        val counts = Severity.entries.associate { it.name to new.count { f -> f.severity == it } }
        return VulnBaselineDiff(
            newFindings = new,
            fixedEntries = fixed,
            persistedFindings = persisted,
            summary = VulnBaselineDiffSummary(counts, new.size, fixed.size, persisted.size),
        )
    }

    @Test
    fun `empty diff shows success banner`() {
        val md = VulnBaselineMarkdown.render(diff())
        assertTrue(md.contains("✅"))
        assertTrue(md.contains("No New Regressions"))
        assertTrue(md.contains("No new regressions were introduced"))
    }

    @Test
    fun `regressions trigger alert banner`() {
        val md = VulnBaselineMarkdown.render(diff(new = listOf(v())))
        assertTrue(md.contains("🚨"))
        assertTrue(md.contains("Regressions Detected"))
    }

    @Test
    fun `pipes and backticks are escaped in table cells`() {
        val md = VulnBaselineMarkdown.render(diff(new = listOf(v(message = "oops | `bad`"))))
        assertTrue(md.contains("oops \\| \\`bad\\`"), "got:\n$md")
    }

    @Test
    fun `collapsible details appear when bucket exceeds threshold`() {
        val many = (1..(VulnBaselineMarkdown.COLLAPSIBLE_THRESHOLD + 1)).map { v(ruleId = "R$it") }
        val md = VulnBaselineMarkdown.render(diff(new = many))
        assertTrue(md.contains("<details>"))
        assertTrue(md.contains("</details>"))
    }

    @Test
    fun `bucket at threshold is rendered inline`() {
        val exact = (1..VulnBaselineMarkdown.COLLAPSIBLE_THRESHOLD).map { v(ruleId = "R$it") }
        val md = VulnBaselineMarkdown.render(diff(new = exact))
        assertFalse(md.contains("<details>"))
    }

    @Test
    fun `fixed section appears when fixed entries present`() {
        val fixedEntry = VulnBaselineEntry(
            fingerprint = "f",
            ruleId = "R1",
            severity = "HIGH",
            cwe = 89,
            filePath = "src/A.java",
            startLine = 2,
            messageHash = "m",
        )
        val md = VulnBaselineMarkdown.render(diff(fixed = listOf(fixedEntry)))
        assertTrue(md.contains("Fixed since baseline"))
        assertTrue(md.contains("src/A.java"))
    }

    @Test
    fun `tool version footer is included when provided`() {
        val md = VulnBaselineMarkdown.render(diff(), toolVersion = "2026.4.4")
        assertTrue(md.contains("2026.4.4"))
    }

    @Test
    fun `escape transforms newlines into spaces`() {
        assertEquals("a b", VulnBaselineMarkdown.escape("a\nb"))
    }

    @Test
    fun `per severity counts are rendered in summary`() {
        val md = VulnBaselineMarkdown.render(
            diff(
                new = listOf(
                    v(severity = Severity.CRITICAL),
                    v(severity = Severity.HIGH),
                    v(severity = Severity.HIGH),
                ),
            )
        )
        assertTrue(md.contains("New CRITICAL"))
        assertTrue(md.contains("New HIGH"))
    }
}
