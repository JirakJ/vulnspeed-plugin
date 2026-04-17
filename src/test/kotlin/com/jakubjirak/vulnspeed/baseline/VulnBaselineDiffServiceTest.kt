/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class VulnBaselineDiffServiceTest {

    private fun v(
        ruleId: String,
        line: Int,
        root: Path,
        severity: Severity = Severity.HIGH,
        message: String = "msg",
    ): Vulnerability = Vulnerability(
        id = "$ruleId-$line",
        ruleId = ruleId,
        ruleName = ruleId,
        type = VulnerabilityType.SQL_INJECTION,
        severity = severity,
        cwe = 89,
        filePath = root.resolve("src/A.java").toString(),
        line = line,
        column = 1,
        message = message,
        codeSnippet = "",
    )

    private fun baseline(root: Path, vararg findings: Vulnerability): VulnBaseline =
        VulnBaseline.fromFindings(findings.toList(), root, "test-tool", acceptedAtEpochMs = 0L)

    @Test
    fun `null baseline reports all current as new`(@TempDir root: Path) {
        val current = listOf(v("R1", 1, root), v("R1", 2, root))
        val diff = VulnBaselineDiffService.diff(null, current, root)
        assertEquals(2, diff.summary.totalNew)
        assertEquals(0, diff.summary.totalFixed)
        assertEquals(0, diff.summary.totalPersisted)
        assertTrue(diff.hasRegressions())
    }

    @Test
    fun `empty current yields all fixed`(@TempDir root: Path) {
        val b = baseline(root, v("R1", 1, root), v("R2", 2, root))
        val diff = VulnBaselineDiffService.diff(b, emptyList(), root)
        assertEquals(0, diff.summary.totalNew)
        assertEquals(2, diff.summary.totalFixed)
        assertFalse(diff.hasRegressions())
    }

    @Test
    fun `identical current matches baseline as all persisted`(@TempDir root: Path) {
        val existing = listOf(v("R1", 1, root), v("R2", 2, root))
        val b = baseline(root, *existing.toTypedArray())
        val diff = VulnBaselineDiffService.diff(b, existing, root)
        assertEquals(0, diff.summary.totalNew)
        assertEquals(0, diff.summary.totalFixed)
        assertEquals(2, diff.summary.totalPersisted)
    }

    @Test
    fun `mixed diff partitions correctly`(@TempDir root: Path) {
        val persisted = v("R1", 1, root)
        val fixed = v("R2", 2, root)
        val new1 = v("R3", 3, root, severity = Severity.CRITICAL)
        val new2 = v("R4", 4, root, severity = Severity.LOW)
        val b = baseline(root, persisted, fixed)
        val current = listOf(persisted, new1, new2)

        val diff = VulnBaselineDiffService.diff(b, current, root)
        assertEquals(2, diff.newFindings.size)
        assertEquals(1, diff.fixedEntries.size)
        assertEquals(1, diff.persistedFindings.size)
        assertEquals(1, diff.summary.newBySeverity[Severity.CRITICAL.name])
        assertEquals(1, diff.summary.newBySeverity[Severity.LOW.name])
        assertEquals(0, diff.summary.newBySeverity[Severity.HIGH.name])
        assertTrue(diff.hasRegressions())
    }

    @Test
    fun `countAtOrAbove computes severity threshold`(@TempDir root: Path) {
        val diff = VulnBaselineDiffService.diff(
            null,
            listOf(
                v("R", 1, root, severity = Severity.CRITICAL),
                v("R", 2, root, severity = Severity.HIGH),
                v("R", 3, root, severity = Severity.MEDIUM),
                v("R", 4, root, severity = Severity.LOW),
            ),
            root,
        )
        assertEquals(1, diff.summary.countAtOrAbove(Severity.CRITICAL))
        assertEquals(2, diff.summary.countAtOrAbove(Severity.HIGH))
        assertEquals(3, diff.summary.countAtOrAbove(Severity.MEDIUM))
        assertEquals(4, diff.summary.countAtOrAbove(Severity.LOW))
    }

    @Test
    fun `every severity is present in summary map`(@TempDir root: Path) {
        val diff = VulnBaselineDiffService.diff(null, emptyList(), root)
        for (s in Severity.entries) {
            assertTrue(diff.summary.newBySeverity.containsKey(s.name))
        }
    }
}
