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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class VulnBaselineCliTest {

    private fun v(
        ruleId: String = "R1",
        line: Int = 10,
        severity: Severity = Severity.HIGH,
        root: Path,
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
        message = "msg",
        codeSnippet = "",
    )

    private fun writeFindings(path: Path, findings: List<Vulnerability>) {
        VulnFindingsJson.write(findings, path)
    }

    private fun runCli(args: Array<String>): Triple<Int, String, String> {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = VulnBaselineCli.run(args, PrintStream(out, true, StandardCharsets.UTF_8), PrintStream(err, true, StandardCharsets.UTF_8))
        return Triple(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8))
    }

    @Test
    fun `missing mode returns exit code 1`() {
        val (code, _, err) = runCli(arrayOf("--project=/x", "--findings=/y"))
        assertEquals(1, code)
        assertTrue(err.contains("Must specify"))
    }

    @Test
    fun `unknown argument returns exit code 1`() {
        val (code, _, err) = runCli(arrayOf("--compare", "--nope"))
        assertEquals(1, code)
        assertTrue(err.contains("Unrecognised"))
    }

    @Test
    fun `create writes baseline with expected entries`(@TempDir root: Path) {
        val findingsFile = root.resolve("findings.json")
        writeFindings(findingsFile, listOf(v(root = root), v(ruleId = "R2", root = root)))
        val baselineFile = root.resolve("baseline.json")
        val (code, out, _) = runCli(arrayOf(
            "--create",
            "--project=$root",
            "--findings=$findingsFile",
            "--baseline=$baselineFile",
            "--tool-version=2026.4.4",
        ))
        assertEquals(0, code)
        assertTrue(out.contains("Wrote 2 entries"))
        val loaded = VulnBaselineStore.load(baselineFile)!!
        assertEquals(2, loaded.entries.size)
        assertEquals("2026.4.4", loaded.toolVersion)
    }

    @Test
    fun `compare with no regressions exits 0`(@TempDir root: Path) {
        val findings = listOf(v(root = root))
        val findingsFile = root.resolve("findings.json")
        writeFindings(findingsFile, findings)
        val baselineFile = root.resolve("baseline.json")

        // Build baseline from same findings
        runCli(arrayOf("--create", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile"))

        val (code, out, _) = runCli(arrayOf(
            "--compare",
            "--project=$root",
            "--findings=$findingsFile",
            "--baseline=$baselineFile",
            "--fail-on=regression",
        ))
        assertEquals(0, code)
        assertTrue(out.contains("No New Regressions") || out.contains("No new regressions"))
    }

    @Test
    fun `compare with regressions and fail-on regression exits 2`(@TempDir root: Path) {
        val findingsFile = root.resolve("findings.json")
        val baselineFile = root.resolve("baseline.json")
        writeFindings(findingsFile, listOf(v(root = root)))
        runCli(arrayOf("--create", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile"))
        // Now expand findings with a new one
        writeFindings(findingsFile, listOf(v(root = root), v(ruleId = "R2", root = root, severity = Severity.CRITICAL)))
        val (code, _, err) = runCli(arrayOf(
            "--compare",
            "--project=$root",
            "--findings=$findingsFile",
            "--baseline=$baselineFile",
            "--fail-on=regression",
        ))
        assertEquals(2, code)
        assertTrue(err.contains("policy"))
    }

    @Test
    fun `fail-on severity threshold only trips for matching severity`(@TempDir root: Path) {
        val findingsFile = root.resolve("findings.json")
        val baselineFile = root.resolve("baseline.json")
        writeFindings(findingsFile, emptyList())
        runCli(arrayOf("--create", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile"))
        // Now a single LOW-severity regression
        writeFindings(findingsFile, listOf(v(root = root, severity = Severity.LOW)))
        val (lowCode, _, _) = runCli(arrayOf(
            "--compare", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile",
            "--fail-on=severity:HIGH",
        ))
        assertEquals(0, lowCode)

        writeFindings(findingsFile, listOf(v(root = root, severity = Severity.CRITICAL)))
        val (critCode, _, _) = runCli(arrayOf(
            "--compare", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile",
            "--fail-on=severity:HIGH",
        ))
        assertEquals(2, critCode)
    }

    @Test
    fun `output json emits valid JSON with expected keys`(@TempDir root: Path) {
        val findingsFile = root.resolve("findings.json")
        val baselineFile = root.resolve("baseline.json")
        writeFindings(findingsFile, emptyList())
        runCli(arrayOf("--create", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile"))
        writeFindings(findingsFile, listOf(v(root = root)))
        val outFile = root.resolve("diff.json")
        val (code, _, _) = runCli(arrayOf(
            "--compare", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile",
            "--output=json", "--output-file=$outFile",
        ))
        assertEquals(0, code)
        val text = Files.readString(outFile, StandardCharsets.UTF_8)
        assertTrue(text.contains("\"newFindings\""))
        assertTrue(text.contains("\"summary\""))
        assertFalse(text.contains("🚨"), "JSON output should not contain markdown banner")
    }

    @Test
    fun `output md is default when --output not specified`(@TempDir root: Path) {
        val findingsFile = root.resolve("findings.json")
        val baselineFile = root.resolve("baseline.json")
        writeFindings(findingsFile, emptyList())
        runCli(arrayOf("--create", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile"))
        writeFindings(findingsFile, listOf(v(root = root)))
        val (code, out, _) = runCli(arrayOf(
            "--compare", "--project=$root", "--findings=$findingsFile", "--baseline=$baselineFile",
        ))
        assertEquals(0, code)
        assertTrue(out.contains("# 🚨") || out.contains("# ✅"))
    }

    @Test
    fun `failOnPolicy parse rejects unknown severity`() {
        assertThrows(IllegalArgumentException::class.java) { FailOnPolicy.parse("severity:BOGUS") }
    }

    @Test
    fun `failOnPolicy parse handles blank as Never`() {
        assertEquals(FailOnPolicy.Never, FailOnPolicy.parse(null))
        assertEquals(FailOnPolicy.Never, FailOnPolicy.parse(""))
    }

    @Test
    fun `failOnPolicy parse handles regression keyword`() {
        assertEquals(FailOnPolicy.AnyRegression, FailOnPolicy.parse("regression"))
    }

    @Test
    fun `findings json round-trip preserves ruleId and line`(@TempDir dir: Path) {
        val p = dir.resolve("f.json")
        val orig = listOf(v(ruleId = "X", line = 77, root = dir))
        VulnFindingsJson.write(orig, p)
        val back = VulnFindingsJson.read(p)
        assertEquals(1, back.size)
        assertEquals("X", back[0].ruleId)
        assertEquals(77, back[0].line)
    }
}
