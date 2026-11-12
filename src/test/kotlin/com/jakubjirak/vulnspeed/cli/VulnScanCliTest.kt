/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.cli

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.jakubjirak.vulnspeed.baseline.VulnFindingsJson
import com.jakubjirak.vulnspeed.model.Severity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class VulnScanCliTest {

    @TempDir
    lateinit var dir: Path

    private fun scan(vararg args: String) =
        CliFixtures.capture { out, err -> VulnScanCli.run(arrayOf(*args), out, err, "9.9.9-test") }

    private fun readJson(path: Path): JsonObject =
        JsonParser.parseString(Files.readString(path, StandardCharsets.UTF_8)).asJsonObject

    @Test
    fun `writes findings JSON readable by the baseline and enrich CLIs`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val json = dir.resolve("out/findings.json")

        val run = scan("--project=$project", "--out-json=$json")

        assertEquals(0, run.code, run.err)
        val findings = VulnFindingsJson.read(json)
        assertTrue(findings.any { it.ruleId == "SQL_001" && it.filePath.endsWith("App.java") })
        assertTrue(findings.none { it.ruleId == "SQL_001" && it.filePath.endsWith("Accepted.java") })
        assertTrue(findings.none { it.filePath.endsWith("OptedOut.java") })
        assertTrue(run.out.contains("Wrote ${findings.size} findings"))
        assertTrue(run.out.contains("Scanned 4 file(s)"))
    }

    @Test
    fun `writes a valid SARIF 2_1_0 report with project-relative locations`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val sarif = dir.resolve("report.sarif")
        val json = dir.resolve("findings.json")

        assertEquals(0, scan("--project=$project", "--out-sarif=$sarif", "--out-json=$json").code)

        val doc = readJson(sarif)
        assertEquals("2.1.0", doc["version"].asString)
        assertTrue(doc["\$schema"].asString.contains("sarif-schema-2.1.0"))
        val run = doc.getAsJsonArray("runs")[0].asJsonObject
        val driver = run.getAsJsonObject("tool").getAsJsonObject("driver")
        assertEquals("VulnSpeed", driver["name"].asString)
        assertEquals("9.9.9-test", driver["version"].asString)

        val results = run.getAsJsonArray("results")
        assertEquals(VulnFindingsJson.read(json).size, results.size())
        val uris = results.map {
            it.asJsonObject.getAsJsonArray("locations")[0].asJsonObject
                .getAsJsonObject("physicalLocation").getAsJsonObject("artifactLocation")["uri"].asString
        }
        assertTrue("src/main/java/App.java" in uris, uris.toString())
        assertTrue(uris.none { it.startsWith("/") }, uris.toString())
        val ruleIds = driver.getAsJsonArray("rules").map { it.asJsonObject["id"].asString }
        assertTrue(results.all { it.asJsonObject["ruleId"].asString in ruleIds })
    }

    @Test
    fun `fail-on returns 2 when a finding meets the threshold`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))

        val run = scan("--project=$project", "--fail-on=severity:HIGH")

        assertEquals(2, run.code)
        assertTrue(run.err.contains("--fail-on=severity:HIGH triggered"))
    }

    @Test
    fun `fail-on returns 0 for a clean project and outputs are still written`() {
        val project = CliFixtures.cleanProject(dir.resolve("p"))
        val json = dir.resolve("findings.json")
        val sarif = dir.resolve("r.sarif")

        val run = scan("--project=$project", "--out-json=$json", "--out-sarif=$sarif", "--fail-on=severity:LOW")

        assertEquals(0, run.code, run.err)
        assertEquals(emptyList<Any>(), VulnFindingsJson.read(json))
        assertEquals(0, readJson(sarif).getAsJsonArray("runs")[0].asJsonObject.getAsJsonArray("results").size())
    }

    @Test
    fun `no fail-on means exit 0 even with critical findings`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        assertEquals(0, scan("--project=$project").code)
    }

    @Test
    fun `max-file-size-kb and max-files are honoured and reported`() {
        val project = dir.resolve("p")
        CliFixtures.write(project, "Big.java", CliFixtures.SQL_LINE + "\n" + "x".repeat(4096))
        CliFixtures.write(project, "a/A.java", CliFixtures.CLEAN_SOURCE)
        CliFixtures.write(project, "b/B.java", CliFixtures.CLEAN_SOURCE)

        val run = scan("--project=$project", "--max-file-size-kb=1", "--max-files=2", "--fail-on=severity:CRITICAL")

        assertEquals(0, run.code, run.err) // Big.java is first in path order but skipped as too large
        assertTrue(run.err.contains("skipped 1 file(s) larger than 1 KB"))
        assertTrue(run.err.contains("scanned only the first 2"))
    }

    @Test
    fun `bad arguments return 1`() {
        assertEquals(1, scan().code)
        assertEquals(1, scan("--project=${dir.resolve("missing")}").code)
        assertEquals(1, scan("--project=$dir", "--fail-on=regression").code)
        assertEquals(1, scan("--project=$dir", "--fail-on=severity:URGENT").code)
        assertEquals(1, scan("--project=$dir", "--max-files=0").code)
        assertEquals(1, scan("--project=$dir", "--max-file-size-kb=abc").code)
        val unknown = scan("--project=$dir", "--bogus")
        assertEquals(1, unknown.code)
        assertTrue(unknown.err.contains("Unrecognised argument: --bogus"))
        assertTrue(unknown.err.contains("Usage:"))
    }

    @Test
    fun `unwritable output returns 1`() {
        val project = CliFixtures.cleanProject(dir.resolve("p"))
        val blocker = CliFixtures.write(dir, "file", "")

        val run = scan("--project=$project", "--out-json=${blocker.resolve("x.json")}")

        assertEquals(1, run.code)
        assertTrue(run.err.contains("IO error"))
    }

    @Test
    fun `severity threshold counting`() {
        val findings = VulnFindingsJson.read(
            scanToJson(CliFixtures.vulnerableProject(dir.resolve("p")))
        )
        assertTrue(VulnScanCli.countAtOrAbove(findings, Severity.CRITICAL) >= 1)
        assertEquals(findings.size, VulnScanCli.countAtOrAbove(findings, Severity.INFO))
        assertFalse(VulnScanCli.countAtOrAbove(emptyList(), Severity.INFO) > 0)
    }

    @Test
    fun `fail-on parser`() {
        assertEquals(Severity.HIGH, VulnScanCli.Args.parseFailOn("severity:high"))
        assertEquals(Severity.CRITICAL, VulnScanCli.Args.parseFailOn("SEVERITY:CRITICAL"))
        assertThrows(IllegalArgumentException::class.java) { VulnScanCli.Args.parseFailOn("HIGH") }
    }

    private fun scanToJson(project: Path): Path {
        val json = dir.resolve("f.json")
        assertEquals(0, scan("--project=$project", "--out-json=$json").code)
        return json
    }
}
