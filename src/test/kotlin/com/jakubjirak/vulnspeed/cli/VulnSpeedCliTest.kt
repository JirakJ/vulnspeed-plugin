/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.cli

import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/** Sub-command dispatch and the full scan → baseline → enrich pipeline, in-process. */
class VulnSpeedCliTest {

    @TempDir
    lateinit var dir: Path

    private fun cli(vararg args: String) = CliFixtures.capture { out, err -> VulnSpeedCli.run(arrayOf(*args), out, err) }

    @Test
    fun `version, help and unknown commands`() {
        val version = cli("version")
        assertEquals(0, version.code)
        assertTrue(version.out.startsWith("vulnspeed-cli "))

        val help = cli("--help")
        assertEquals(0, help.code)
        assertTrue(help.out.contains("scan") && help.out.contains("baseline") && help.out.contains("enrich"))

        val none = cli()
        assertEquals(1, none.code)
        assertTrue(none.err.contains("Usage:"))

        val unknown = cli("deploy")
        assertEquals(1, unknown.code)
        assertTrue(unknown.err.contains("unknown command: deploy"))
    }

    @Test
    fun `scan then baseline create and compare gates only on new findings`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val baseline = dir.resolve("p/.vulnspeed-baseline.json")
        val findings = dir.resolve("findings.json")

        assertEquals(0, cli("scan", "--project=$project", "--out-json=$findings").code)
        val create = cli("baseline", "--create", "--project=$project", "--findings=$findings", "--baseline=$baseline")
        assertEquals(0, create.code, create.err)
        assertTrue(Files.exists(baseline))

        // Unchanged code: nothing new, the gate passes.
        val same = cli(
            "baseline", "--compare", "--project=$project", "--findings=$findings", "--baseline=$baseline",
            "--fail-on=severity:HIGH"
        )
        assertEquals(0, same.code, same.err)

        // A new SQL injection in another file is a regression and trips the gate.
        CliFixtures.write(project, "src/main/java/New.java", "class New {\n${CliFixtures.SQL_LINE}\n}\n")
        assertEquals(0, cli("scan", "--project=$project", "--out-json=$findings").code)
        val report = dir.resolve("diff.md")
        val regressed = cli(
            "baseline", "--compare", "--project=$project", "--findings=$findings", "--baseline=$baseline",
            "--output=md", "--output-file=$report", "--fail-on=severity:HIGH"
        )
        assertEquals(2, regressed.code)
        assertTrue(Files.readString(report, StandardCharsets.UTF_8).contains("New.java"))
    }

    @Test
    fun `baseline records the CLI version unless overridden`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val findings = dir.resolve("findings.json")
        val baseline = dir.resolve("b.json")
        cli("scan", "--project=$project", "--out-json=$findings")

        cli("baseline", "--create", "--project=$project", "--findings=$findings", "--baseline=$baseline", "--tool-version=1.2.3")

        assertTrue(Files.readString(baseline, StandardCharsets.UTF_8).contains("1.2.3"))
    }

    @Test
    fun `enrich runs offline over scan output`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val findings = dir.resolve("findings.json")
        val enriched = dir.resolve("enriched.json")
        cli("scan", "--project=$project", "--out-json=$findings")

        val run = cli(
            "enrich", "--findings=$findings", "--out=$enriched", "--format=json", "--offline",
            "--cache-dir=${dir.resolve("cache")}", "--fail-on-severity=CRITICAL"
        )

        assertEquals(2, run.code, run.err) // the SQL injection is CRITICAL
        val doc = JsonParser.parseString(Files.readString(enriched, StandardCharsets.UTF_8)).asJsonArray
        assertTrue(doc.size() > 0)
        assertTrue(doc.all { it.asJsonObject.has("vulnerability") })
    }
}
