/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class CveEnrichmentCliTest {

    private lateinit var osvServer: LocalHttpServer
    private val gson: Gson = GsonBuilder().setPrettyPrinting().create()

    @BeforeEach
    fun setup() {
        osvServer = LocalHttpServer().also { it.start() }
    }

    @AfterEach
    fun teardown() {
        osvServer.stop()
    }

    private fun writeFindings(path: Path, list: List<Vulnerability>) {
        Files.writeString(path, gson.toJson(list), StandardCharsets.UTF_8)
    }

    private fun vuln(
        ruleId: String = "CVE-2021-44228",
        severity: Severity = Severity.HIGH,
    ) = Vulnerability(
        id = "v1",
        ruleId = ruleId,
        ruleName = ruleId,
        type = VulnerabilityType.VULNERABLE_COMPONENTS,
        severity = severity,
        cwe = 502,
        filePath = "pom.xml",
        line = 1,
        column = 0,
        message = "bad",
        codeSnippet = "",
    )

    private fun factory(policy: EnrichmentPolicy, cacheDir: Path): CveEnricher {
        val p = policy.copy(maxRetries = 0, connectTimeoutMs = 500, readTimeoutMs = 1500)
        return CveEnricher(
            CveMetadataCache(cacheDir),
            OsvClient(osvServer.baseUrl(), p, HttpTransport(p, sleeper = {})),
            NvdClient(osvServer.baseUrl(), p, HttpTransport(p, sleeper = {})), // share server
            p,
        )
    }

    @Test
    fun `happy path writes json output`(@TempDir tmp: Path) {
        val findings = tmp.resolve("findings.json")
        writeFindings(findings, listOf(vuln()))
        val out = tmp.resolve("out.json")
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))

        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val exit = CveEnrichmentCli.run(
            arrayOf(
                "--findings=$findings",
                "--out=$out",
                "--format=json",
                "--cache-dir=${tmp.resolve("cache")}",
            ),
            PrintStream(stdout), PrintStream(stderr),
            ::factory,
        )
        assertEquals(0, exit)
        assertTrue(Files.exists(out))
        val content = Files.readString(out)
        assertTrue(content.contains("CVE-2021-44228"))
    }

    @Test
    fun `markdown format emits report`(@TempDir tmp: Path) {
        val findings = tmp.resolve("f.json")
        writeFindings(findings, listOf(vuln()))
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val out = tmp.resolve("r.md")
        val exit = CveEnrichmentCli.run(
            arrayOf(
                "--findings=$findings",
                "--out=$out",
                "--format=md",
                "--cache-dir=${tmp.resolve("c")}",
            ),
            PrintStream(stdout), PrintStream(stderr),
            ::factory,
        )
        assertEquals(0, exit)
        assertTrue(Files.readString(out).contains("# VulnSpeed"))
    }

    @Test
    fun `missing findings flag returns 1`() {
        val stderr = ByteArrayOutputStream()
        val exit = CveEnrichmentCli.run(
            arrayOf("--format=json"),
            PrintStream(ByteArrayOutputStream()), PrintStream(stderr),
            ::factory,
        )
        assertEquals(1, exit)
        assertTrue(stderr.toString().contains("--findings"))
    }

    @Test
    fun `unknown flag returns 1`() {
        val stderr = ByteArrayOutputStream()
        val exit = CveEnrichmentCli.run(
            arrayOf("--what=now"),
            PrintStream(ByteArrayOutputStream()), PrintStream(stderr),
            ::factory,
        )
        assertEquals(1, exit)
    }

    @Test
    fun `malformed findings returns 1`(@TempDir tmp: Path) {
        val findings = tmp.resolve("bad.json")
        Files.writeString(findings, "{not valid")
        val stderr = ByteArrayOutputStream()
        val exit = CveEnrichmentCli.run(
            arrayOf("--findings=$findings", "--cache-dir=${tmp.resolve("c")}", "--offline"),
            PrintStream(ByteArrayOutputStream()), PrintStream(stderr),
            ::factory,
        )
        assertEquals(1, exit)
    }

    @Test
    fun `fail-on-severity triggers exit 2`(@TempDir tmp: Path) {
        val findings = tmp.resolve("f.json")
        writeFindings(findings, listOf(vuln(severity = Severity.CRITICAL)))
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        val exit = CveEnrichmentCli.run(
            arrayOf(
                "--findings=$findings",
                "--cache-dir=${tmp.resolve("c")}",
                "--fail-on-severity=HIGH",
                "--format=json",
            ),
            PrintStream(ByteArrayOutputStream()), PrintStream(ByteArrayOutputStream()),
            ::factory,
        )
        assertEquals(2, exit)
    }

    @Test
    fun `below threshold passes`(@TempDir tmp: Path) {
        val findings = tmp.resolve("f.json")
        writeFindings(findings, listOf(vuln(severity = Severity.LOW)))
        val exit = CveEnrichmentCli.run(
            arrayOf(
                "--findings=$findings",
                "--cache-dir=${tmp.resolve("c")}",
                "--fail-on-severity=HIGH",
                "--offline",
                "--format=json",
            ),
            PrintStream(ByteArrayOutputStream()), PrintStream(ByteArrayOutputStream()),
            ::factory,
        )
        assertEquals(0, exit)
    }

    @Test
    fun `offline mode short-circuits`(@TempDir tmp: Path) {
        val findings = tmp.resolve("f.json")
        writeFindings(findings, listOf(vuln()))
        val exit = CveEnrichmentCli.run(
            arrayOf(
                "--findings=$findings",
                "--cache-dir=${tmp.resolve("c")}",
                "--offline",
                "--format=json",
            ),
            PrintStream(ByteArrayOutputStream()), PrintStream(ByteArrayOutputStream()),
            ::factory,
        )
        assertEquals(0, exit)
        assertEquals(0, osvServer.requestCount())
    }

    @Test
    fun `max-age-days negative is rejected`(@TempDir tmp: Path) {
        val findings = tmp.resolve("f.json")
        writeFindings(findings, emptyList())
        val stderr = ByteArrayOutputStream()
        val exit = CveEnrichmentCli.run(
            arrayOf("--findings=$findings", "--max-age-days=-1"),
            PrintStream(ByteArrayOutputStream()), PrintStream(stderr),
            ::factory,
        )
        assertEquals(1, exit)
    }

    @Test
    fun `shouldFail helper is severity-aware`() {
        val vulnMid = EnrichedVulnerability(vuln(severity = Severity.MEDIUM), null)
        val vulnHigh = EnrichedVulnerability(vuln(severity = Severity.HIGH), null)
        assertTrue(CveEnrichmentCli.shouldFail(listOf(vulnHigh), Severity.HIGH))
        assertEquals(false, CveEnrichmentCli.shouldFail(listOf(vulnMid), Severity.HIGH))
        assertEquals(false, CveEnrichmentCli.shouldFail(listOf(vulnHigh), null))
    }

    @Test
    fun `renderJson emits valid structure`() {
        val enriched = listOf(
            EnrichedVulnerability(
                vuln(),
                CveMetadata(cveId = "CVE-2021-44228", cvssScore = 10.0, source = "OSV"),
            ),
        )
        val json = CveEnrichmentCli.renderJson(enriched)
        assertTrue(json.contains("CVE-2021-44228"))
        assertNotEquals("", json.trim())
    }
}
