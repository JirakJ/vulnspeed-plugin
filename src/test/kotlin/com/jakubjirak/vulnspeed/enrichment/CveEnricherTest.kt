/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class CveEnricherTest {

    private lateinit var osvServer: LocalHttpServer
    private lateinit var nvdServer: LocalHttpServer
    private lateinit var policy: EnrichmentPolicy

    @BeforeEach
    fun setup() {
        osvServer = LocalHttpServer().also { it.start() }
        nvdServer = LocalHttpServer().also { it.start() }
        policy = EnrichmentPolicy(maxRetries = 1)
    }

    @AfterEach
    fun teardown() {
        osvServer.stop()
        nvdServer.stop()
    }

    private fun buildEnricher(
        cacheDir: Path,
        policy: EnrichmentPolicy = this.policy,
    ): CveEnricher = CveEnricher(
        CveMetadataCache(cacheDir),
        OsvClient(osvServer.baseUrl(), policy, HttpTransport(policy, sleeper = {})),
        NvdClient(nvdServer.baseUrl(), policy, HttpTransport(policy, sleeper = {})),
        policy,
    )

    private fun vuln(
        ruleId: String = "CVE-2021-44228",
        tags: List<String> = emptyList(),
    ) = Vulnerability(
        id = "v1",
        ruleId = ruleId,
        ruleName = ruleId,
        type = VulnerabilityType.VULNERABLE_COMPONENTS,
        severity = Severity.HIGH,
        cwe = 502,
        filePath = "pom.xml",
        line = 1,
        column = 0,
        message = "Vulnerable log4j",
        codeSnippet = "",
        tags = tags,
    )

    @Test
    fun `osv hit short-circuits nvd`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        val enricher = buildEnricher(tmp)
        val enriched = enricher.enrich(vuln())
        assertNotNull(enriched.metadata)
        assertEquals("OSV", enriched.metadata!!.source)
        assertEquals(0, nvdServer.requestCount())
    }

    @Test
    fun `falls through to nvd when osv 404s`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(404, "{}"))
        nvdServer.enqueue(LocalHttpServer.Response(200, FeedSamples.NVD_LOG4SHELL))
        val enricher = buildEnricher(tmp)
        val enriched = enricher.enrich(vuln())
        assertNotNull(enriched.metadata)
        assertEquals("NVD", enriched.metadata!!.source)
    }

    @Test
    fun `returns null metadata when both feeds fail`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(404, "{}"))
        nvdServer.enqueue(LocalHttpServer.Response(404, "{}"))
        val enricher = buildEnricher(tmp)
        assertNull(enricher.enrich(vuln()).metadata)
    }

    @Test
    fun `cache hit avoids network`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        val enricher = buildEnricher(tmp)
        enricher.enrich(vuln())
        val before = osvServer.requestCount()
        enricher.enrich(vuln())
        assertEquals(before, osvServer.requestCount())
    }

    @Test
    fun `offline mode never hits the network`(@TempDir tmp: Path) {
        val offline = policy.copy(offline = true)
        val enricher = buildEnricher(tmp, offline)
        val enriched = enricher.enrich(vuln())
        assertNull(enriched.metadata)
        assertEquals(0, osvServer.requestCount())
        assertEquals(0, nvdServer.requestCount())
    }

    @Test
    fun `offline mode still uses cache`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        buildEnricher(tmp).enrich(vuln())
        val offlineEnricher = buildEnricher(tmp, policy.copy(offline = true))
        val enriched = offlineEnricher.enrich(vuln())
        assertNotNull(enriched.metadata)
    }

    @Test
    fun `prefer NVD switches order`(@TempDir tmp: Path) {
        val p = policy.copy(preferOsv = false)
        nvdServer.enqueue(LocalHttpServer.Response(200, FeedSamples.NVD_LOG4SHELL))
        val enricher = buildEnricher(tmp, p)
        val enriched = enricher.enrich(vuln())
        assertEquals("NVD", enriched.metadata?.source)
        assertEquals(0, osvServer.requestCount())
    }

    @Test
    fun `no cve id skips enrichment`(@TempDir tmp: Path) {
        val enricher = buildEnricher(tmp)
        val enriched = enricher.enrich(vuln(ruleId = "SOME-INTERNAL-RULE"))
        assertNull(enriched.metadata)
        assertEquals(0, osvServer.requestCount())
        assertEquals(0, nvdServer.requestCount())
    }

    @Test
    fun `cve id in tags is discovered`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        val enricher = buildEnricher(tmp)
        val enriched = enricher.enrich(vuln(ruleId = "INTERNAL", tags = listOf("cve-2021-44228")))
        assertNotNull(enriched.metadata)
    }

    @Test
    fun `batch enrichment preserves order`(@TempDir tmp: Path) {
        osvServer.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        osvServer.enqueue(LocalHttpServer.Response(404, "{}"))
        nvdServer.enqueue(LocalHttpServer.Response(404, "{}"))
        val enricher = buildEnricher(tmp)
        val list = enricher.enrich(listOf(vuln(), vuln(ruleId = "CVE-9999-9999")))
        assertEquals(2, list.size)
        assertNotNull(list[0].metadata)
        assertNull(list[1].metadata)
    }
}
