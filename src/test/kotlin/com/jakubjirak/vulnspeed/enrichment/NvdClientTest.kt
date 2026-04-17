/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class NvdClientTest {

    private lateinit var server: LocalHttpServer
    private lateinit var policy: EnrichmentPolicy

    @BeforeEach
    fun setup() {
        server = LocalHttpServer().also { it.start() }
        policy = EnrichmentPolicy(maxRetries = 1)
    }

    @AfterEach
    fun teardown() = server.stop()

    @Test
    fun `parses real NVD payload`() {
        server.enqueue(LocalHttpServer.Response(200, FeedSamples.NVD_LOG4SHELL))
        val client = NvdClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        val md = client.fetch("CVE-2021-44228")

        assertEquals("CVE-2021-44228", md.cveId)
        assertEquals(10.0, md.cvssScore)
        assertEquals("CRITICAL", md.severity)
        assertTrue(md.cweIds.contains("CWE-502"))
        assertTrue(md.summary.startsWith("Apache Log4j2"))
        assertNotNull(md.published)
        assertEquals("NVD", md.source)
    }

    @Test
    fun `apiKey header is forwarded when provided`() {
        val keyedPolicy = policy.copy(nvdApiKey = "secret-key-xyz")
        server.enqueue(LocalHttpServer.Response(200, FeedSamples.NVD_MINIMAL))
        val client = NvdClient(server.baseUrl(), keyedPolicy, HttpTransport(keyedPolicy, sleeper = {}))
        client.fetch("CVE-2099-0002")

        val headers = server.recorded().first().headers
        val apiKey = headers["Apikey"] ?: headers["apiKey"] ?: headers["Apikey"]
        assertNotNull(apiKey)
        assertEquals("secret-key-xyz", apiKey!!.first())
    }

    @Test
    fun `404 raises CveNotFoundException`() {
        server.enqueue(LocalHttpServer.Response(404, "{}"))
        val client = NvdClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        assertThrows(CveNotFoundException::class.java) { client.fetch("CVE-0000-0000") }
    }

    @Test
    fun `missing vulnerabilities array raises feed exception`() {
        server.enqueue(LocalHttpServer.Response(200, """{"resultsPerPage":0}"""))
        val client = NvdClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        assertThrows(EnrichmentFeedException::class.java) { client.fetch("CVE-2099-9999") }
    }
}
