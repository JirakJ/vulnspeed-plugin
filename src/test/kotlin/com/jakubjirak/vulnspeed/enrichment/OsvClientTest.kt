/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OsvClientTest {

    private lateinit var server: LocalHttpServer
    private lateinit var policy: EnrichmentPolicy

    @BeforeEach
    fun setup() {
        server = LocalHttpServer().also { it.start() }
        policy = EnrichmentPolicy(maxRetries = 2, connectTimeoutMs = 1500, readTimeoutMs = 1500)
    }

    @AfterEach
    fun teardown() {
        server.stop()
    }

    @Test
    fun `parses real OSV payload`() {
        server.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_LOG4SHELL))
        val client = OsvClient(
            baseUrl = server.baseUrl(),
            policy = policy,
            transport = HttpTransport(policy, sleeper = {}),
        )
        val md = client.fetch("CVE-2021-44228")

        assertEquals("CVE-2021-44228", md.cveId)
        assertEquals(9.8, md.cvssScore)
        assertEquals("CRITICAL", md.severity)
        assertTrue(md.cweIds.contains("CWE-502"))
        assertTrue(md.cweIds.contains("CWE-917"))
        assertNotNull(md.published)
        assertEquals(1, md.affectedRanges.size)
        val range = md.affectedRanges.first()
        assertEquals("Maven", range.ecosystem)
        assertEquals("org.apache.logging.log4j:log4j-core", range.pkg)
        assertEquals("2.0", range.introduced)
        assertEquals("2.15.0", range.fixed)
        assertTrue(md.fixedVersions.any { it.contains("2.15.0") })
        assertEquals("OSV", md.source)

        // User-Agent must be forwarded.
        val ua = server.recorded().first().headers["User-agent"] ?: server.recorded().first().headers["User-Agent"]
        assertNotNull(ua)
    }

    @Test
    fun `404 raises CveNotFoundException`() {
        server.enqueue(LocalHttpServer.Response(404, """{"code":5}"""))
        val client = OsvClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        assertThrows(CveNotFoundException::class.java) { client.fetch("CVE-0000-0000") }
    }

    @Test
    fun `429 is retried then succeeds`() {
        server.enqueue(LocalHttpServer.Response(429, "slow down", mapOf("Retry-After" to "0")))
        server.enqueue(LocalHttpServer.Response(200, FeedSamples.OSV_MINIMAL))
        val client = OsvClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        val md = client.fetch("CVE-2099-0001")
        assertEquals("CVE-2099-0001", md.cveId)
        assertEquals(2, server.requestCount())
    }

    @Test
    fun `5xx retries are exhausted`() {
        repeat(5) { server.enqueue(LocalHttpServer.Response(503, "oops")) }
        val client = OsvClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        assertThrows(EnrichmentTransportException::class.java) { client.fetch("CVE-2099-0001") }
        assertEquals(policy.maxRetries + 1, server.requestCount())
    }

    @Test
    fun `malformed JSON raises feed exception`() {
        server.enqueue(LocalHttpServer.Response(200, "{ not really json"))
        val client = OsvClient(server.baseUrl(), policy, HttpTransport(policy, sleeper = {}))
        assertThrows(EnrichmentFeedException::class.java) { client.fetch("CVE-2099-0001") }
    }

    @Test
    fun `extractCveId helper parses tags and rule ids`() {
        val parser = FeedParsers.parseOsv(FeedSamples.OSV_MINIMAL)
        assertEquals("CVE-2099-0001", parser.cveId)
        assertFalse(parser.cweIds.isEmpty())
    }
}
