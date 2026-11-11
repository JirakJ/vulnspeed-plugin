/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

class FeedParsersTest {

    @Test
    fun `osv rejects malformed json and non-object roots`() {
        assertThrows(EnrichmentFeedException::class.java) { FeedParsers.parseOsv("{not json") }
        assertThrows(EnrichmentFeedException::class.java) { FeedParsers.parseOsv("[1,2]") }
    }

    @Test
    fun `osv minimal document yields empty defaults`() {
        val meta = FeedParsers.parseOsv("""{"id":"GHSA-xxxx"}""")
        assertEquals("GHSA-XXXX", meta.cveId)
        assertEquals(0.0, meta.cvssScore)
        assertEquals("UNKNOWN", meta.severity)
        assertTrue(meta.cweIds.isEmpty())
        assertTrue(meta.references.isEmpty())
        assertTrue(meta.affectedRanges.isEmpty())
        assertNull(meta.published)
        assertEquals("OSV", meta.source)
    }

    @Test
    fun `osv picks cve alias, falls back to details and normalizes cwe ids`() {
        val json = """
            {
              "id": "GHSA-abcd",
              "aliases": ["PYSEC-1", "cve-2024-0001"],
              "details": "Long details",
              "published": "2024-01-02T03:04:05Z",
              "database_specific": {"cwe_ids": ["79", "CWE-89", "cwe-79"]},
              "references": [{"url": "https://a"}, {"url": "https://a"}, {"type": "WEB"}]
            }
        """.trimIndent()
        val meta = FeedParsers.parseOsv(json)
        assertEquals("CVE-2024-0001", meta.cveId)
        assertEquals("Long details", meta.summary)
        assertEquals(Instant.parse("2024-01-02T03:04:05Z"), meta.published)
        assertEquals(listOf("CWE-79", "CWE-89"), meta.cweIds)
        assertEquals(listOf("https://a"), meta.references)
    }

    @Test
    fun `osv numeric cvss score maps to severity buckets`() {
        fun sev(score: String) = FeedParsers.parseOsv(
            """{"id":"CVE-1","severity":[{"type":"CVSS_V3","score":"$score"}]}"""
        ).severity
        assertEquals("LOW", sev("3.9"))
        assertEquals("MEDIUM", sev("4.0"))
        assertEquals("HIGH", sev("7.0"))
        assertEquals("CRITICAL", sev("9.0"))
    }

    @Test
    fun `osv keeps vector string when score is a cvss vector`() {
        val meta = FeedParsers.parseOsv(
            """{"id":"CVE-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}"""
        )
        assertEquals("CVSS:3.1/AV:N", meta.cvssVector)
        assertEquals(0.0, meta.cvssScore)
    }

    @Test
    fun `osv collects affected ranges and fixed versions, skipping nameless packages`() {
        val json = """
            {
              "id": "CVE-2",
              "affected": [
                {"package": {"name": "lib", "ecosystem": "Maven"},
                 "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]},
                {"package": {"name": ""}, "ranges": [{"events": [{"fixed": "9"}]}]},
                {"package": {"name": "other"}, "ranges": [{"events": []}]}
              ]
            }
        """.trimIndent()
        val meta = FeedParsers.parseOsv(json)
        assertEquals(listOf("Maven:lib@1.2.3"), meta.fixedVersions)
        assertEquals(1, meta.affectedRanges.size)
        val range = meta.affectedRanges.single()
        assertEquals("0", range.introduced)
        assertEquals("1.2.3", range.fixed)
    }

    @Test
    fun `nvd structural errors are reported`() {
        assertThrows(EnrichmentFeedException::class.java) { FeedParsers.parseNvd("\"x\"") }
        assertThrows(EnrichmentFeedException::class.java) { FeedParsers.parseNvd("{}") }
        assertThrows(EnrichmentFeedException::class.java) { FeedParsers.parseNvd("""{"vulnerabilities":[]}""") }
        assertThrows(EnrichmentFeedException::class.java) { FeedParsers.parseNvd("""{"vulnerabilities":[{}]}""") }
    }

    @Test
    fun `nvd prefers v31 metrics, english description and zone-less dates`() {
        val json = """
            {"vulnerabilities":[{"cve":{
              "id":"CVE-2021-44228",
              "published":"2021-12-10T10:15:09.143",
              "descriptions":[{"lang":"es","value":"hola"},{"lang":"en","value":"Log4Shell"}],
              "metrics":{
                "cvssMetricV2":[{"cvssData":{"baseScore":9.3,"vectorString":"v2"}}],
                "cvssMetricV31":[{"cvssData":{"baseScore":10.0,"vectorString":"v31","baseSeverity":"critical"}}]
              },
              "weaknesses":[{"description":[{"value":"CWE-502"},{"value":"NVD-CWE-Other"},{"value":"CWE-502"}]}],
              "references":[{"url":"https://r"}]
            }}]}
        """.trimIndent()
        val meta = FeedParsers.parseNvd(json)
        assertEquals("CVE-2021-44228", meta.cveId)
        assertEquals("Log4Shell", meta.summary)
        assertEquals(10.0, meta.cvssScore)
        assertEquals("v31", meta.cvssVector)
        assertEquals("CRITICAL", meta.severity)
        assertEquals(listOf("CWE-502"), meta.cweIds)
        assertEquals(Instant.parse("2021-12-10T10:15:09.143Z"), meta.published)
        assertEquals("NVD", meta.source)
    }

    @Test
    fun `nvd without metrics is unknown and derives severity from score when missing`() {
        val noMetrics = FeedParsers.parseNvd("""{"vulnerabilities":[{"cve":{}}]}""")
        assertEquals("UNKNOWN", noMetrics.cveId)
        assertEquals("UNKNOWN", noMetrics.severity)

        val derived = FeedParsers.parseNvd(
            """{"vulnerabilities":[{"cve":{"id":"CVE-3","metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":5.0}}]}}}]}"""
        )
        assertEquals("MEDIUM", derived.severity)
    }

    @Test
    fun `nvd tolerates non-numeric scores and unparseable dates`() {
        val meta = FeedParsers.parseNvd(
            """{"vulnerabilities":[{"cve":{"id":"CVE-4","published":"yesterday",""" +
                """"metrics":{"cvssMetricV30":[{"cvssData":{"baseScore":"n/a"}}]}}}]}"""
        )
        assertEquals(0.0, meta.cvssScore)
        assertNull(meta.published)
    }
}
