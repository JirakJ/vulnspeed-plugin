/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.jakubjirak.vulnspeed.model.Vulnerability
import java.io.IOException
import java.time.Duration

/**
 * High-level orchestrator that turns a [Vulnerability] into an
 * [EnrichedVulnerability] by consulting, in order:
 *
 *   1. the local [CveMetadataCache] (respecting TTL);
 *   2. the preferred remote feed (OSV or NVD per policy);
 *   3. the alternate remote feed as fallback.
 *
 * When [EnrichmentPolicy.offline] is `true`, steps (2) and (3) are skipped.
 * Cache hits, network misses, and feed errors are all non-fatal: the original
 * finding is returned with `metadata = null` rather than propagating the
 * exception so a single 404 cannot fail an entire project scan.
 */
class CveEnricher(
    private val cache: CveMetadataCache,
    private val osv: OsvClient,
    private val nvd: NvdClient,
    private val policy: EnrichmentPolicy = EnrichmentPolicy(),
) {

    /** Enrich a single [vuln]. Never throws on missing/failed feeds. */
    fun enrich(vuln: Vulnerability): EnrichedVulnerability {
        val cveId = extractCveId(vuln) ?: return EnrichedVulnerability(vuln, null)
        return EnrichedVulnerability(vuln, fetchMetadata(cveId))
    }

    /** Batch enrichment preserving input order. */
    fun enrich(vulns: List<Vulnerability>): List<EnrichedVulnerability> = vulns.map(::enrich)

    /**
     * Fetch metadata for a bare [cveId]. Public to allow ad-hoc lookups
     * (e.g. from the action or CLI) without constructing a [Vulnerability].
     */
    fun fetchMetadata(cveId: String): CveMetadata? {
        val maxAge = Duration.ofDays(policy.maxAgeDays.toLong())
        cache.load(cveId, maxAge)?.let { return it }
        if (policy.offline) return null

        val order: List<() -> CveMetadata?> = if (policy.preferOsv) {
            listOf({ tryFetch { osv.fetch(cveId) } }, { tryFetch { nvd.fetch(cveId) } })
        } else {
            listOf({ tryFetch { nvd.fetch(cveId) } }, { tryFetch { osv.fetch(cveId) } })
        }
        for (step in order) {
            val md = step()
            if (md != null) {
                runCatching { cache.store(cveId, md) }
                return md
            }
        }
        return null
    }

    private inline fun tryFetch(block: () -> CveMetadata): CveMetadata? = try {
        block()
    } catch (_: CveNotFoundException) {
        null
    } catch (_: EnrichmentFeedException) {
        null
    } catch (_: IOException) {
        null
    }
}
