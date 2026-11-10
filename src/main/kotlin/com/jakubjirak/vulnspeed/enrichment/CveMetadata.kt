/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.jakubjirak.vulnspeed.model.Vulnerability
import java.time.Instant

/**
 * Describes a single affected package range for a CVE.
 *
 * @property ecosystem e.g. `Maven`, `npm`, `PyPI`.
 * @property pkg       canonical package identifier within [ecosystem].
 * @property introduced inclusive lower bound of the vulnerable range (if known).
 * @property fixed     exclusive upper bound at which the issue is fixed.
 */
data class AffectedRange(
    val ecosystem: String,
    val pkg: String,
    val introduced: String? = null,
    val fixed: String? = null,
)

/**
 * Canonical, feed-agnostic CVE metadata produced by the enrichment layer.
 *
 * The structure intentionally covers the union of the most commonly consumed
 * fields exposed by the OSV.dev and NVD feeds, normalised onto a single shape
 * so downstream reporters do not need feed-specific branching.
 */
data class CveMetadata(
    val cveId: String,
    val cvssScore: Double = 0.0,
    val cvssVector: String = "",
    val severity: String = "UNKNOWN",
    val cweIds: List<String> = emptyList(),
    val published: Instant? = null,
    val modified: Instant? = null,
    val summary: String = "",
    val references: List<String> = emptyList(),
    val fixedVersions: List<String> = emptyList(),
    val affectedRanges: List<AffectedRange> = emptyList(),
    val source: String = "",
)

/**
 * Non-breaking wrapper around [Vulnerability] that attaches optional
 * [CveMetadata] produced by [CveEnricher].
 */
data class EnrichedVulnerability(
    val vulnerability: Vulnerability,
    val metadata: CveMetadata? = null,
) {
    /** Convenience: CVE id derived from tags/ruleId when present. */
    val cveId: String? get() = metadata?.cveId ?: extractCveId(vulnerability)
}

/** Best-effort extraction of a CVE id from a finding's ruleId, tags or id. */
internal fun extractCveId(v: Vulnerability): String? {
    val regex = Regex("CVE-\\d{4}-\\d{4,7}", RegexOption.IGNORE_CASE)
    return sequenceOf(v.ruleId, v.id, v.ruleName)
        .plus(v.tags.asSequence())
        .mapNotNull { regex.find(it)?.value?.uppercase() }
        .firstOrNull()
}
