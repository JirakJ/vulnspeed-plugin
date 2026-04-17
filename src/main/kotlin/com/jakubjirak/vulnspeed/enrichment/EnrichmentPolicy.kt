/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

/**
 * Tunable knobs controlling the CVE enrichment pipeline.
 *
 * @property offline            if `true`, the enricher only consults the local cache and never hits the network.
 * @property maxAgeDays         cache entries older than this are treated as stale.
 * @property preferOsv          if `true`, OSV is consulted before NVD; otherwise NVD is queried first.
 * @property rateLimitPerMin    maximum outbound requests per minute per remote feed.
 * @property userAgent          HTTP User-Agent string sent with every remote request.
 * @property connectTimeoutMs   connect timeout for outbound requests, in milliseconds.
 * @property readTimeoutMs      read timeout for outbound requests, in milliseconds.
 * @property maxRetries         number of retries on transient (5xx/429/timeout) failures.
 * @property nvdApiKey          optional NVD API key; `null` means anonymous.
 */
data class EnrichmentPolicy(
    val offline: Boolean = false,
    val maxAgeDays: Int = 7,
    val preferOsv: Boolean = true,
    val rateLimitPerMin: Int = 30,
    val userAgent: String = "VulnSpeed/unknown (+https://github.com/JirakJ/vulnspeed-plugin)",
    val connectTimeoutMs: Long = 5_000L,
    val readTimeoutMs: Long = 10_000L,
    val maxRetries: Int = 3,
    val nvdApiKey: String? = null,
) {
    init {
        require(maxAgeDays >= 0) { "maxAgeDays must be non-negative" }
        require(rateLimitPerMin >= 0) { "rateLimitPerMin must be non-negative" }
        require(maxRetries >= 0) { "maxRetries must be non-negative" }
    }
}
