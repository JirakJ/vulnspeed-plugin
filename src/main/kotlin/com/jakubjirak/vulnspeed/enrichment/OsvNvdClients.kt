/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Raised when a remote feed reports that the requested CVE does not exist. */
class CveNotFoundException(message: String) : RuntimeException(message)

/** Raised when all retries are exhausted or the response is unparseable. */
class EnrichmentTransportException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * Thin HTTP transport wrapping [HttpClient] that implements:
 *   * 3-attempt retry with exponential backoff (base 250 ms, ×2 each try)
 *   * 429 Retry-After handling (honoured up to 30 s)
 *   * pluggable clock + sleeper for deterministic tests
 *
 * The class is deliberately tiny so that [OsvClient] and [NvdClient] can share
 * the exact same transport without code duplication.
 */
class HttpTransport(
    private val policy: EnrichmentPolicy,
    private val sleeper: (Long) -> Unit = Thread::sleep,
    clientFactory: () -> HttpClient = {
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(policy.connectTimeoutMs))
            .build()
    },
) {
    private val client: HttpClient = clientFactory()

    /** Issue a request, retrying transient failures. Returns the body on 200. */
    @Throws(IOException::class)
    fun send(request: HttpRequest): String {
        var attempt = 0
        var delay = 250L
        var lastError: Throwable? = null
        while (attempt <= policy.maxRetries) {
            try {
                val response = client.send(request, HttpResponse.BodyHandlers.ofString())
                when (val status = response.statusCode()) {
                    in 200..299 -> return response.body()
                    404 -> throw CveNotFoundException("404 for ${request.uri()}")
                    429 -> {
                        val retryAfter = parseRetryAfter(response.headers().firstValue("Retry-After").orElse(null))
                        sleeper(retryAfter ?: delay)
                    }
                    in 500..599 -> sleeper(delay)
                    else -> throw EnrichmentTransportException("Unexpected status $status from ${request.uri()}")
                }
            } catch (e: CveNotFoundException) {
                throw e
            } catch (e: EnrichmentTransportException) {
                throw e
            } catch (e: IOException) {
                lastError = e
                sleeper(delay)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw EnrichmentTransportException("Interrupted", e)
            }
            delay *= 2
            attempt += 1
        }
        throw EnrichmentTransportException(
            "Exhausted ${policy.maxRetries} retries for ${request.uri()}", lastError
        )
    }

    private fun parseRetryAfter(raw: String?): Long? {
        if (raw.isNullOrBlank()) return null
        val seconds = raw.trim().toLongOrNull() ?: return null
        return (seconds * 1000L).coerceAtMost(30_000L)
    }
}

/**
 * Tiny OSV.dev HTTP client. Only the lookup and query endpoints are exposed,
 * which is all the enrichment layer needs.
 */
class OsvClient(
    private val baseUrl: String = "https://api.osv.dev",
    private val policy: EnrichmentPolicy = EnrichmentPolicy(),
    private val transport: HttpTransport = HttpTransport(policy),
) {

    /**
     * Fetch a single vulnerability by identifier (OSV or CVE id).
     *
     * @throws CveNotFoundException if the feed returns 404.
     * @throws EnrichmentFeedException on malformed response JSON.
     * @throws IOException on transport failure.
     */
    @Throws(IOException::class)
    fun fetch(cveId: String): CveMetadata {
        val uri = URI.create("$baseUrl/v1/vulns/${cveId.trim()}")
        val request = HttpRequest.newBuilder()
            .uri(uri)
            .timeout(Duration.ofMillis(policy.readTimeoutMs))
            .header("User-Agent", policy.userAgent)
            .header("Accept", "application/json")
            .GET()
            .build()
        val body = transport.send(request)
        return FeedParsers.parseOsv(body)
    }
}

/**
 * Tiny NVD 2.0 HTTP client. Honours the `NVD_API_KEY` header when a key is
 * provided via [EnrichmentPolicy.nvdApiKey].
 */
class NvdClient(
    private val baseUrl: String = "https://services.nvd.nist.gov",
    private val policy: EnrichmentPolicy = EnrichmentPolicy(),
    private val transport: HttpTransport = HttpTransport(policy),
) {

    /** Fetch a single CVE. */
    @Throws(IOException::class)
    fun fetch(cveId: String): CveMetadata {
        val uri = URI.create("$baseUrl/rest/json/cves/2.0?cveId=${cveId.trim()}")
        val builder = HttpRequest.newBuilder()
            .uri(uri)
            .timeout(Duration.ofMillis(policy.readTimeoutMs))
            .header("User-Agent", policy.userAgent)
            .header("Accept", "application/json")
            .GET()
        policy.nvdApiKey?.takeIf { it.isNotBlank() }?.let { builder.header("apiKey", it) }
        val body = transport.send(builder.build())
        return FeedParsers.parseNvd(body)
    }
}
