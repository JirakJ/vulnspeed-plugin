/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class CveMetadataCacheTest {

    private fun sample(id: String = "CVE-2099-0001") = CveMetadata(
        cveId = id,
        cvssScore = 7.5,
        cvssVector = "CVSS:3.1/AV:N",
        severity = "HIGH",
        cweIds = listOf("CWE-89"),
        published = Instant.parse("2099-01-01T00:00:00Z"),
        modified = Instant.parse("2099-01-02T00:00:00Z"),
        summary = "x",
        references = listOf("https://example.com"),
        fixedVersions = listOf("Maven:a.b:1.0"),
        source = "OSV",
    )

    @Test
    fun `store and load round-trip`(@TempDir tmp: Path) {
        val cache = CveMetadataCache(tmp)
        cache.store("CVE-2099-0001", sample())
        val loaded = cache.load("CVE-2099-0001", Duration.ofDays(7))
        assertNotNull(loaded)
        assertEquals(7.5, loaded!!.cvssScore)
        assertEquals(listOf("CWE-89"), loaded.cweIds)
        assertEquals(1, cache.size())
        assertTrue(cache.contains("CVE-2099-0001"))
    }

    @Test
    fun `expired entries return null`(@TempDir tmp: Path) {
        val clock = AtomicInteger(0)
        val fakeClock: () -> Instant = { Instant.EPOCH.plusSeconds(clock.get().toLong()) }
        val cache = CveMetadataCache(tmp, fakeClock)
        cache.store("CVE-X", sample("CVE-X"))
        clock.set(10_000_000) // far in the future
        assertNull(cache.load("CVE-X", Duration.ofSeconds(1)))
    }

    @Test
    fun `corrupt file returns null`(@TempDir tmp: Path) {
        val cache = CveMetadataCache(tmp)
        java.nio.file.Files.writeString(cache.pathFor("CVE-BAD"), "{not json")
        assertNull(cache.load("CVE-BAD", Duration.ofDays(7)))
    }

    @Test
    fun `evict removes entry`(@TempDir tmp: Path) {
        val cache = CveMetadataCache(tmp)
        cache.store("CVE-1", sample("CVE-1"))
        assertTrue(cache.contains("CVE-1"))
        cache.evict("CVE-1")
        assertFalse(cache.contains("CVE-1"))
    }

    @Test
    fun `atomic write leaves no tmp file on success`(@TempDir tmp: Path) {
        val cache = CveMetadataCache(tmp)
        cache.store("CVE-A", sample("CVE-A"))
        val tmpLeftover = java.nio.file.Files.list(tmp).use { it.filter { p -> p.toString().endsWith(".tmp") }.count() }
        assertEquals(0L, tmpLeftover)
    }

    @Test
    fun `concurrent access is safe`(@TempDir tmp: Path) {
        val cache = CveMetadataCache(tmp)
        val exec = Executors.newFixedThreadPool(2)
        val latch = CountDownLatch(1)
        val errors = AtomicInteger(0)
        val iterations = 200

        val r: Runnable = Runnable {
            try {
                latch.await()
                for (i in 0 until iterations) {
                    val id = "CVE-2099-${i % 5}"
                    cache.store(id, sample(id))
                    cache.load(id, Duration.ofDays(7))
                }
            } catch (_: Exception) {
                errors.incrementAndGet()
            }
        }
        exec.submit(r)
        exec.submit(r)
        latch.countDown()
        exec.shutdown()
        assertTrue(exec.awaitTermination(30, TimeUnit.SECONDS))
        assertEquals(0, errors.get())
        // One entry per distinct id expected (5 distinct ids).
        assertEquals(5, cache.size())
    }
}
