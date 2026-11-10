/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonSyntaxException
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Duration
import java.time.Instant
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Disk-backed CVE metadata cache with TTL and atomic writes.
 *
 * Each entry lives in its own file named `{cveId}.json` so lookups are O(1)
 * and writes never touch unrelated entries. The envelope records when the
 * entry was stored, allowing TTL expiry without relying on filesystem mtimes
 * (which are unreliable across platforms and backups).
 *
 * All operations are thread-safe: a lock is taken for the duration of read
 * and write operations on a single key, and writes use the canonical
 * `.tmp` + `ATOMIC_MOVE` pattern.
 */
class CveMetadataCache(
    val cacheDir: Path,
    private val clock: () -> Instant = Instant::now,
) {

    private val gson: Gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()
    private val lock = ReentrantLock()

    init {
        Files.createDirectories(cacheDir)
    }

    private data class Envelope(
        val storedAt: String,
        val metadata: CveMetadata,
    )

    /** Path that an entry for [cveId] would occupy, whether or not it exists. */
    fun pathFor(cveId: String): Path = cacheDir.resolve(sanitize(cveId) + ".json")

    /** Whether [cveId] has any cached entry (fresh or stale). */
    fun contains(cveId: String): Boolean = Files.isRegularFile(pathFor(cveId))

    /**
     * Load a cached entry if present and still within [maxAge].
     *
     * Returns `null` when the entry is missing, stale, or corrupted.
     */
    fun load(cveId: String, maxAge: Duration): CveMetadata? = lock.withLock {
        val path = pathFor(cveId)
        if (!Files.isRegularFile(path)) return null
        try {
            val text = Files.readString(path, StandardCharsets.UTF_8)
            val env = gson.fromJson(text, Envelope::class.java) ?: return null
            val storedAt = Instant.parse(env.storedAt)
            if (Duration.between(storedAt, clock()) > maxAge) return null
            env.metadata
        } catch (_: JsonSyntaxException) {
            null
        } catch (_: IOException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Persist [metadata] for [cveId]. */
    @Throws(IOException::class)
    fun store(cveId: String, metadata: CveMetadata) {
        lock.withLock {
            val target = pathFor(cveId)
            val tmp = target.resolveSibling(target.fileName.toString() + ".tmp")
            val env = Envelope(storedAt = clock().toString(), metadata = metadata)
            val bytes = gson.toJson(env).toByteArray(StandardCharsets.UTF_8)
            Files.write(tmp, bytes)
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    /** Delete a cached entry if present. No-op otherwise. */
    fun evict(cveId: String) {
        lock.withLock {
            Files.deleteIfExists(pathFor(cveId))
        }
    }

    /** Number of cached `.json` entries currently on disk. */
    fun size(): Int = lock.withLock {
        if (!Files.isDirectory(cacheDir)) return 0
        Files.list(cacheDir).use { stream ->
            stream.filter { it.fileName.toString().endsWith(".json") }.count().toInt()
        }
    }

    private fun sanitize(cveId: String): String =
        cveId.trim().uppercase().replace(Regex("[^A-Z0-9._-]"), "_")
}
