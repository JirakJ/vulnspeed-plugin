/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.google.gson.GsonBuilder
import com.google.gson.JsonSyntaxException
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

/** Thrown when a baseline file cannot be read or is malformed / incompatible. */
class VulnBaselineIoException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * Pure-Kotlin persistence for [VulnBaseline].
 *
 * The on-disk format is pretty-printed JSON. Writes are atomic: the baseline is
 * first written to a sibling `*.tmp` file and then moved into place, so a
 * crash mid-write can never leave a corrupted baseline behind.
 */
object VulnBaselineStore {

    /** Default file name written under the project root by [saveDefault]. */
    const val DEFAULT_FILE_NAME: String = ".vulnspeed-baseline.json"

    private val gson = GsonBuilder()
        .setPrettyPrinting()
        .disableHtmlEscaping()
        .serializeNulls()
        .create()

    /**
     * Serialize [baseline] to [path] atomically.
     *
     * Parent directories are created as needed. After a successful return
     * there are no `.tmp` artefacts in the target directory.
     */
    @Throws(IOException::class)
    fun save(baseline: VulnBaseline, path: Path) {
        val json = gson.toJson(baseline)
        val abs = path.toAbsolutePath()
        val parent = abs.parent ?: path.fileSystem.getPath(".").toAbsolutePath()
        Files.createDirectories(parent)
        val tmp = Files.createTempFile(parent, ".vulnspeed-baseline", ".tmp")
        try {
            Files.write(tmp, json.toByteArray(StandardCharsets.UTF_8))
            try {
                Files.move(tmp, abs, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, abs, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    /**
     * Load a baseline from [path].
     *
     * @return the parsed [VulnBaseline], or `null` if no file exists at [path].
     * @throws VulnBaselineIoException when the file is malformed, empty, or
     *         advertises an unknown [VulnBaseline.schemaVersion].
     */
    @Throws(VulnBaselineIoException::class)
    fun load(path: Path): VulnBaseline? {
        if (!Files.exists(path)) return null
        val text = try {
            Files.readString(path, StandardCharsets.UTF_8)
        } catch (e: IOException) {
            throw VulnBaselineIoException("Cannot read baseline at $path: ${e.message}", e)
        }
        if (text.isBlank()) {
            throw VulnBaselineIoException("Baseline file at $path is empty")
        }
        val baseline = try {
            gson.fromJson(text, VulnBaseline::class.java)
        } catch (e: JsonSyntaxException) {
            throw VulnBaselineIoException("Malformed baseline JSON at $path: ${e.message}", e)
        } catch (e: RuntimeException) {
            throw VulnBaselineIoException("Failed to parse baseline at $path: ${e.message}", e)
        } ?: throw VulnBaselineIoException("Baseline file at $path did not parse to an object")

        if (baseline.schemaVersion != VulnBaseline.CURRENT_SCHEMA_VERSION) {
            throw VulnBaselineIoException(
                "Unsupported baseline schemaVersion ${baseline.schemaVersion}; " +
                    "expected ${VulnBaseline.CURRENT_SCHEMA_VERSION}"
            )
        }
        return baseline
    }

    /**
     * Save [baseline] to the default location `<root>/.vulnspeed-baseline.json`.
     *
     * @return the path that was written.
     */
    @Throws(IOException::class)
    fun saveDefault(baseline: VulnBaseline, root: Path): Path {
        val target = defaultPath(root)
        save(baseline, target)
        return target
    }

    /** Resolve the default baseline path under [root]. */
    fun defaultPath(root: Path): Path = root.resolve(DEFAULT_FILE_NAME)
}
