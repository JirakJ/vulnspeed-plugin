/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.jakubjirak.vulnspeed.model.Vulnerability
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest

/**
 * Deterministic vulnerability fingerprint used to correlate findings across
 * scan runs.
 *
 * A fingerprint is a SHA-256 hex digest over a pipe-joined payload consisting
 * of `ruleId|cwe|relativeFilePath|startLine|normalizedMessage`. The components
 * are chosen so that cosmetic reformatting, line re-numbering in unrelated
 * files, or IDE-specific absolute paths do not change the fingerprint.
 *
 * All operations are pure and thread-safe.
 */
object VulnFingerprint {

    /**
     * Compute the fingerprint of [v] relative to [projectRoot].
     *
     * @param v a concrete finding from a scan.
     * @param projectRoot absolute path of the project root. Used to relativize
     *                    the finding's file path.
     * @return lower-case SHA-256 hex digest, 64 characters long.
     */
    fun of(v: Vulnerability, projectRoot: Path): String {
        val rel = relativeFilePath(v.filePath, projectRoot)
        val normalized = normalizeMessage(v.message)
        val payload = "${v.ruleId}|${v.cwe}|$rel|${v.line}|$normalized"
        return sha256Hex(payload)
    }

    /**
     * Return the SHA-256 hex digest of the normalized form of [raw].
     *
     * Exposed for tests and for auditability — the `messageHash` stored in a
     * baseline entry is derived from this helper.
     */
    fun messageHash(raw: String): String = sha256Hex(normalizeMessage(raw))

    /**
     * Normalize a human-readable finding message.
     *
     * Applied transformations, in order:
     * 1. Lower-case.
     * 2. Replace single- and double-quoted strings with `<S>`.
     * 3. Replace numeric literals (integers and decimals) with `<N>`.
     * 4. Collapse runs of whitespace to a single space.
     * 5. Trim leading and trailing whitespace.
     */
    fun normalizeMessage(raw: String): String {
        var s = raw.lowercase()
        s = QUOTED_RE.replace(s, "<S>")
        s = NUMBER_RE.replace(s, "<N>")
        s = WHITESPACE_RE.replace(s, " ")
        return s.trim()
    }

    /**
     * Compute the project-relative path of [rawPath].
     *
     * The result always uses forward slashes. If the file is outside
     * [projectRoot], the absolute path is returned with a `file://` prefix so
     * that fingerprints remain stable but obviously distinguishable.
     */
    fun relativeFilePath(rawPath: String, projectRoot: Path): String {
        val absRoot = try {
            projectRoot.toAbsolutePath().normalize()
        } catch (_: RuntimeException) {
            return rawPath.replace('\\', '/')
        }
        val file = try {
            Paths.get(rawPath).toAbsolutePath().normalize()
        } catch (_: RuntimeException) {
            return rawPath.replace('\\', '/')
        }
        return if (file.startsWith(absRoot)) {
            val rel = absRoot.relativize(file).toString().replace('\\', '/')
            if (rel.isEmpty()) "." else rel
        } else {
            "file://" + file.toString().replace('\\', '/')
        }
    }

    private fun sha256Hex(s: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(s.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private val QUOTED_RE = Regex("\"[^\"]*\"|'[^']*'")
    private val NUMBER_RE = Regex("-?\\d+(?:\\.\\d+)?")
    private val WHITESPACE_RE = Regex("\\s+")
}
