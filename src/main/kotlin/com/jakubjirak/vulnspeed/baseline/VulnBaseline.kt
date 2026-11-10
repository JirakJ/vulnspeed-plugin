/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.jakubjirak.vulnspeed.model.Vulnerability
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest

/**
 * A single accepted finding in a [VulnBaseline].
 *
 * @property fingerprint deterministic fingerprint of the finding (see [VulnFingerprint]).
 * @property ruleId the analyzer rule that produced the finding.
 * @property severity severity name (matches [com.jakubjirak.vulnspeed.model.Severity]).
 * @property cwe CWE identifier.
 * @property filePath project-relative file path (forward slashes).
 * @property startLine 1-based start line.
 * @property messageHash hash of the normalized message, for auditability.
 * @property acceptedReason optional human-readable justification that round-trips through save/load.
 * @property acceptedAtEpochMs optional time at which the entry was accepted into the baseline.
 */
data class VulnBaselineEntry(
    val fingerprint: String,
    val ruleId: String,
    val severity: String,
    val cwe: Int,
    val filePath: String,
    val startLine: Int,
    val messageHash: String,
    val acceptedReason: String? = null,
    val acceptedAtEpochMs: Long? = null,
)

/**
 * An immutable snapshot of accepted vulnerabilities for a project.
 *
 * A baseline lets security gates ignore historical findings so that new code
 * introduces zero regressions without the team having to triage thousands of
 * pre-existing issues first.
 *
 * @property schemaVersion increasing integer. Loaders reject unknown versions.
 * @property generatedAtEpochMs creation timestamp, milliseconds since epoch.
 * @property toolVersion VulnSpeed plugin version that produced the baseline.
 * @property projectRootHash SHA-256 of the project's absolute root path.
 *                           Used to detect a baseline copied to a different project.
 * @property entries sorted, accepted findings.
 */
data class VulnBaseline(
    val schemaVersion: Int = CURRENT_SCHEMA_VERSION,
    val generatedAtEpochMs: Long,
    val toolVersion: String,
    val projectRootHash: String,
    val entries: List<VulnBaselineEntry>,
) {
    companion object {
        /** The only schema version this build recognises. */
        const val CURRENT_SCHEMA_VERSION: Int = 1

        /** Compute the project-root hash used to pin a baseline to a project. */
        fun projectRootHash(root: Path): String {
            val abs = root.toAbsolutePath().normalize().toString()
            val md = MessageDigest.getInstance("SHA-256")
            val bytes = md.digest(abs.toByteArray(StandardCharsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        /**
         * Build a baseline from a list of [Vulnerability] findings.
         *
         * The resulting entries are sorted by fingerprint so that baselines
         * produced from identical inputs are byte-identical.
         */
        fun fromFindings(
            findings: List<Vulnerability>,
            projectRoot: Path,
            toolVersion: String,
            acceptedAtEpochMs: Long = System.currentTimeMillis(),
            acceptedReason: String? = null,
        ): VulnBaseline {
            val entries = findings.map { v ->
                VulnBaselineEntry(
                    fingerprint = VulnFingerprint.of(v, projectRoot),
                    ruleId = v.ruleId,
                    severity = v.severity.name,
                    cwe = v.cwe,
                    filePath = VulnFingerprint.relativeFilePath(v.filePath, projectRoot),
                    startLine = v.line,
                    messageHash = VulnFingerprint.messageHash(v.message),
                    acceptedReason = acceptedReason,
                    acceptedAtEpochMs = acceptedAtEpochMs,
                )
            }.sortedBy { it.fingerprint }
            return VulnBaseline(
                schemaVersion = CURRENT_SCHEMA_VERSION,
                generatedAtEpochMs = acceptedAtEpochMs,
                toolVersion = toolVersion,
                projectRootHash = projectRootHash(projectRoot),
                entries = entries,
            )
        }
    }
}
