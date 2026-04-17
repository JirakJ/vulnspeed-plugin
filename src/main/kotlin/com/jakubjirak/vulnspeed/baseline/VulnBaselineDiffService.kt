/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import java.nio.file.Path

/**
 * Aggregate counts describing a [VulnBaselineDiff].
 *
 * @property newBySeverity number of new findings bucketed by [Severity.name].
 *                         Every severity is present with at least a zero count.
 * @property totalNew total number of new regressions.
 * @property totalFixed number of baseline entries no longer reported.
 * @property totalPersisted number of current findings already in the baseline.
 */
data class VulnBaselineDiffSummary(
    val newBySeverity: Map<String, Int>,
    val totalNew: Int,
    val totalFixed: Int,
    val totalPersisted: Int,
) {
    /** `true` when at least one new regression was found. */
    fun hasRegressions(): Boolean = totalNew > 0

    /** Convenience: count of new findings at or above [threshold]. */
    fun countAtOrAbove(threshold: Severity): Int {
        val order = Severity.entries.toList()
        val idx = order.indexOf(threshold)
        return order.take(idx + 1).sumOf { newBySeverity[it.name] ?: 0 }
    }
}

/**
 * Result of comparing current findings against a stored [VulnBaseline].
 *
 * @property newFindings current findings that have no fingerprint match in the baseline (regressions).
 * @property fixedEntries baseline entries with no fingerprint match in the current scan.
 * @property persistedFindings current findings whose fingerprint is still in the baseline.
 * @property summary aggregate per-severity counts.
 */
data class VulnBaselineDiff(
    val newFindings: List<Vulnerability>,
    val fixedEntries: List<VulnBaselineEntry>,
    val persistedFindings: List<Vulnerability>,
    val summary: VulnBaselineDiffSummary,
) {
    /** Convenience forwarder to [VulnBaselineDiffSummary.hasRegressions]. */
    fun hasRegressions(): Boolean = summary.hasRegressions()
}

/**
 * Pure-Kotlin service that computes the differential between a saved
 * [VulnBaseline] and a set of current findings.
 */
object VulnBaselineDiffService {

    /**
     * Compute the differential.
     *
     * @param baseline previously saved baseline, or `null` if none exists.
     * @param currentFindings findings from the current scan.
     * @param projectRoot absolute project root, used to produce matching fingerprints.
     *
     * When [baseline] is `null`, every current finding is reported as new.
     */
    fun diff(
        baseline: VulnBaseline?,
        currentFindings: List<Vulnerability>,
        projectRoot: Path,
    ): VulnBaselineDiff {
        if (baseline == null) {
            return VulnBaselineDiff(
                newFindings = currentFindings.toList(),
                fixedEntries = emptyList(),
                persistedFindings = emptyList(),
                summary = summary(currentFindings, fixed = 0, persisted = 0),
            )
        }

        val currentByFp = linkedMapOf<String, Vulnerability>()
        for (v in currentFindings) {
            val fp = VulnFingerprint.of(v, projectRoot)
            currentByFp.putIfAbsent(fp, v)
        }
        val baselineByFp = baseline.entries.associateBy { it.fingerprint }

        val newFindings = currentByFp.filterKeys { it !in baselineByFp }.values.toList()
        val fixedEntries = baselineByFp.filterKeys { it !in currentByFp }.values.toList()
        val persistedFindings = currentByFp.filterKeys { it in baselineByFp }.values.toList()

        return VulnBaselineDiff(
            newFindings = newFindings,
            fixedEntries = fixedEntries,
            persistedFindings = persistedFindings,
            summary = summary(newFindings, fixedEntries.size, persistedFindings.size),
        )
    }

    private fun summary(
        newFindings: List<Vulnerability>,
        fixed: Int,
        persisted: Int,
    ): VulnBaselineDiffSummary {
        val counts: MutableMap<String, Int> = Severity.entries.associate { it.name to 0 }.toMutableMap()
        for (v in newFindings) {
            counts[v.severity.name] = (counts[v.severity.name] ?: 0) + 1
        }
        return VulnBaselineDiffSummary(
            newBySeverity = counts.toMap(),
            totalNew = newFindings.size,
            totalFixed = fixed,
            totalPersisted = persisted,
        )
    }
}
