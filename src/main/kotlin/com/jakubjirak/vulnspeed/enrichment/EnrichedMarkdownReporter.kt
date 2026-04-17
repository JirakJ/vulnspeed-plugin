/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Renders an [EnrichedVulnerability] list as a PR-friendly Markdown report.
 *
 * Sections:
 *   * Summary table (counts per severity + CVE coverage)
 *   * Enriched findings table (CVE, package, CVSS, severity, fix)
 *   * Per-finding details blocks with CWEs, references, fixed versions.
 */
object EnrichedMarkdownReporter {

    private val dateFmt: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC)

    /**
     * Render [enriched] as Markdown.
     *
     * @param title         document title.
     * @param toolVersion   VulnSpeed version to cite in the footer.
     * @param generatedAt   timestamp for the report (UTC).
     */
    fun render(
        enriched: List<EnrichedVulnerability>,
        title: String = "VulnSpeed — CVE Enrichment Report",
        toolVersion: String = "unknown",
        generatedAt: Instant = Instant.now(),
    ): String {
        val sb = StringBuilder()
        sb.append("# ").append(title).append('\n')
        sb.append('\n')
        sb.append("_Generated ").append(dateFmt.format(generatedAt))
            .append(" by VulnSpeed ").append(toolVersion).append("._\n\n")

        sb.append(renderSummary(enriched)).append('\n')

        val withMeta = enriched.filter { it.metadata != null }
        val withoutMeta = enriched.filter { it.metadata == null }

        sb.append("## Enriched Findings\n\n")
        if (withMeta.isEmpty()) {
            sb.append("_No findings could be enriched with CVE metadata._\n\n")
        } else {
            sb.append("| CVE | Package | CVSS | Severity | Fixed In | CWE |\n")
            sb.append("|-----|---------|-----:|----------|----------|-----|\n")
            for (e in withMeta) {
                val m = e.metadata!!
                val pkg = e.vulnerability.let { "${it.filePath}:${it.line}" }
                val cwes = if (m.cweIds.isEmpty()) "—" else m.cweIds.joinToString(", ")
                val fixed = if (m.fixedVersions.isEmpty()) "—" else m.fixedVersions.joinToString("<br/>")
                sb.append("| ").append(esc(m.cveId))
                    .append(" | ").append(esc(pkg))
                    .append(" | ").append(formatScore(m.cvssScore))
                    .append(" | ").append(esc(m.severity))
                    .append(" | ").append(esc(fixed))
                    .append(" | ").append(esc(cwes))
                    .append(" |\n")
            }
            sb.append('\n')

            sb.append("## Details\n\n")
            for (e in withMeta) {
                val m = e.metadata!!
                sb.append("### ").append(m.cveId).append('\n')
                if (m.summary.isNotBlank()) sb.append("> ").append(escInline(m.summary)).append("\n\n")
                sb.append("- **Source:** ").append(esc(m.source)).append('\n')
                sb.append("- **CVSS:** ").append(formatScore(m.cvssScore))
                if (m.cvssVector.isNotBlank()) sb.append(" (").append(esc(m.cvssVector)).append(')')
                sb.append('\n')
                sb.append("- **Severity:** ").append(esc(m.severity)).append('\n')
                if (m.cweIds.isNotEmpty()) sb.append("- **CWE:** ").append(esc(m.cweIds.joinToString(", "))).append('\n')
                m.published?.let { sb.append("- **Published:** ").append(dateFmt.format(it)).append('\n') }
                m.modified?.let { sb.append("- **Modified:** ").append(dateFmt.format(it)).append('\n') }
                if (m.fixedVersions.isNotEmpty()) {
                    sb.append("- **Fixed versions:**\n")
                    for (fv in m.fixedVersions) sb.append("  - `").append(fv).append("`\n")
                }
                if (m.affectedRanges.isNotEmpty()) {
                    sb.append("- **Affected ranges:**\n")
                    for (r in m.affectedRanges) {
                        sb.append("  - `").append(r.ecosystem).append(':').append(r.pkg).append('`')
                        val intro = r.introduced ?: "0"
                        val fixed = r.fixed ?: "∞"
                        sb.append(" (").append(intro).append(" → ").append(fixed).append(")\n")
                    }
                }
                if (m.references.isNotEmpty()) {
                    sb.append("- **References:**\n")
                    for (ref in m.references) sb.append("  - <").append(ref).append(">\n")
                }
                sb.append('\n')
            }
        }

        if (withoutMeta.isNotEmpty()) {
            sb.append("## Findings without CVE Metadata\n\n")
            sb.append("| Rule | Severity | File:Line | Message |\n")
            sb.append("|------|----------|-----------|---------|\n")
            for (e in withoutMeta) {
                val v = e.vulnerability
                sb.append("| ").append(esc(v.ruleId))
                    .append(" | ").append(esc(v.severity.name))
                    .append(" | ").append(esc("${v.filePath}:${v.line}"))
                    .append(" | ").append(escInline(v.message))
                    .append(" |\n")
            }
            sb.append('\n')
        }

        sb.append("---\n_Report generated by VulnSpeed ").append(toolVersion).append("._\n")
        return sb.toString()
    }

    private fun renderSummary(enriched: List<EnrichedVulnerability>): String {
        val total = enriched.size
        val withMeta = enriched.count { it.metadata != null }
        val bySeverity = enriched.groupingBy { it.metadata?.severity ?: "UNKNOWN" }.eachCount()
        val sb = StringBuilder()
        sb.append("## Summary\n\n")
        sb.append("- Total findings: **").append(total).append("**\n")
        sb.append("- Enriched with CVE metadata: ").append(withMeta).append('\n')
        sb.append("- Severity breakdown:\n")
        for (sev in listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) {
            val count = bySeverity[sev] ?: 0
            if (count > 0) sb.append("  - ").append(sev).append(": ").append(count).append('\n')
        }
        sb.append('\n')
        return sb.toString()
    }

    private fun formatScore(score: Double): String =
        if (score <= 0.0) "—" else "%.1f".format(score)

    private fun esc(s: String): String =
        s.replace("|", "\\|").replace("\n", " ").replace("\r", "")

    private fun escInline(s: String): String =
        s.replace("|", "\\|").replace("\n", " ").replace("\r", "").take(240)
}
