/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import java.security.MessageDigest

/**
 * Exports VulnSpeed scan findings to a SARIF 2.1.0 JSON report.
 *
 * The generated document conforms to the OASIS SARIF 2.1.0 schema
 * (https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json)
 * and is accepted by GitHub Code Scanning, GitLab SAST ingestion, Azure DevOps,
 * SonarQube, and DefectDojo.
 *
 * This class is pure Kotlin with no IDE dependencies so it can be unit tested
 * and reused in CI/CD tooling.
 */
class SarifReportExporter {

    /**
     * Produce a SARIF 2.1.0 JSON document describing the given [findings].
     *
     * @param findings list of vulnerabilities from a VulnSpeed scan (may be empty).
     * @param toolVersion the version string of the VulnSpeed plugin / engine.
     * @param projectRoot absolute path to the project root. File paths inside
     *                    findings are made project-relative when possible.
     * @return a valid SARIF 2.1.0 JSON string.
     */
    fun export(
        findings: List<Vulnerability>,
        toolVersion: String,
        projectRoot: String
    ): String {
        val normalizedRoot = normalizeRoot(projectRoot)
        val rules = buildRules(findings)
        val ruleIndexById = rules.mapIndexed { i, r -> r.id to i }.toMap()

        val sb = StringBuilder(4096)
        sb.append('{')
        appendKeyString(sb, "\$schema",
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json")
        sb.append(',')
        appendKeyString(sb, "version", "2.1.0")
        sb.append(',')
        appendKey(sb, "runs")
        sb.append('[')
        appendRun(sb, findings, rules, ruleIndexById, toolVersion, normalizedRoot)
        sb.append(']')
        sb.append('}')
        return sb.toString()
    }

    private fun appendRun(
        sb: StringBuilder,
        findings: List<Vulnerability>,
        rules: List<SarifRule>,
        ruleIndexById: Map<String, Int>,
        toolVersion: String,
        projectRoot: String
    ) {
        sb.append('{')
        appendKey(sb, "tool"); sb.append('{')
        appendKey(sb, "driver"); sb.append('{')
        appendKeyString(sb, "name", "VulnSpeed"); sb.append(',')
        appendKeyString(sb, "version", toolVersion); sb.append(',')
        appendKeyString(sb, "informationUri", "https://github.com/JirakJ/vulnspeed-plugin"); sb.append(',')
        appendKeyString(sb, "semanticVersion", toolVersion); sb.append(',')
        appendKey(sb, "rules"); sb.append('[')
        rules.forEachIndexed { i, rule ->
            if (i > 0) sb.append(',')
            appendRule(sb, rule)
        }
        sb.append(']')
        sb.append('}') // driver
        sb.append('}') // tool
        sb.append(',')
        appendKey(sb, "results"); sb.append('[')
        findings.forEachIndexed { i, v ->
            if (i > 0) sb.append(',')
            appendResult(sb, v, ruleIndexById, projectRoot)
        }
        sb.append(']')
        sb.append('}')
    }

    private fun appendRule(sb: StringBuilder, rule: SarifRule) {
        sb.append('{')
        appendKeyString(sb, "id", rule.id); sb.append(',')
        appendKeyString(sb, "name", rule.name); sb.append(',')
        appendKey(sb, "shortDescription"); sb.append('{')
        appendKeyString(sb, "text", rule.shortDescription)
        sb.append('}'); sb.append(',')
        appendKey(sb, "fullDescription"); sb.append('{')
        appendKeyString(sb, "text", rule.fullDescription)
        sb.append('}'); sb.append(',')
        appendKeyString(sb, "helpUri", rule.helpUri); sb.append(',')
        appendKey(sb, "help"); sb.append('{')
        appendKeyString(sb, "text", rule.fullDescription); sb.append(',')
        appendKeyString(sb, "markdown", rule.fullDescription + "\n\nSee: " + rule.helpUri)
        sb.append('}'); sb.append(',')
        appendKey(sb, "defaultConfiguration"); sb.append('{')
        appendKeyString(sb, "level", rule.level)
        sb.append('}'); sb.append(',')
        appendKey(sb, "properties"); sb.append('{')
        appendKey(sb, "tags"); sb.append('[')
        rule.tags.forEachIndexed { i, t ->
            if (i > 0) sb.append(',')
            sb.append('"'); jsonEscape(sb, t); sb.append('"')
        }
        sb.append(']'); sb.append(',')
        appendKeyString(sb, "security-severity", rule.securitySeverity)
        sb.append('}')
        sb.append('}')
    }

    private fun appendResult(
        sb: StringBuilder,
        v: Vulnerability,
        ruleIndexById: Map<String, Int>,
        projectRoot: String
    ) {
        val relPath = relativize(v.filePath, projectRoot)
        val uri = toUriPath(relPath)
        val startLine = maxOf(1, v.line)
        val startCol = maxOf(1, v.column)
        val endCol = startCol + 1
        val level = severityToLevel(v.severity)
        val fingerprint = fingerprint(v.ruleId, relPath, startLine, v.message)

        sb.append('{')
        appendKeyString(sb, "ruleId", v.ruleId); sb.append(',')
        val idx = ruleIndexById[v.ruleId]
        if (idx != null) {
            appendKey(sb, "ruleIndex"); sb.append(idx.toString()); sb.append(',')
        }
        appendKeyString(sb, "level", level); sb.append(',')
        appendKey(sb, "message"); sb.append('{')
        appendKeyString(sb, "text", v.message)
        sb.append('}'); sb.append(',')
        appendKey(sb, "locations"); sb.append('[')
        sb.append('{')
        appendKey(sb, "physicalLocation"); sb.append('{')
        appendKey(sb, "artifactLocation"); sb.append('{')
        appendKeyString(sb, "uri", uri); sb.append(',')
        appendKeyString(sb, "uriBaseId", "%SRCROOT%")
        sb.append('}'); sb.append(',')
        appendKey(sb, "region"); sb.append('{')
        appendKey(sb, "startLine"); sb.append(startLine.toString()); sb.append(',')
        appendKey(sb, "endLine"); sb.append(startLine.toString()); sb.append(',')
        appendKey(sb, "startColumn"); sb.append(startCol.toString()); sb.append(',')
        appendKey(sb, "endColumn"); sb.append(endCol.toString()); sb.append(',')
        appendKey(sb, "snippet"); sb.append('{')
        appendKeyString(sb, "text", v.codeSnippet)
        sb.append('}')
        sb.append('}')
        sb.append('}')
        sb.append('}')
        sb.append(']'); sb.append(',')
        appendKey(sb, "partialFingerprints"); sb.append('{')
        appendKeyString(sb, "vulnspeed/v1", fingerprint)
        sb.append('}'); sb.append(',')
        appendKey(sb, "properties"); sb.append('{')
        appendKeyString(sb, "cwe", "CWE-${v.cwe}"); sb.append(',')
        appendKeyString(sb, "owasp", v.owasp); sb.append(',')
        appendKeyString(sb, "severity", v.severity.name); sb.append(',')
        appendKeyString(sb, "confidence", v.confidence.toString())
        sb.append('}')
        sb.append('}')
    }

    /** Build a deduplicated list of rules from findings. */
    internal fun buildRules(findings: List<Vulnerability>): List<SarifRule> {
        val seen = LinkedHashMap<String, SarifRule>()
        for (v in findings) {
            if (!seen.containsKey(v.ruleId)) {
                seen[v.ruleId] = SarifRule(
                    id = v.ruleId,
                    name = v.ruleName.ifBlank { v.ruleId },
                    shortDescription = v.ruleName.ifBlank { v.message.take(120) },
                    fullDescription = v.message,
                    helpUri = cweUri(v.cwe),
                    level = severityToLevel(v.severity),
                    securitySeverity = severityToScore(v.severity),
                    tags = listOf("security", v.type.name, "CWE-${v.cwe}")
                )
            }
        }
        return seen.values.toList()
    }

    /**
     * Map internal [Severity] to SARIF level values:
     * CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note.
     */
    internal fun severityToLevel(s: Severity): String = when (s) {
        Severity.CRITICAL, Severity.HIGH -> "error"
        Severity.MEDIUM -> "warning"
        Severity.LOW, Severity.INFO -> "note"
    }

    /** GitHub Code Scanning "security-severity" numeric score (0-10). */
    internal fun severityToScore(s: Severity): String = when (s) {
        Severity.CRITICAL -> "9.5"
        Severity.HIGH -> "8.0"
        Severity.MEDIUM -> "5.0"
        Severity.LOW -> "3.0"
        Severity.INFO -> "1.0"
    }

    /**
     * Resolve a CWE help URI. Non-positive CWE ids fall back to the CWE list URL.
     */
    internal fun cweUri(cwe: Int): String =
        if (cwe > 0) "https://cwe.mitre.org/data/definitions/$cwe.html"
        else "https://cwe.mitre.org/data/definitions/"

    /** Make [absolute] path project-relative when possible; else return [absolute]. */
    internal fun relativize(absolute: String, projectRoot: String): String {
        if (projectRoot.isBlank()) return absolute
        val normAbs = absolute.replace('\\', '/')
        val normRoot = projectRoot.replace('\\', '/').trimEnd('/')
        return when {
            normAbs.startsWith("$normRoot/") -> normAbs.substring(normRoot.length + 1)
            normAbs == normRoot -> ""
            else -> normAbs
        }
    }

    /**
     * Percent-encode a filesystem path into a SARIF-acceptable artifactLocation URI.
     * Forward slashes are preserved; every other non-unreserved byte is %-escaped
     * against its UTF-8 encoding.
     */
    internal fun toUriPath(path: String): String {
        val sb = StringBuilder(path.length + 16)
        val bytes = path.replace('\\', '/').toByteArray(Charsets.UTF_8)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            val safe = c == '/'.code ||
                (c in 'A'.code..'Z'.code) ||
                (c in 'a'.code..'z'.code) ||
                (c in '0'.code..'9'.code) ||
                c == '-'.code || c == '_'.code || c == '.'.code || c == '~'.code
            if (safe) sb.append(c.toChar())
            else sb.append('%').append(HEX_UPPER[(c ushr 4) and 0xF]).append(HEX_UPPER[c and 0xF])
        }
        return sb.toString()
    }

    /**
     * Stable partial fingerprint combining ruleId, path, line, and message so
     * identical findings across runs deduplicate in downstream systems.
     */
    internal fun fingerprint(ruleId: String, path: String, startLine: Int, message: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(ruleId.toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(path.toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(startLine.toString().toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(message.toByteArray(Charsets.UTF_8))
        val out = md.digest()
        val hex = StringBuilder(out.size * 2)
        for (byte in out) {
            val v = byte.toInt() and 0xFF
            hex.append(HEX_LOWER[(v ushr 4) and 0xF]).append(HEX_LOWER[v and 0xF])
        }
        return hex.toString()
    }

    private fun normalizeRoot(root: String): String {
        if (root.isBlank()) return ""
        return root.replace('\\', '/').trimEnd('/')
    }

    // ---- JSON helpers ----

    private fun appendKey(sb: StringBuilder, key: String) {
        sb.append('"'); jsonEscape(sb, key); sb.append('"'); sb.append(':')
    }

    private fun appendKeyString(sb: StringBuilder, key: String, value: String) {
        appendKey(sb, key)
        sb.append('"'); jsonEscape(sb, value); sb.append('"')
    }

    private fun jsonEscape(sb: StringBuilder, s: String) {
        for (ch in s) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    val c = ch.code
                    if (c < 0x20 || c == 0x7F) {
                        sb.append("\\u")
                        sb.append(HEX_LOWER[(c ushr 12) and 0xF])
                        sb.append(HEX_LOWER[(c ushr 8) and 0xF])
                        sb.append(HEX_LOWER[(c ushr 4) and 0xF])
                        sb.append(HEX_LOWER[c and 0xF])
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
    }

    /**
     * Internal representation of a SARIF reporting descriptor.
     */
    internal data class SarifRule(
        val id: String,
        val name: String,
        val shortDescription: String,
        val fullDescription: String,
        val helpUri: String,
        val level: String,
        val securitySeverity: String,
        val tags: List<String>
    )

    companion object {
        private val HEX_LOWER = "0123456789abcdef".toCharArray()
        private val HEX_UPPER = "0123456789ABCDEF".toCharArray()
    }
}
