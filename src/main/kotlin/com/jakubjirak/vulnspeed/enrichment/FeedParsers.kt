/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/** Signals a structural problem in an upstream feed response. */
class EnrichmentFeedException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Parsers for the OSV.dev and NVD JSON schemas into the canonical [CveMetadata].
 *
 * Kept deliberately tolerant: missing fields are treated as empty rather than
 * raising, because real-world responses from both feeds routinely omit fields
 * such as `cvss`, `cwe_ids`, or `published`.
 */
internal object FeedParsers {

    /** Parse an OSV.dev `/v1/vulns/{id}` response into [CveMetadata]. */
    fun parseOsv(json: String): CveMetadata {
        val rootEl = safeParse(json)
        if (!rootEl.isJsonObject) throw EnrichmentFeedException("OSV: root is not an object")
        val root = rootEl.asJsonObject

        val cveId = pickCveId(root)
        val summary = getString(root, "summary").ifBlank { getString(root, "details") }
        val published = getInstant(root, "published")
        val modified = getInstant(root, "modified")

        val severityArr = getArray(root, "severity")
        val (score, vector) = parseOsvSeverity(severityArr)
        val cweIds = parseOsvCwes(root)

        val references = iter(getArray(root, "references"))
            .mapNotNull { asObject(it) }
            .mapNotNull { getString(it, "url").ifBlank { null } }
            .distinct()

        val ranges = mutableListOf<AffectedRange>()
        val fixedVersions = mutableListOf<String>()
        for (entry in iter(getArray(root, "affected"))) {
            val obj = asObject(entry) ?: continue
            val pkg = getObject(obj, "package") ?: continue
            val name = getString(pkg, "name")
            if (name.isBlank()) continue
            val ecosystem = getString(pkg, "ecosystem").ifBlank { "unknown" }
            for (r in iter(getArray(obj, "ranges"))) {
                val robj = asObject(r) ?: continue
                var introduced: String? = null
                var fixed: String? = null
                for (ev in iter(getArray(robj, "events"))) {
                    val evo = asObject(ev) ?: continue
                    getString(evo, "introduced").ifBlank { null }?.let { introduced = it }
                    getString(evo, "fixed").ifBlank { null }?.let {
                        fixed = it
                        fixedVersions += "$ecosystem:$name@$it"
                    }
                }
                if (introduced != null || fixed != null) {
                    ranges += AffectedRange(ecosystem = ecosystem, pkg = name, introduced = introduced, fixed = fixed)
                }
            }
        }

        return CveMetadata(
            cveId = cveId,
            cvssScore = score,
            cvssVector = vector,
            severity = severityFromScore(score),
            cweIds = cweIds,
            published = published,
            modified = modified,
            summary = summary,
            references = references.toList(),
            fixedVersions = fixedVersions.distinct(),
            affectedRanges = ranges,
            source = "OSV",
        )
    }

    /** Parse an NVD `/rest/json/cves/2.0` response into [CveMetadata]. */
    fun parseNvd(json: String): CveMetadata {
        val rootEl = safeParse(json)
        if (!rootEl.isJsonObject) throw EnrichmentFeedException("NVD: root is not an object")
        val root = rootEl.asJsonObject

        val vulns = getArray(root, "vulnerabilities")
            ?: throw EnrichmentFeedException("NVD: missing 'vulnerabilities' array")
        val first = iter(vulns).firstNotNullOfOrNull { asObject(it) }
            ?: throw EnrichmentFeedException("NVD: empty 'vulnerabilities' array")
        val cve = getObject(first, "cve")
            ?: throw EnrichmentFeedException("NVD: missing 'cve' object")

        val cveId = getString(cve, "id").ifBlank { "UNKNOWN" }
        val summary = iter(getArray(cve, "descriptions"))
            .mapNotNull { asObject(it) }
            .firstOrNull { getString(it, "lang") == "en" }
            ?.let { getString(it, "value") }
            .orEmpty()
        val published = getInstant(cve, "published")
        val modified = getInstant(cve, "lastModified")

        val metrics = getObject(cve, "metrics")
        val (score, vector, severity) = parseNvdMetrics(metrics)

        val cwes = iter(getArray(cve, "weaknesses"))
            .mapNotNull { asObject(it) }
            .flatMap { w -> iter(getArray(w, "description")).mapNotNull { asObject(it) } }
            .map { getString(it, "value") }
            .filter { it.startsWith("CWE-") }
            .distinct()
            .toList()

        val references = iter(getArray(cve, "references"))
            .mapNotNull { asObject(it) }
            .mapNotNull { getString(it, "url").ifBlank { null } }
            .distinct()
            .toList()

        return CveMetadata(
            cveId = cveId,
            cvssScore = score,
            cvssVector = vector,
            severity = severity,
            cweIds = cwes,
            published = published,
            modified = modified,
            summary = summary,
            references = references,
            fixedVersions = emptyList(),
            affectedRanges = emptyList(),
            source = "NVD",
        )
    }

    private fun parseOsvSeverity(arr: JsonArray?): Pair<Double, String> {
        if (arr == null) return 0.0 to ""
        for (el in arr) {
            val o = asObject(el) ?: continue
            val type = getString(o, "type")
            val score = getString(o, "score")
            if (type.contains("CVSS", ignoreCase = true) && score.isNotBlank()) {
                return (score.toDoubleOrNull() ?: 0.0) to score
            }
        }
        return 0.0 to ""
    }

    private fun parseOsvCwes(root: JsonObject): List<String> {
        val ds = getObject(root, "database_specific") ?: return emptyList()
        val arr = getArray(ds, "cwe_ids") ?: return emptyList()
        return iter(arr).mapNotNull { asString(it)?.uppercase() }
            .map { if (it.startsWith("CWE-")) it else "CWE-$it" }
            .distinct()
            .toList()
    }

    private data class NvdMetric(val score: Double, val vector: String, val severity: String)

    private fun parseNvdMetrics(metrics: JsonObject?): NvdMetric {
        if (metrics == null) return NvdMetric(0.0, "", "UNKNOWN")
        for (key in listOf("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")) {
            val arr = getArray(metrics, key) ?: continue
            val first = iter(arr).firstNotNullOfOrNull { asObject(it) } ?: continue
            val data = getObject(first, "cvssData") ?: continue
            val score = getDouble(data, "baseScore")
            val vector = getString(data, "vectorString")
            val severity = getString(data, "baseSeverity").ifBlank { severityFromScore(score) }
            return NvdMetric(score, vector, severity.uppercase())
        }
        return NvdMetric(0.0, "", "UNKNOWN")
    }

    private fun pickCveId(root: JsonObject): String {
        val id = getString(root, "id")
        if (id.startsWith("CVE-", ignoreCase = true)) return id.uppercase()
        val aliases = iter(getArray(root, "aliases")).mapNotNull { asString(it) }
        val alias = aliases.firstOrNull { it.startsWith("CVE-", ignoreCase = true) }
        return (alias ?: id).uppercase()
    }

    private fun severityFromScore(score: Double): String = when {
        score <= 0.0 -> "UNKNOWN"
        score < 4.0 -> "LOW"
        score < 7.0 -> "MEDIUM"
        score < 9.0 -> "HIGH"
        else -> "CRITICAL"
    }

    private fun safeParse(json: String): JsonElement = try {
        JsonParser.parseString(json)
    } catch (e: RuntimeException) {
        throw EnrichmentFeedException("Malformed JSON: ${e.message}", e)
    }

    // --- small typed accessors over Gson's loose JSON tree ---

    private fun iter(arr: JsonArray?): Sequence<JsonElement> =
        if (arr == null) emptySequence() else arr.asSequence()

    private fun asObject(el: JsonElement?): JsonObject? =
        if (el != null && el.isJsonObject) el.asJsonObject else null

    private fun asString(el: JsonElement?): String? =
        if (el != null && el.isJsonPrimitive && el.asJsonPrimitive.isString) el.asString else null

    private fun getString(obj: JsonObject, key: String): String {
        if (!obj.has(key)) return ""
        val el = obj.get(key)
        return if (el != null && !el.isJsonNull && el.isJsonPrimitive) el.asString else ""
    }

    private fun getDouble(obj: JsonObject, key: String): Double {
        if (!obj.has(key)) return 0.0
        val el = obj.get(key)
        if (el == null || el.isJsonNull || !el.isJsonPrimitive) return 0.0
        return try {
            el.asDouble
        } catch (_: NumberFormatException) {
            0.0
        }
    }

    private fun getArray(obj: JsonObject, key: String): JsonArray? {
        if (!obj.has(key)) return null
        val el = obj.get(key)
        return if (el != null && el.isJsonArray) el.asJsonArray else null
    }

    private fun getObject(obj: JsonObject, key: String): JsonObject? {
        if (!obj.has(key)) return null
        val el = obj.get(key)
        return if (el != null && el.isJsonObject) el.asJsonObject else null
    }

    private fun getInstant(obj: JsonObject, key: String): java.time.Instant? {
        val raw = getString(obj, key).ifBlank { return null }
        val tried = sequenceOf(raw, normalizeNvdDate(raw))
        for (candidate in tried) {
            try {
                return java.time.Instant.parse(candidate)
            } catch (_: java.time.format.DateTimeParseException) {
                // try next
            }
        }
        return null
    }

    /** NVD often emits `2021-12-10T10:15:09.143` (no zone). Assume UTC. */
    private fun normalizeNvdDate(raw: String): String =
        if (raw.endsWith("Z") || raw.contains('+')) raw else "${raw}Z"
}
