/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.sbom

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

/**
 * Produces a **CycloneDX v1.5** JSON Software Bill of Materials (SBOM).
 *
 * The document is consumed out-of-the-box by Dependency-Track, Sonatype
 * Lifecycle, GitHub Dependency Graph, FOSSA, and `cyclonedx-cli`.
 *
 * Pure Kotlin — no IDE or filesystem dependencies. All JSON serialization
 * flows through Gson so escaping is handled correctly.
 *
 * ### Serial number stability
 * `serialNumber` is a deterministic UUIDv5-style identifier derived from a
 * SHA-1 digest of the sorted component Package URLs. The same set of inputs
 * therefore yields the same `serialNumber` across runs (useful for diffs in
 * Git), while any change to the component set produces a new identifier.
 */
class CycloneDxSbomExporter {

    private val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

    /**
     * Build a CycloneDX 1.5 JSON document.
     *
     * @param components library/application components discovered by
     *                   [ManifestDependencyCollector] (may be empty).
     * @param vulnerabilities findings from the latest VulnSpeed scan; each
     *                       becomes one entry in `vulnerabilities[]`.
     * @param appMetadata information about the scanned application (emitted
     *                    as `metadata.component`).
     * @return Pretty-printed CycloneDX 1.5 JSON.
     */
    fun export(
        components: List<Component>,
        vulnerabilities: List<Vulnerability>,
        appMetadata: AppMetadata
    ): String {
        val root = JsonObject()
        root.addProperty("bomFormat", "CycloneDX")
        root.addProperty("specVersion", "1.5")
        root.addProperty("serialNumber", buildSerialNumber(components))
        root.addProperty("version", 1)
        root.add("metadata", buildMetadata(appMetadata))
        root.add("components", buildComponents(components))
        root.add("vulnerabilities", buildVulnerabilities(vulnerabilities, components, appMetadata))
        return gson.toJson(root)
    }

    private fun buildSerialNumber(components: List<Component>): String {
        val payload = components
            .mapNotNull { it.purl }
            .sorted()
            .joinToString("\n")
            .ifEmpty { "vulnspeed-empty-bom" }
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest(payload.toByteArray(StandardCharsets.UTF_8))
        sha1[6] = ((sha1[6].toInt() and 0x0F) or 0x50).toByte()
        sha1[8] = ((sha1[8].toInt() and 0x3F) or 0x80).toByte()
        val msb = (0 until 8).fold(0L) { acc, i -> (acc shl 8) or (sha1[i].toLong() and 0xFF) }
        val lsb = (8 until 16).fold(0L) { acc, i -> (acc shl 8) or (sha1[i].toLong() and 0xFF) }
        return "urn:uuid:" + UUID(msb, lsb).toString()
    }

    private fun buildMetadata(app: AppMetadata): JsonObject {
        val meta = JsonObject()
        meta.addProperty("timestamp", Instant.now().toString())

        val tools = JsonObject()
        val toolComponents = JsonArray()
        val tool = JsonObject()
        tool.addProperty("type", "application")
        tool.addProperty("name", "VulnSpeed")
        tool.addProperty("version", app.toolVersion)
        tool.addProperty("publisher", "JirakJ")
        toolComponents.add(tool)
        tools.add("components", toolComponents)
        meta.add("tools", tools)

        val appComponent = JsonObject()
        appComponent.addProperty("type", Component.Type.APPLICATION.wireValue)
        appComponent.addProperty("bom-ref", app.bomRef)
        appComponent.addProperty("name", app.name)
        app.version?.let { appComponent.addProperty("version", it) }
        meta.add("component", appComponent)
        return meta
    }

    private fun buildComponents(components: List<Component>): JsonArray {
        val arr = JsonArray()
        components.forEach { c ->
            val obj = JsonObject()
            obj.addProperty("type", c.type.wireValue)
            obj.addProperty("bom-ref", c.bomRef)
            obj.addProperty("name", c.name)
            c.version?.let { obj.addProperty("version", it) }
            c.description?.let { obj.addProperty("description", it) }
            c.purl?.let { obj.addProperty("purl", it) }

            if (c.licenses.isNotEmpty()) {
                val licenses = JsonArray()
                c.licenses.forEach { id ->
                    val lic = JsonObject()
                    val inner = JsonObject()
                    inner.addProperty("id", id)
                    lic.add("license", inner)
                    licenses.add(lic)
                }
                obj.add("licenses", licenses)
            }

            if (c.hashes.isNotEmpty()) {
                val hashes = JsonArray()
                c.hashes.entries.sortedBy { it.key }.forEach { (alg, value) ->
                    val h = JsonObject()
                    h.addProperty("alg", alg)
                    h.addProperty("content", value)
                    hashes.add(h)
                }
                obj.add("hashes", hashes)
            }
            arr.add(obj)
        }
        return arr
    }

    private fun buildVulnerabilities(
        vulnerabilities: List<Vulnerability>,
        components: List<Component>,
        app: AppMetadata
    ): JsonArray {
        val arr = JsonArray()
        vulnerabilities.forEach { v ->
            val obj = JsonObject()
            obj.addProperty("id", vulnId(v))

            val source = JsonObject()
            source.addProperty("name", "VulnSpeed")
            source.addProperty("url", "https://github.com/JirakJ/vulnspeed-plugin")
            obj.add("source", source)

            val ratings = JsonArray()
            val rating = JsonObject()
            rating.addProperty("severity", severityWire(v.severity))
            val score = cvssScoreFor(v.severity)
            if (score != null) {
                rating.addProperty("method", "CVSSv3.1")
                rating.addProperty("score", score)
            }
            ratings.add(rating)
            obj.add("ratings", ratings)

            if (v.cwe > 0) {
                val cwes = JsonArray()
                cwes.add(v.cwe)
                obj.add("cwes", cwes)
            }

            obj.addProperty("description", v.message)

            v.fixSuggestion?.let {
                val rec = buildString {
                    append(it.title)
                    if (it.description.isNotBlank()) append(" — ").append(it.description)
                }
                if (rec.isNotBlank()) obj.addProperty("recommendation", rec)
            }

            val affects = JsonArray()
            val affected = JsonObject()
            affected.addProperty("ref", resolveAffectsRef(v, components, app))
            affects.add(affected)
            obj.add("affects", affects)

            arr.add(obj)
        }
        return arr
    }

    private fun vulnId(v: Vulnerability): String {
        for (tag in v.tags) {
            val t = tag.trim()
            if (t.startsWith("CVE-", ignoreCase = true)) return t.uppercase()
        }
        return if (v.cwe > 0) "CWE-${v.cwe}" else v.ruleId
    }

    private fun severityWire(s: Severity): String = when (s) {
        Severity.CRITICAL -> "critical"
        Severity.HIGH -> "high"
        Severity.MEDIUM -> "medium"
        Severity.LOW -> "low"
        Severity.INFO -> "info"
    }

    private fun cvssScoreFor(s: Severity): Double? = when (s) {
        Severity.CRITICAL -> 9.8
        Severity.HIGH -> 7.5
        Severity.MEDIUM -> 5.3
        Severity.LOW -> 3.1
        Severity.INFO -> null
    }

    private fun resolveAffectsRef(
        v: Vulnerability,
        components: List<Component>,
        app: AppMetadata
    ): String {
        val path = v.filePath
        if (path.isNotBlank()) {
            val match = components.firstOrNull { c ->
                val token = c.name.substringAfterLast(':').substringAfterLast('/')
                token.isNotBlank() && path.contains(token, ignoreCase = true)
            }
            if (match != null) return match.bomRef
        }
        return app.bomRef
    }
}
