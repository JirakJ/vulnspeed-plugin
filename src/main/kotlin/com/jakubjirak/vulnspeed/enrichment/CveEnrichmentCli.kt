/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import java.io.IOException
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * IDE-free CLI for the CVE enrichment layer.
 *
 * Usage:
 * ```
 * --findings=<file.json> [--out=<file>] [--format=json|md]
 *   [--offline] [--cache-dir=<dir>] [--max-age-days=<n>]
 *   [--nvd-key=<key>] [--fail-on-severity=LOW|MEDIUM|HIGH|CRITICAL]
 * ```
 *
 * Exit codes:
 *   * `0` — success, no findings at/above `--fail-on-severity` threshold.
 *   * `1` — bad arguments / IO error.
 *   * `2` — `--fail-on-severity` threshold triggered.
 */
object CveEnrichmentCli {

    private val gson: Gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()
    private val listType = object : TypeToken<List<Vulnerability>>() {}.type

    @JvmStatic
    fun main(args: Array<String>) {
        val code = run(args, System.out, System.err, enricherFactory = ::defaultEnricher)
        if (code != 0) kotlin.system.exitProcess(code)
    }

    /**
     * Run the CLI and return the exit code. Exposed for tests with an injected
     * [enricherFactory] so no network calls are made during tests.
     */
    fun run(
        args: Array<String>,
        out: PrintStream,
        err: PrintStream,
        enricherFactory: (EnrichmentPolicy, Path) -> CveEnricher,
    ): Int {
        val parsed = try {
            Args.parse(args)
        } catch (e: IllegalArgumentException) {
            err.println("vulnspeed-enrich: ${e.message}")
            printUsage(err)
            return 1
        }

        return try {
            val findings = readFindings(parsed.findings)
            val cacheDir = parsed.cacheDir ?: defaultCacheDir()
            val policy = EnrichmentPolicy(
                offline = parsed.offline,
                maxAgeDays = parsed.maxAgeDays,
                preferOsv = true,
                nvdApiKey = parsed.nvdApiKey ?: System.getenv("NVD_API_KEY"),
            )
            val enricher = enricherFactory(policy, cacheDir)
            val enriched = enricher.enrich(findings)

            val rendered = when (parsed.format) {
                OutputFormat.JSON -> renderJson(enriched)
                OutputFormat.MARKDOWN -> EnrichedMarkdownReporter.render(enriched)
            }

            if (parsed.outFile != null) {
                Files.createDirectories(
                    parsed.outFile.toAbsolutePath().parent ?: parsed.outFile.fileSystem.getPath(".")
                )
                Files.write(parsed.outFile, rendered.toByteArray(StandardCharsets.UTF_8))
                out.println("Wrote ${enriched.size} findings to ${parsed.outFile}")
            } else {
                out.println(rendered)
            }

            if (shouldFail(enriched, parsed.failOnSeverity)) {
                err.println(
                    "vulnspeed-enrich: fail-on-severity=${parsed.failOnSeverity} triggered"
                )
                return 2
            }
            0
        } catch (e: IOException) {
            err.println("vulnspeed-enrich: IO error: ${e.message}")
            1
        } catch (e: JsonSyntaxException) {
            err.println("vulnspeed-enrich: malformed findings JSON: ${e.message}")
            1
        }
    }

    internal fun renderJson(enriched: List<EnrichedVulnerability>): String =
        gson.toJson(enriched.map {
            mapOf(
                "vulnerability" to it.vulnerability,
                "metadata" to it.metadata,
            )
        })

    internal fun shouldFail(enriched: List<EnrichedVulnerability>, threshold: Severity?): Boolean {
        if (threshold == null) return false
        val order = listOf(Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        val thresholdIdx = order.indexOf(threshold)
        return enriched.any { order.indexOf(it.vulnerability.severity) >= thresholdIdx }
    }

    private fun readFindings(path: Path): List<Vulnerability> {
        val text = Files.readString(path, StandardCharsets.UTF_8)
        return gson.fromJson<List<Vulnerability>>(text, listType) ?: emptyList()
    }

    private fun defaultCacheDir(): Path {
        val home = System.getProperty("user.home") ?: "."
        return Paths.get(home, ".vulnspeed", "cve-cache")
    }

    private fun defaultEnricher(policy: EnrichmentPolicy, cacheDir: Path): CveEnricher {
        val cache = CveMetadataCache(cacheDir)
        val osv = OsvClient(policy = policy)
        val nvd = NvdClient(policy = policy)
        return CveEnricher(cache, osv, nvd, policy)
    }

    private fun printUsage(err: PrintStream) {
        err.println(
            """
            Usage:
              vulnspeed-enrich --findings=<file.json> [--out=<file>] [--format=json|md]
                               [--offline] [--cache-dir=<dir>] [--max-age-days=<n>]
                               [--nvd-key=<key>] [--fail-on-severity=LOW|MEDIUM|HIGH|CRITICAL]
            """.trimIndent()
        )
    }

    internal enum class OutputFormat { JSON, MARKDOWN }

    internal data class Args(
        val findings: Path,
        val outFile: Path?,
        val format: OutputFormat,
        val offline: Boolean,
        val cacheDir: Path?,
        val maxAgeDays: Int,
        val nvdApiKey: String?,
        val failOnSeverity: Severity?,
    ) {
        companion object {
            fun parse(argv: Array<String>): Args {
                var findings: Path? = null
                var outFile: Path? = null
                var format = OutputFormat.JSON
                var offline = false
                var cacheDir: Path? = null
                var maxAgeDays = 7
                var nvdApiKey: String? = null
                var failOnSeverity: Severity? = null

                for (raw in argv) {
                    when {
                        raw.startsWith("--findings=") -> findings = Paths.get(raw.removePrefix("--findings="))
                        raw.startsWith("--out=") -> outFile = Paths.get(raw.removePrefix("--out="))
                        raw.startsWith("--format=") -> format = parseFormat(raw.removePrefix("--format="))
                        raw == "--offline" -> offline = true
                        raw.startsWith("--cache-dir=") -> cacheDir = Paths.get(raw.removePrefix("--cache-dir="))
                        raw.startsWith("--max-age-days=") -> maxAgeDays =
                            raw.removePrefix("--max-age-days=").toIntOrNull()
                                ?: throw IllegalArgumentException("--max-age-days must be an integer")
                        raw.startsWith("--nvd-key=") -> nvdApiKey = raw.removePrefix("--nvd-key=").ifBlank { null }
                        raw.startsWith("--fail-on-severity=") -> failOnSeverity =
                            parseSeverity(raw.removePrefix("--fail-on-severity="))
                        raw == "--help" || raw == "-h" ->
                            throw IllegalArgumentException("help requested")
                        else -> throw IllegalArgumentException("Unknown argument: $raw")
                    }
                }
                require(findings != null) { "--findings=<path> is required" }
                require(maxAgeDays >= 0) { "--max-age-days must be non-negative" }
                return Args(findings, outFile, format, offline, cacheDir, maxAgeDays, nvdApiKey, failOnSeverity)
            }

            private fun parseFormat(raw: String): OutputFormat = when (raw.lowercase()) {
                "json" -> OutputFormat.JSON
                "md", "markdown" -> OutputFormat.MARKDOWN
                else -> throw IllegalArgumentException("--format must be json or md")
            }

            private fun parseSeverity(raw: String): Severity {
                val name = raw.trim().uppercase()
                return Severity.entries.firstOrNull { it.name == name }
                    ?: throw IllegalArgumentException("Unknown severity: $raw")
            }
        }
    }
}
