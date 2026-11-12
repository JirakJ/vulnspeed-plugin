/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.cli

import com.jakubjirak.vulnspeed.baseline.VulnFindingsJson
import com.jakubjirak.vulnspeed.core.HeadlessProjectScanner
import com.jakubjirak.vulnspeed.core.HeadlessScanOutcome
import com.jakubjirak.vulnspeed.core.ScanPolicy
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.report.SarifReportExporter
import java.io.IOException
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Headless project scan: runs the VulnSpeed rules over a directory on disk and
 * writes the findings as JSON (the input of `baseline` and `enrich`) and/or SARIF.
 *
 * Usage:
 * ```
 * scan --project=<dir> [--out-json=<file>] [--out-sarif=<file>]
 *      [--fail-on=severity:LOW|MEDIUM|HIGH|CRITICAL]
 *      [--max-file-size-kb=<n>] [--max-files=<n>]
 * ```
 *
 * Exit codes: `0` success, `1` bad arguments / IO error, `2` `--fail-on` threshold met.
 */
object VulnScanCli {

    /** Execute the scan and return the exit code. [toolVersion] is written into the SARIF report. */
    fun run(args: Array<String>, out: PrintStream, err: PrintStream, toolVersion: String): Int {
        val parsed = try {
            Args.parse(args)
        } catch (e: IllegalArgumentException) {
            err.println("vulnspeed scan: ${e.message}")
            printUsage(err)
            return 1
        }
        if (!Files.isDirectory(parsed.project)) {
            err.println("vulnspeed scan: --project is not a directory: ${parsed.project}")
            return 1
        }

        val root = parsed.project.toAbsolutePath().normalize()
        val outcome = HeadlessProjectScanner(maxFileSizeKb = parsed.maxFileSizeKb, maxFiles = parsed.maxFiles).scan(root)
        val findings = outcome.result.vulnerabilities

        try {
            parsed.outJson?.let {
                VulnFindingsJson.write(findings, it)
                out.println("Wrote ${findings.size} findings to $it")
            }
            parsed.outSarif?.let {
                val sarif = SarifReportExporter().export(findings, toolVersion, root.toString())
                Files.createDirectories(it.toAbsolutePath().parent ?: it.fileSystem.getPath("."))
                Files.write(it, sarif.toByteArray(StandardCharsets.UTF_8))
                out.println("Wrote SARIF report to $it")
            }
        } catch (e: IOException) {
            err.println("vulnspeed scan: IO error: ${e.message}")
            return 1
        }

        printSummary(outcome, out, err, parsed)
        return exitCode(findings, parsed.failOn, err)
    }

    private fun exitCode(findings: List<Vulnerability>, threshold: Severity?, err: PrintStream): Int {
        val matching = threshold?.let { countAtOrAbove(findings, it) } ?: 0
        if (matching == 0) return 0
        err.println("vulnspeed scan: --fail-on=severity:${threshold?.name} triggered by $matching finding(s)")
        return 2
    }

    /** Number of [findings] whose severity is [threshold] or more severe. */
    internal fun countAtOrAbove(findings: List<Vulnerability>, threshold: Severity): Int =
        findings.count { it.severity.ordinal <= threshold.ordinal }

    private fun printSummary(outcome: HeadlessScanOutcome, out: PrintStream, err: PrintStream, args: Args) {
        val stats = outcome.result.stats
        out.println(
            "Scanned ${stats.filesScanned} file(s), ${stats.linesOfCode} line(s): ${stats.totalVulns} finding(s) " +
                "(critical=${stats.criticalCount}, high=${stats.highCount}, " +
                "medium=${stats.mediumCount}, low=${stats.lowCount})"
        )
        if (outcome.filesSkippedTooLarge > 0) {
            err.println(
                "vulnspeed scan: skipped ${outcome.filesSkippedTooLarge} file(s) larger than ${args.maxFileSizeKb} KB"
            )
        }
        if (outcome.filesUnreadable > 0) {
            err.println("vulnspeed scan: could not read ${outcome.filesUnreadable} file(s)")
        }
        if (outcome.truncated) {
            err.println(
                "vulnspeed scan: found ${outcome.filesFound} files, scanned only the first ${args.maxFiles} " +
                    "(raise --max-files to scan more)"
            )
        }
    }

    private fun printUsage(err: PrintStream) {
        err.println(
            """
            Usage:
              vulnspeed scan --project=<dir> [--out-json=<file>] [--out-sarif=<file>]
                             [--fail-on=severity:LOW|MEDIUM|HIGH|CRITICAL]
                             [--max-file-size-kb=<n>] [--max-files=<n>]
            """.trimIndent()
        )
    }

    /** Parsed `scan` arguments. */
    internal data class Args(
        val project: Path,
        val outJson: Path?,
        val outSarif: Path?,
        val failOn: Severity?,
        val maxFileSizeKb: Int,
        val maxFiles: Int,
    ) {
        companion object {
            fun parse(argv: Array<String>): Args {
                var project: Path? = null
                var outJson: Path? = null
                var outSarif: Path? = null
                var failOn: Severity? = null
                var maxFileSizeKb = ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB
                var maxFiles = ScanPolicy.MAX_FILES_PER_SCAN

                for (raw in argv) {
                    when {
                        raw.startsWith("--project=") -> project = Paths.get(raw.removePrefix("--project="))
                        raw.startsWith("--out-json=") -> outJson = Paths.get(raw.removePrefix("--out-json="))
                        raw.startsWith("--out-sarif=") -> outSarif = Paths.get(raw.removePrefix("--out-sarif="))
                        raw.startsWith("--fail-on=") -> failOn = parseFailOn(raw.removePrefix("--fail-on="))
                        raw.startsWith("--max-file-size-kb=") ->
                            maxFileSizeKb = positiveInt("--max-file-size-kb", raw.removePrefix("--max-file-size-kb="))
                        raw.startsWith("--max-files=") ->
                            maxFiles = positiveInt("--max-files", raw.removePrefix("--max-files="))
                        else -> throw IllegalArgumentException("Unrecognised argument: $raw")
                    }
                }
                val projectPath = requireNotNull(project) { "--project=<dir> is required" }
                return Args(projectPath, outJson, outSarif, failOn, maxFileSizeKb, maxFiles)
            }

            /** Accepts `severity:<LEVEL>` (the same form the baseline CLI uses). */
            fun parseFailOn(raw: String): Severity {
                require(raw.startsWith("severity:", ignoreCase = true)) {
                    "--fail-on must be severity:LOW|MEDIUM|HIGH|CRITICAL, got: $raw"
                }
                val name = raw.substringAfter(':').trim().uppercase()
                return Severity.entries.firstOrNull { it.name == name }
                    ?: throw IllegalArgumentException("Unknown severity in --fail-on: $name")
            }

            private fun positiveInt(flag: String, raw: String): Int {
                val value = raw.toIntOrNull()
                require(value != null && value > 0) { "$flag must be a positive integer, got: $raw" }
                return value
            }
        }
    }
}
