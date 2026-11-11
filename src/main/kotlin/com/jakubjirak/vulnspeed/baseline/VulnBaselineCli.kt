/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

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
 * Findings loader/writer for the CLI.
 *
 * The on-disk format is a JSON array of [Vulnerability] records matching the
 * shape used everywhere else in VulnSpeed. Intended to be produced by CI jobs
 * from the latest scan (`.idea/vulnspeed-findings.json` or similar) and then
 * consumed by the [VulnBaselineCli].
 */
object VulnFindingsJson {
    private val gson: Gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()
    private val listType = object : TypeToken<List<Vulnerability>>() {}.type

    /** Read a findings JSON document from [path]. */
    @Throws(IOException::class)
    fun read(path: Path): List<Vulnerability> {
        val text = Files.readString(path, StandardCharsets.UTF_8)
        return try {
            gson.fromJson<List<Vulnerability>>(text, listType) ?: emptyList()
        } catch (e: JsonSyntaxException) {
            throw IOException("Malformed findings JSON at $path: ${e.message}", e)
        }
    }

    /** Write [findings] to [path] as a JSON array. */
    @Throws(IOException::class)
    fun write(findings: List<Vulnerability>, path: Path) {
        val json = gson.toJson(findings, listType)
        Files.createDirectories(path.toAbsolutePath().parent ?: path.fileSystem.getPath("."))
        Files.write(path, json.toByteArray(StandardCharsets.UTF_8))
    }
}

/**
 * Threshold controlling when the CLI should return a non-zero exit code.
 */
sealed interface FailOnPolicy {
    /** Never fails the build purely on diff contents. */
    data object Never : FailOnPolicy

    /** Fails as soon as any new regression is detected. */
    data object AnyRegression : FailOnPolicy

    /** Fails when a new regression at [threshold] or higher severity is detected. */
    data class MinSeverity(val threshold: Severity) : FailOnPolicy

    companion object {
        /**
         * Parse the `--fail-on` value.
         *
         * Accepted forms: `regression`, `severity:HIGH`, `severity:CRITICAL`, etc.
         */
        fun parse(raw: String?): FailOnPolicy {
            if (raw.isNullOrBlank()) return Never
            val v = raw.trim()
            if (v.equals("regression", ignoreCase = true)) return AnyRegression
            if (v.startsWith("severity:", ignoreCase = true)) {
                val name = v.substringAfter(':').trim().uppercase()
                val sev = Severity.entries.firstOrNull { it.name == name }
                    ?: throw IllegalArgumentException("Unknown severity in --fail-on: $name")
                return MinSeverity(sev)
            }
            throw IllegalArgumentException("Unrecognised --fail-on value: $raw")
        }
    }
}

/**
 * IDE-free command-line entry point for baseline operations.
 *
 * Usage:
 * ```
 * --create  --project=<dir> [--baseline=<path>] --findings=<findings.json>
 *           [--tool-version=<v>] [--reason=<text>]
 * --compare --project=<dir> [--baseline=<path>] --findings=<findings.json>
 *           [--output=md|json] [--output-file=<path>] [--fail-on=...]
 * ```
 *
 * Exit codes:
 * * `0` — success, no regressions (or regressions below `--fail-on` threshold).
 * * `1` — bad arguments or IO failure.
 * * `2` — regressions matched the `--fail-on` policy.
 */
object VulnBaselineCli {

    private val gson: Gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()

    /** Process entry-point. */
    @JvmStatic
    fun main(args: Array<String>) {
        val code = run(args, System.out, System.err)
        if (code != 0) kotlin.system.exitProcess(code)
    }

    /**
     * Execute the CLI and return the exit code.
     *
     * Exposed so tests can assert behaviour without invoking [System.exit].
     */
    fun run(args: Array<String>, out: PrintStream, err: PrintStream): Int {
        val parsed: Args = try {
            Args.parse(args)
        } catch (e: IllegalArgumentException) {
            err.println("vulnspeed-baseline: ${e.message}")
            printUsage(err)
            return 1
        }
        return try {
            when (parsed.mode) {
                Mode.CREATE -> runCreate(parsed, out)
                Mode.COMPARE -> runCompare(parsed, out, err)
            }
        } catch (e: IOException) {
            err.println("vulnspeed-baseline: IO error: ${e.message}")
            1
        } catch (e: VulnBaselineIoException) {
            err.println("vulnspeed-baseline: baseline error: ${e.message}")
            1
        }
    }

    private fun runCreate(a: Args, out: PrintStream): Int {
        val root = a.project
        val findings = VulnFindingsJson.read(a.findings!!)
        val baseline = VulnBaseline.fromFindings(
            findings = findings,
            projectRoot = root,
            toolVersion = a.toolVersion,
            acceptedReason = a.reason,
        )
        val target = a.baseline ?: VulnBaselineStore.defaultPath(root)
        VulnBaselineStore.save(baseline, target)
        out.println("Wrote ${baseline.entries.size} entries to $target")
        return 0
    }

    private fun runCompare(a: Args, out: PrintStream, err: PrintStream): Int {
        val root = a.project
        val findings = VulnFindingsJson.read(a.findings!!)
        val baselinePath = a.baseline ?: VulnBaselineStore.defaultPath(root)
        val baseline = VulnBaselineStore.load(baselinePath)
        val diff = VulnBaselineDiffService.diff(baseline, findings, root)

        val rendered: String = when (a.output) {
            OutputFormat.JSON -> gson.toJson(
                mapOf(
                    "summary" to diff.summary,
                    "newFindings" to diff.newFindings,
                    "fixedEntries" to diff.fixedEntries,
                    "persistedFindings" to diff.persistedFindings,
                )
            )
            OutputFormat.MARKDOWN -> VulnBaselineMarkdown.render(diff, a.toolVersion)
        }
        if (a.outputFile != null) {
            Files.createDirectories(a.outputFile.toAbsolutePath().parent ?: a.outputFile.fileSystem.getPath("."))
            Files.write(a.outputFile, rendered.toByteArray(StandardCharsets.UTF_8))
        } else {
            out.println(rendered)
        }

        if (shouldFail(diff, a.failOn)) {
            err.println(
                "vulnspeed-baseline: policy ${a.failOn} triggered — " +
                    "new=${diff.summary.totalNew} fixed=${diff.summary.totalFixed} " +
                    "persisted=${diff.summary.totalPersisted}"
            )
            return 2
        }
        return 0
    }

    internal fun shouldFail(diff: VulnBaselineDiff, policy: FailOnPolicy): Boolean = when (policy) {
        FailOnPolicy.Never -> false
        FailOnPolicy.AnyRegression -> diff.hasRegressions()
        is FailOnPolicy.MinSeverity -> diff.summary.countAtOrAbove(policy.threshold) > 0
    }

    private fun printUsage(err: PrintStream) {
        err.println(
            """
            Usage:
              vulnspeed-baseline --create  --project=<dir> --findings=<file> [--baseline=<file>] [--tool-version=<v>] [--reason=<text>]
              vulnspeed-baseline --compare --project=<dir> --findings=<file> [--baseline=<file>] [--output=md|json]
                                 [--output-file=<file>] [--fail-on=regression|severity:HIGH]
            """.trimIndent()
        )
    }

    /** Whether the CLI is creating or comparing a baseline. */
    private enum class Mode { CREATE, COMPARE }

    /** Output format selector for the compare sub-command. */
    internal enum class OutputFormat { MARKDOWN, JSON }

    /** Immutable parsed argument set. */
    private data class Args(
        val mode: Mode,
        val project: Path,
        val findings: Path?,
        val baseline: Path?,
        val output: OutputFormat,
        val outputFile: Path?,
        val failOn: FailOnPolicy,
        val toolVersion: String,
        val reason: String?,
    ) {
        companion object {
            fun parse(argv: Array<String>): Args {
                var mode: Mode? = null
                var project: Path? = null
                var findings: Path? = null
                var baseline: Path? = null
                var output: OutputFormat = OutputFormat.MARKDOWN
                var outputFile: Path? = null
                var failOn: FailOnPolicy = FailOnPolicy.Never
                var toolVersion = "unknown"
                var reason: String? = null

                for (raw in argv) {
                    when {
                        raw == "--create" -> mode = assignMode(mode, Mode.CREATE)
                        raw == "--compare" -> mode = assignMode(mode, Mode.COMPARE)
                        raw.startsWith("--project=") -> project = Paths.get(raw.removePrefix("--project="))
                        raw.startsWith("--findings=") -> findings = Paths.get(raw.removePrefix("--findings="))
                        raw.startsWith("--baseline=") -> baseline = Paths.get(raw.removePrefix("--baseline="))
                        raw.startsWith("--output=") -> output = parseOutput(raw.removePrefix("--output="))
                        raw.startsWith("--output-file=") -> outputFile = Paths.get(raw.removePrefix("--output-file="))
                        raw.startsWith("--fail-on=") -> failOn = FailOnPolicy.parse(raw.removePrefix("--fail-on="))
                        raw.startsWith("--tool-version=") -> toolVersion = raw.removePrefix("--tool-version=")
                        raw.startsWith("--reason=") -> reason = raw.removePrefix("--reason=")
                        raw == "--help" || raw == "-h" ->
                            throw IllegalArgumentException("help requested")
                        else -> throw IllegalArgumentException("Unrecognised argument: $raw")
                    }
                }

                requireNotNull(mode) { "Must specify --create or --compare" }
                val projectPath = requireNotNull(project) { "--project is required" }
                requireNotNull(findings) { "--findings is required" }

                return Args(mode, projectPath, findings, baseline, output, outputFile, failOn, toolVersion, reason)
            }

            private fun assignMode(existing: Mode?, next: Mode): Mode {
                require(existing == null || existing == next) { "Cannot combine --create with --compare" }
                return next
            }

            private fun parseOutput(raw: String): OutputFormat = when (raw.lowercase()) {
                "md", "markdown" -> OutputFormat.MARKDOWN
                "json" -> OutputFormat.JSON
                else -> throw IllegalArgumentException("Unknown --output: $raw (expected md|json)")
            }
        }
    }
}
