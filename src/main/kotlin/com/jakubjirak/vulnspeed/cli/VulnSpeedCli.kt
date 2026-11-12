/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.cli

import com.jakubjirak.vulnspeed.baseline.VulnBaselineCli
import com.jakubjirak.vulnspeed.enrichment.CveEnrichmentCli
import java.io.PrintStream

/**
 * Entry point of the standalone `vulnspeed-cli-<version>.jar` (published with
 * every GitHub release). Dispatches to the sub-commands:
 *
 * * `scan`     — scan a project directory, write findings JSON and/or SARIF ([VulnScanCli])
 * * `baseline` — create or compare a security baseline from findings JSON ([VulnBaselineCli])
 * * `enrich`   — enrich findings JSON with OSV / NVD CVE metadata ([CveEnrichmentCli])
 * * `version`  — print the tool version
 */
object VulnSpeedCli {

    /** Version from the jar manifest (`Implementation-Version`), or `dev` when run from classes. */
    val version: String
        get() = VulnSpeedCli::class.java.`package`?.implementationVersion ?: "dev"

    @JvmStatic
    fun main(args: Array<String>) {
        val code = run(args, System.out, System.err)
        if (code != 0) kotlin.system.exitProcess(code)
    }

    /** Dispatch [args] and return the exit code (`0` ok, `1` usage / IO error, `2` policy triggered). */
    fun run(args: Array<String>, out: PrintStream, err: PrintStream): Int {
        val command = args.firstOrNull()
        val rest = args.drop(1).toTypedArray()
        return when (command) {
            "scan" -> VulnScanCli.run(rest, out, err, version)
            // A later --tool-version given by the user overrides this default.
            "baseline" -> VulnBaselineCli.run(arrayOf("--tool-version=$version") + rest, out, err)
            "enrich" -> CveEnrichmentCli.run(rest, out, err, CveEnrichmentCli::defaultEnricher)
            "version", "--version" -> {
                out.println("vulnspeed-cli $version")
                0
            }
            "help", "--help", "-h" -> {
                printUsage(out)
                0
            }
            else -> {
                if (command != null) err.println("vulnspeed: unknown command: $command")
                printUsage(err)
                1
            }
        }
    }

    private fun printUsage(stream: PrintStream) {
        stream.println(
            """
            VulnSpeed CLI $version

            Usage: java -jar vulnspeed-cli.jar <command> [options]

            Commands:
              scan      --project=<dir> [--out-json=<file>] [--out-sarif=<file>] [--fail-on=severity:HIGH]
                        [--max-file-size-kb=<n>] [--max-files=<n>]
              baseline  --create  --project=<dir> --findings=<file> [--baseline=<file>] [--reason=<text>]
              baseline  --compare --project=<dir> --findings=<file> [--baseline=<file>] [--output=md|json]
                        [--output-file=<file>] [--fail-on=regression|severity:HIGH]
              enrich    --findings=<file> [--out=<file>] [--format=json|md] [--offline] [--cache-dir=<dir>]
                        [--max-age-days=<n>] [--nvd-key=<key>] [--fail-on-severity=HIGH]
              version   print the version

            Exit codes: 0 success, 1 bad arguments or IO error, 2 --fail-on policy triggered.
            """.trimIndent()
        )
    }
}
