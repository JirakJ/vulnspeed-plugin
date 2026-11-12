/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.model.Vulnerability
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID

/**
 * Outcome of a headless project scan.
 *
 * @property result findings and statistics, in the same shape the IDE produces.
 * @property filesFound scannable files found below the project root.
 * @property filesSkippedTooLarge files skipped because they exceed the max file size.
 * @property filesUnreadable files that could not be read.
 * @property truncated true when more than `maxFiles` files were found and only the first were scanned.
 */
data class HeadlessScanOutcome(
    val result: ScanResult,
    val filesFound: Int,
    val filesSkippedTooLarge: Int,
    val filesUnreadable: Int,
    val truncated: Boolean,
)

/**
 * Scans a project directory on disk without the IntelliJ platform, using the same
 * rules ([RuleScanner]), file selection ([ProjectFileWalker]), max-file-size limit
 * and `vulnspeed-ignore` suppression comments as the IDE plugin.
 *
 * File paths in the findings are absolute, normalised and use `/` separators,
 * matching what the IDE writes; baseline fingerprints and SARIF locations make
 * them project-relative.
 */
class HeadlessProjectScanner(
    private val scanner: RuleScanner = RuleScanner(),
    private val maxFileSizeKb: Int = ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB,
    private val maxFiles: Int = ScanPolicy.MAX_FILES_PER_SCAN,
) {

    /** Scans every supported file below [projectRoot]. */
    fun scan(projectRoot: Path): HeadlessScanOutcome {
        val startTime = System.currentTimeMillis()
        val found = ProjectFileWalker.collect(projectRoot.toAbsolutePath().normalize())
        val selected = found.take(maxFiles.coerceAtLeast(1))

        val findings = mutableListOf<Vulnerability>()
        var filesScanned = 0
        var linesOfCode = 0L
        var tooLarge = 0
        var unreadable = 0

        for (file in selected) {
            when (val fileResult = scanFile(file)) {
                FileResult.TooLarge -> tooLarge++
                FileResult.Unreadable -> unreadable++
                is FileResult.Scanned -> {
                    findings.addAll(fileResult.result.vulnerabilities)
                    filesScanned += fileResult.result.stats.filesScanned
                    linesOfCode += fileResult.result.stats.linesOfCode
                }
            }
        }

        findings.sortWith(
            compareBy<Vulnerability>({ it.severity.ordinal }, { it.filePath }, { it.line }, { it.column }, { it.ruleId })
        )
        val endTime = System.currentTimeMillis()
        val result = ScanResult(
            scanId = UUID.randomUUID().toString(),
            timestamp = endTime,
            durationMs = endTime - startTime,
            vulnerabilities = findings,
            stats = statsFor(findings, filesScanned, linesOfCode),
        )
        return HeadlessScanOutcome(
            result = result,
            filesFound = found.size,
            filesSkippedTooLarge = tooLarge,
            filesUnreadable = unreadable,
            truncated = found.size > selected.size,
        )
    }

    private fun scanFile(file: Path): FileResult {
        return try {
            // Cheap pre-check on the on-disk size before reading the file.
            if (ScanPolicy.isTooLarge(Files.size(file), maxFileSizeKb)) return FileResult.TooLarge
            val content = String(Files.readAllBytes(file), StandardCharsets.UTF_8)
            val path = file.toAbsolutePath().normalize().toString().replace('\\', '/')
            val result = scanner.scanContent(content, path, RuleScanner.languageFor(file.fileName.toString()), maxFileSizeKb)
            if (result.stats.filesScanned == 0) FileResult.TooLarge else FileResult.Scanned(result)
        } catch (ignored: IOException) {
            FileResult.Unreadable
        }
    }

    private sealed interface FileResult {
        data object TooLarge : FileResult
        data object Unreadable : FileResult
        data class Scanned(val result: ScanResult) : FileResult
    }
}
