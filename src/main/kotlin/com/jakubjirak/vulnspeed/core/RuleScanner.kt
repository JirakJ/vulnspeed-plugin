/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.FixSuggestion
import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.model.ScanStats
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * The VulnSpeed rule engine: runs every applicable regex rule over a file's text
 * and turns matches into [Vulnerability] records.
 *
 * Precision guards, applied per rule:
 * - a rule runs only on files of its [Rule.languages] (derived from the file name)
 * - [Rule.requiresInFile] / [Rule.excludeIfFileContains] gate a rule on file context
 * - comment lines and lines longer than [MAX_LINE_LENGTH] (minified / generated code)
 *   are skipped unless the rule sets [Rule.matchAnywhere] (secrets)
 * - [Rule.excludePattern] drops a matching line, [Rule.skipTestFiles] skips test sources
 * - a rule reports a line at most once, and when several rules with the same CWE hit
 *   one line only the most severe finding is kept
 * - `vulnspeed-ignore` suppression comments and the max-file-size limit are honoured
 *
 * Pure Kotlin with no IntelliJ platform dependency, so the IDE plugin
 * ([VulnSpeedEngine]) and the headless CLI ([HeadlessProjectScanner]) share
 * exactly the same rules and behaviour.
 *
 * @param onRuleError receives a message when a rule throws while matching; the
 *                    rule is skipped and scanning continues.
 */
class RuleScanner(private val onRuleError: (String) -> Unit = {}) {

    /** Every rule shipped with VulnSpeed, in declaration order. */
    val rules: List<Rule> = loadDefaultRules()

    private val enabledRules: List<Rule> = rules.filter { it.enabled }

    private val regexCache = ConcurrentHashMap<String, Regex>()

    /**
     * Scans [content] with every enabled rule that applies to [language]. Content larger
     * than [maxFileSizeKb] (the "Max file size" setting) is skipped and reported as 0 files scanned.
     */
    fun scanContent(content: String, filePath: String, language: String, maxFileSizeKb: Int): ScanResult {
        val startTime = System.currentTimeMillis()
        if (ScanPolicy.isTooLarge(content.length.toLong(), maxFileSizeKb)) {
            return emptyScanResult(startTime)
        }

        val file = FileContext(content, filePath, language)
        val vulnerabilities = if (SuppressionDirectives.isFileSuppressed(file.lines)) {
            mutableListOf()
        } else {
            enabledRules.flatMapTo(mutableListOf()) { scanWithRule(file, it) }
        }
        val deduplicated = deduplicate(vulnerabilities).sortedWith(compareBy({ it.severity.ordinal }, { it.line }))

        val endTime = System.currentTimeMillis()
        return ScanResult(
            scanId = UUID.randomUUID().toString(),
            timestamp = endTime,
            durationMs = endTime - startTime,
            vulnerabilities = deduplicated,
            stats = statsFor(deduplicated, filesScanned = 1, linesOfCode = file.lines.size.toLong()),
        )
    }

    /** Lines, comment mask and test-file flag of one file, computed once and shared by all rules. */
    private class FileContext(val content: String, val filePath: String, val language: String) {
        val lines: List<String> = content.lines()
        val commentLines: BooleanArray by lazy { CommentLines.mask(lines, language) }
        val isTestFile: Boolean by lazy { SourceLanguages.isTestPath(filePath) }
    }

    /** Runs a single [rule] over [content]; used by tests to exercise one rule in isolation. */
    private fun scanWithRule(content: String, filePath: String, rule: Rule, language: String): List<Vulnerability> {
        val file = FileContext(content, filePath, language)
        if (SuppressionDirectives.isFileSuppressed(file.lines)) return emptyList()
        return scanWithRule(file, rule)
    }

    private fun scanWithRule(file: FileContext, rule: Rule): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()
        try {
            if (!applies(rule, file)) return emptyList()
            val regex = compiled(rule.pattern)
            val exclude = rule.excludePattern?.let { compiled(it) }

            file.lines.forEachIndexed { lineNum, line ->
                if (!rule.matchAnywhere && (line.length > MAX_LINE_LENGTH || file.commentLines[lineNum])) return@forEachIndexed
                val match = regex.find(line) ?: return@forEachIndexed
                if (exclude != null && exclude.containsMatchIn(line)) return@forEachIndexed
                if (SuppressionDirectives.isSuppressed(file.lines, lineNum, rule.id)) return@forEachIndexed
                vulns.add(toVulnerability(rule, file, lineNum, line, match.range))
            }
        } catch (e: IllegalArgumentException) {
            onRuleError("VulnSpeed rule ${rule.id} failed: ${e.message}")
        } catch (e: StackOverflowError) {
            onRuleError("VulnSpeed rule ${rule.id} failed: regex backtracking overflow (${e.javaClass.simpleName})")
        }
        return vulns
    }

    private fun applies(rule: Rule, file: FileContext): Boolean {
        if (rule.languages.isNotEmpty() && file.language !in rule.languages) return false
        if (rule.skipTestFiles && file.isTestFile) return false
        if (rule.requiresInFile != null && !compiled(rule.requiresInFile).containsMatchIn(file.content)) return false
        return rule.excludeIfFileContains == null || !compiled(rule.excludeIfFileContains).containsMatchIn(file.content)
    }

    private fun compiled(pattern: String): Regex = regexCache.getOrPut(pattern) { Regex(pattern, RegexOption.MULTILINE) }

    private fun toVulnerability(rule: Rule, file: FileContext, lineNum: Int, line: String, range: IntRange) = Vulnerability(
        id = UUID.randomUUID().toString(),
        ruleId = rule.id,
        ruleName = rule.name,
        type = parseVulnType(rule.id),
        severity = rule.severity,
        cwe = rule.cwe,
        filePath = file.filePath,
        line = lineNum + 1,
        column = range.first + 1,
        message = rule.description,
        codeSnippet = line.substring(maxOf(0, range.first - SNIPPET_CONTEXT), minOf(line.length, range.last + 1 + SNIPPET_CONTEXT)),
        confidence = DEFAULT_CONFIDENCE,
        owasp = rule.owasp,
        fixSuggestion = generateFixSuggestion(rule),
        tags = listOf(file.language, rule.id),
    )

    /**
     * Keeps one finding per (line, CWE): when e.g. a generic and a vendor-specific
     * credential rule both hit the same line, the most severe (then first declared) wins.
     */
    private fun deduplicate(findings: List<Vulnerability>): List<Vulnerability> =
        findings.groupBy { it.line to it.cwe }.values.map { group -> group.minBy { it.severity.ordinal } }

    private fun generateFixSuggestion(rule: Rule): FixSuggestion? = FixSuggestions.forRule(rule.id)

    private fun parseVulnType(ruleId: String): VulnerabilityType = FixSuggestions.typeOf(ruleId)

    private fun loadDefaultRules(): List<Rule> = SecretsRules.RULES + BuiltInRules.RULES

    companion object {
        /** Lines longer than this are treated as minified / generated and skipped by non-secret rules. */
        const val MAX_LINE_LENGTH = 1000

        private const val SNIPPET_CONTEXT = 10
        private const val DEFAULT_CONFIDENCE = 0.85f

        /** Language tag used to scope rules and tag findings, derived from the file name. */
        fun languageFor(fileName: String): String = SourceLanguages.languageFor(fileName)
    }
}

/** Aggregates per-severity counts for [vulnerabilities]. */
fun statsFor(vulnerabilities: List<Vulnerability>, filesScanned: Int, linesOfCode: Long): ScanStats = ScanStats(
    totalVulns = vulnerabilities.size,
    criticalCount = vulnerabilities.count { it.severity == Severity.CRITICAL },
    highCount = vulnerabilities.count { it.severity == Severity.HIGH },
    mediumCount = vulnerabilities.count { it.severity == Severity.MEDIUM },
    lowCount = vulnerabilities.count { it.severity == Severity.LOW },
    filesScanned = filesScanned,
    linesOfCode = linesOfCode,
)

/** Result for a file that was not scanned (no document, or above the max file size). */
fun emptyScanResult(startTime: Long): ScanResult = ScanResult(
    scanId = UUID.randomUUID().toString(),
    timestamp = System.currentTimeMillis(),
    durationMs = System.currentTimeMillis() - startTime,
    vulnerabilities = emptyList(),
    stats = ScanStats(0, 0, 0, 0, 0, 0, 0),
)
