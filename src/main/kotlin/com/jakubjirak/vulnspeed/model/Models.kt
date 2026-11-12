package com.jakubjirak.vulnspeed.model



enum class Severity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO
}

enum class VulnerabilityType {
    SQL_INJECTION,
    XSS,
    AUTHENTICATION,
    SENSITIVE_DATA,
    XXE,
    ACCESS_CONTROL,
    MISCONFIG,
    INSECURE_DESERIALIZATION,
    VULNERABLE_COMPONENTS,
    INSUFFICIENT_LOGGING,
    WEAK_CRYPTO,
    BUFFER_OVERFLOW,
    USE_AFTER_FREE,
    COMMAND_INJECTION,
    PATH_TRAVERSAL,
    CSRF,
    INSECURE_DEPENDENCY,
    HARDCODED_CREDENTIALS,
    INSECURE_RANDOMNESS,
    INFORMATION_DISCLOSURE,
    // New types for v2025.5.0 features
    CODE_INJECTION,
    SENSITIVE_DATA_EXPOSURE,
    SECURITY_MISCONFIGURATION,
    SECRET_EXPOSURE,
    IAC_VULNERABILITY,
    API_SECURITY,
    COMPLIANCE_VIOLATION
}

data class Vulnerability(
    val id: String,
    val ruleId: String,
    val ruleName: String,
    val type: VulnerabilityType,
    val severity: Severity,
    val cwe: Int,
    val filePath: String,
    val line: Int,
    val column: Int,
    val message: String,
    val codeSnippet: String,
    val confidence: Float = 1.0f,
    val owasp: String = "",
    val fixSuggestion: FixSuggestion? = null,
    val isFalsePositive: Boolean = false,
    val tags: List<String> = emptyList()
)

data class FixSuggestion(
    val title: String,
    val description: String,
    val code: String,
    val references: List<String> = emptyList()
)

data class ScanResult(
    val scanId: String,
    val timestamp: Long,
    val durationMs: Long,
    val vulnerabilities: List<Vulnerability>,
    val stats: ScanStats
)

data class ScanStats(
    val totalVulns: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val filesScanned: Int,
    val linesOfCode: Long
)

/**
 * A regex rule. [pattern] is matched line by line; the optional fields narrow
 * where it applies so it only reports code it can meaningfully judge.
 *
 * @property languages language tags (see `SourceLanguages`) the rule applies to; empty = every scanned file.
 * @property excludePattern a line that also matches this regex is not reported (e.g. a sanitizer on the same line).
 * @property requiresInFile the rule only runs on files that contain a match for this regex somewhere.
 * @property excludeIfFileContains the rule is skipped for files that contain a match for this regex (e.g. a hardening call).
 * @property matchAnywhere also match inside comments and in very long (minified/generated) lines — used for secrets.
 * @property skipTestFiles the rule does not run on test sources (test fixtures routinely use fake credentials, weak TLS, …).
 */
data class Rule(
    val id: String,
    val name: String,
    val description: String,
    val severity: Severity,
    val cwe: Int,
    val owasp: String,
    val pattern: String,
    val enabled: Boolean = true,
    val languages: Set<String> = emptySet(),
    val excludePattern: String? = null,
    val requiresInFile: String? = null,
    val excludeIfFileContains: String? = null,
    val matchAnywhere: Boolean = false,
    val skipTestFiles: Boolean = false,
)
