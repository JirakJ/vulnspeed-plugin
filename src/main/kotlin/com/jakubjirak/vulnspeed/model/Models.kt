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

data class DeviceInfo(
    val backend: String,
    val deviceName: String,
    val computeUnits: Int,
    val maxMemoryMb: Long,
    val supportsFloat64: Boolean
)

data class Rule(
    val id: String,
    val name: String,
    val description: String,
    val severity: Severity,
    val cwe: Int,
    val owasp: String,
    val pattern: String,
    val enabled: Boolean = true
)
