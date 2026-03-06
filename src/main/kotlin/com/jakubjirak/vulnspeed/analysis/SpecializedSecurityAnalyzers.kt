package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.Severity

/**
 * Specialized Security Analyzers for VulnSpeed v2025.10.0
 * 
 * New Features:
 * - Memory Safety Analysis (buffer overflow, use-after-free, memory corruption)
 * - Firmware Security Scan (IoT/embedded vulnerabilities)
 * - Blockchain Smart Contract Auditing (Solidity, Rust)
 * - OAuth/OIDC Misconfiguration Detection
 * - Cryptographic Agility Analysis
 * - Sidecar Proxy Security (Envoy, Istio)
 * - Edge Computing Security
 */
class SpecializedSecurityAnalyzers {

    /**
     * Memory Safety Analysis
     * Detects buffer overflows, use-after-free, memory corruption vulnerabilities
     */
    fun analyzeMemorySafety(content: String, filePath: String): MemorySafetyReport {

        val vulnerabilities = mutableListOf<MemoryVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val memoryPatterns = listOf(
            // C/C++ patterns
            MemPattern("BUFFER_OVERFLOW", """strcpy\s*\(|strcat\s*\(|sprintf\s*\(|gets\s*\(""",
                "Unsafe string function - potential buffer overflow", Severity.CRITICAL, "C/C++"),
            MemPattern("FORMAT_STRING", """printf\s*\(\s*[^"]\w+\s*\)|sprintf\s*\([^,]+,\s*[^"]\w+\s*\)""",
                "Format string vulnerability - user input in format specifier", Severity.CRITICAL, "C/C++"),
            MemPattern("USE_AFTER_FREE", """free\s*\([^)]+\)[^}]*\1|delete\s+\w+[^}]*\1->|delete\[\]\s+\w+""",
                "Potential use-after-free - memory accessed after deallocation", Severity.CRITICAL, "C/C++"),
            MemPattern("DOUBLE_FREE", """free\s*\(\s*(\w+)\s*\)[^}]*free\s*\(\s*\1\s*\)""",
                "Double free vulnerability detected", Severity.CRITICAL, "C/C++"),
            MemPattern("UNINITIALIZED_MEMORY", """(int|char|void\s*\*)\s+\w+\s*;[^=]*\w+\s*[+\-*/]""",
                "Potentially uninitialized variable used", Severity.HIGH, "C/C++"),
            MemPattern("INTEGER_OVERFLOW", """malloc\s*\([^)]*\*[^)]*\)|alloc.*size\s*\*""",
                "Potential integer overflow in allocation size", Severity.HIGH, "C/C++"),
            MemPattern("NULL_DEREF", """\*\s*\w+\s*=[^}]*if\s*\(\s*\w+\s*==\s*NULL""",
                "Potential null pointer dereference before check", Severity.HIGH, "C/C++"),
            // Rust patterns (unsafe blocks)
            MemPattern("UNSAFE_RUST", """unsafe\s*\{[^}]*\*\s*(mut\s+)?\w+""",
                "Raw pointer dereference in unsafe block", Severity.MEDIUM, "Rust"),
            MemPattern("RUST_TRANSMUTE", """mem::transmute|std::mem::transmute""",
                "Use of transmute - bypasses type safety", Severity.HIGH, "Rust"),
            // Go patterns
            MemPattern("GO_CGO_UNSAFE", """C\.\w+|unsafe\.Pointer""",
                "CGO or unsafe pointer usage in Go", Severity.MEDIUM, "Go")
        )

        lines.forEachIndexed { index, line ->
            memoryPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(MemoryVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity,
                        pattern.language
                    ))
                }
            }
        }

        // Calculate memory safety score
        val criticalCount = vulnerabilities.count { it.severity == Severity.CRITICAL }
        val highCount = vulnerabilities.count { it.severity == Severity.HIGH }
        val safetyScore = (100.0 - criticalCount * 20 - highCount * 10).coerceIn(0.0, 100.0)

        recommendations.add("Use memory-safe alternatives (strncpy, snprintf, fgets)")
        recommendations.add("Enable AddressSanitizer and MemorySanitizer in CI/CD")
        recommendations.add("Consider migrating to Rust for memory-critical components")

        return MemorySafetyReport(filePath, vulnerabilities, recommendations, safetyScore)
    }

    /**
     * Firmware Security Scan
     * IoT/embedded firmware vulnerability analysis
     */
    fun analyzeFirmwareSecurity(content: String, filePath: String): FirmwareSecurityReport {

        val vulnerabilities = mutableListOf<FirmwareVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val firmwarePatterns = listOf(
            FWPattern("HARDCODED_CREDENTIALS", """(password|passwd|pwd|secret|apikey)\s*=\s*["'][^"']+["']""",
                "Hardcoded credentials in firmware", Severity.CRITICAL),
            FWPattern("DEBUG_ENABLED", """#define\s+DEBUG\s+1|debug\s*=\s*true|DEBUG_MODE""",
                "Debug mode enabled in production firmware", Severity.HIGH),
            FWPattern("INSECURE_BOOT", """secure_boot\s*=\s*false|SECURE_BOOT.*0|bypass.*signature""",
                "Secure boot disabled or bypassed", Severity.CRITICAL),
            FWPattern("WEAK_CRYPTO", """DES|MD5|SHA1|RC4|ECB""",
                "Weak cryptographic algorithm in firmware", Severity.HIGH),
            FWPattern("TELNET_ENABLED", """telnet|port\s*=\s*23|TELNET_SERVER""",
                "Telnet service enabled - use SSH instead", Severity.HIGH),
            FWPattern("UART_DEBUG", """UART|serial.*debug|console.*enable""",
                "UART debug interface exposed", Severity.MEDIUM),
            FWPattern("JTAG_ENABLED", """JTAG|jtag_enable|debug_port""",
                "JTAG debug interface may be enabled", Severity.MEDIUM),
            FWPattern("UPDATE_NO_VERIFY", """update.*\{[^}]*(?!verify|signature|checksum)""",
                "Firmware update without integrity verification", Severity.CRITICAL),
            FWPattern("BUSYBOX_SHELL", """busybox|/bin/sh|dropbear""",
                "BusyBox or shell access detected", Severity.MEDIUM)
        )

        lines.forEachIndexed { index, line ->
            firmwarePatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(FirmwareVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity
                    ))
                }
            }
        }

        recommendations.add("Enable secure boot with verified boot chain")
        recommendations.add("Remove all debug interfaces in production builds")
        recommendations.add("Implement signed firmware updates with rollback protection")
        recommendations.add("Use hardware security modules (HSM) for key storage")

        return FirmwareSecurityReport(filePath, vulnerabilities, recommendations)
    }

    /**
     * Blockchain Smart Contract Auditing
     * Solidity and Rust (Solana) smart contract security
     */
    fun analyzeSmartContract(content: String, filePath: String): SmartContractReport {

        val vulnerabilities = mutableListOf<SmartContractVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // Solidity patterns
        val solidityPatterns = listOf(
            SCPattern("REENTRANCY", """\.call\{value:|\.call\.value\(|\.send\(|\.transfer\(""",
                "Potential reentrancy vulnerability - external call before state change", Severity.CRITICAL, "Solidity"),
            SCPattern("TX_ORIGIN", """tx\.origin""",
                "tx.origin used for authentication - use msg.sender instead", Severity.HIGH, "Solidity"),
            SCPattern("UNCHECKED_RETURN", """\.call\([^)]*\)|\.send\([^)]*\)|\.transfer\([^)]*\)""",
                "Unchecked return value from external call", Severity.HIGH, "Solidity"),
            SCPattern("INTEGER_OVERFLOW", """(\+\+|\-\-|\+\=|\-\=|\*\=)(?!.*SafeMath)""",
                "Arithmetic operation without SafeMath or overflow check", Severity.HIGH, "Solidity"),
            SCPattern("DELEGATECALL", """delegatecall""",
                "delegatecall used - can lead to storage collision", Severity.HIGH, "Solidity"),
            SCPattern("SELFDESTRUCT", """selfdestruct|suicide""",
                "selfdestruct can be called - verify access control", Severity.HIGH, "Solidity"),
            SCPattern("FLOATING_PRAGMA", """pragma\s+solidity\s*\^""",
                "Floating pragma - lock to specific compiler version", Severity.MEDIUM, "Solidity"),
            SCPattern("TIMESTAMP_DEPEND", """block\.timestamp|now""",
                "Block timestamp dependency - can be manipulated by miners", Severity.MEDIUM, "Solidity"),
            SCPattern("FRONT_RUNNING", """approve\(|allowance|transferFrom""",
                "Potential front-running vulnerability in approval flow", Severity.MEDIUM, "Solidity")
        )

        // Rust/Solana patterns
        val rustPatterns = listOf(
            SCPattern("MISSING_SIGNER", """#\[account\([^)]*(?!signer)""",
                "Account without signer verification", Severity.HIGH, "Rust/Solana"),
            SCPattern("MISSING_OWNER", """#\[account\([^)]*(?!owner)""",
                "Account without owner verification", Severity.HIGH, "Rust/Solana"),
            SCPattern("UNCHECKED_MATH", """checked_add|checked_sub|checked_mul""",
                "Consider using checked arithmetic", Severity.MEDIUM, "Rust/Solana")
        )

        val allPatterns = solidityPatterns + rustPatterns

        lines.forEachIndexed { index, line ->
            allPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(SmartContractVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity,
                        pattern.platform
                    ))
                }
            }
        }

        val penaltySum = vulnerabilities.fold(0) { acc, vuln ->
            acc + when (vuln.severity) {
                Severity.CRITICAL -> 25
                Severity.HIGH -> 15
                Severity.MEDIUM -> 5
                else -> 2
            }
        }
        val auditScore = (100.0 - penaltySum).coerceIn(0.0, 100.0)

        recommendations.add("Use ReentrancyGuard for functions with external calls")
        recommendations.add("Implement checks-effects-interactions pattern")
        recommendations.add("Lock pragma to specific Solidity version")
        recommendations.add("Add comprehensive unit and fuzzing tests")

        return SmartContractReport(filePath, vulnerabilities, recommendations, auditScore)
    }

    /**
     * OAuth/OIDC Misconfiguration Detection
     */
    fun analyzeOAuthOIDC(content: String, filePath: String): OAuthOIDCReport {

        val vulnerabilities = mutableListOf<OAuthVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val oauthPatterns = listOf(
            OAuthPattern("IMPLICIT_FLOW", """response_type\s*[=:]\s*["']?token["']?|grant_type.*implicit""",
                "Implicit flow used - vulnerable to token leakage", Severity.HIGH),
            OAuthPattern("NO_STATE_PARAM", """authorize\?[^}]*(?!state=)""",
                "Missing state parameter - vulnerable to CSRF", Severity.HIGH),
            OAuthPattern("NO_PKCE", """authorization_code.*(?!code_challenge|code_verifier)""",
                "Authorization code flow without PKCE", Severity.MEDIUM),
            OAuthPattern("WEAK_REDIRECT", """redirect_uri.*\*|callback.*localhost""",
                "Weak redirect URI validation", Severity.HIGH),
            OAuthPattern("TOKEN_IN_URL", """access_token.*[?&]|token=.*url|#access_token""",
                "Access token exposed in URL", Severity.HIGH),
            OAuthPattern("LONG_TOKEN_EXPIRY", """expires_in\s*[=:]\s*\d{6,}|expiry.*year""",
                "Excessively long token expiration", Severity.MEDIUM),
            OAuthPattern("NO_TOKEN_VALIDATION", """jwt.*decode(?!.*verify)|parseToken(?!.*validate)""",
                "JWT decoded without signature validation", Severity.CRITICAL),
            OAuthPattern("INSECURE_SCOPE", """scope.*\*|scope.*admin|scope.*all""",
                "Overly permissive OAuth scope", Severity.MEDIUM),
            OAuthPattern("CLIENT_SECRET_EXPOSED", """client_secret\s*[=:]\s*["'][^"']+["']""",
                "Client secret hardcoded or exposed", Severity.CRITICAL)
        )

        lines.forEachIndexed { index, line ->
            oauthPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(OAuthVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity
                    ))
                }
            }
        }

        recommendations.add("Use Authorization Code flow with PKCE")
        recommendations.add("Always validate state parameter to prevent CSRF")
        recommendations.add("Implement strict redirect URI validation")
        recommendations.add("Use short-lived access tokens with refresh tokens")

        return OAuthOIDCReport(filePath, vulnerabilities, recommendations)
    }

    /**
     * Cryptographic Agility Analysis
     * Crypto algorithm deprecation and migration analysis
     */
    fun analyzeCryptographicAgility(content: String, filePath: String): CryptoAgilityReport {

        val findings = mutableListOf<CryptoAgilityFinding>()
        val migrationPaths = mutableMapOf<String, String>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val deprecatedAlgorithms = listOf(
            CryptoAlgo("MD5", """MD5|md5|MessageDigest.*"MD5"""", "SHA-256 or SHA-3", "2024", Severity.HIGH),
            CryptoAlgo("SHA1", """SHA-?1(?!28)|sha-?1|MessageDigest.*"SHA-1"""", "SHA-256 or SHA-3", "2024", Severity.HIGH),
            CryptoAlgo("DES", """\bDES\b|TripleDES|3DES|DESede""", "AES-256-GCM", "2023", Severity.CRITICAL),
            CryptoAlgo("RC4", """RC4|ARC4|ARCFOUR""", "ChaCha20-Poly1305", "2015", Severity.CRITICAL),
            CryptoAlgo("RSA-1024", """RSA.*1024|keysize.*1024.*RSA""", "RSA-2048+ or ECDSA P-256", "2023", Severity.HIGH),
            CryptoAlgo("PKCS1v15", """PKCS1|RSA/ECB""", "RSA-OAEP or ECDSA", "2025", Severity.MEDIUM),
            CryptoAlgo("ECB_MODE", """ECB|AES/ECB|/ECB/""", "GCM or CBC with HMAC", "Deprecated", Severity.HIGH),
            CryptoAlgo("STATIC_IV", """IV\s*=\s*["'][^"']+["']|iv.*static|hardcoded.*iv""", "Random IV per encryption", "N/A", Severity.HIGH),
            CryptoAlgo("RSA_NO_PADDING", """RSA/None|NoPadding.*RSA""", "OAEP padding", "N/A", Severity.CRITICAL)
        )

        lines.forEachIndexed { index, line ->
            deprecatedAlgorithms.forEach { algo ->
                if (Regex(algo.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    findings.add(CryptoAgilityFinding(
                        algo.name,
                        "Deprecated/weak algorithm: ${algo.name}",
                        index + 1,
                        algo.severity,
                        algo.eolDate
                    ))
                    migrationPaths[algo.name] = algo.replacement
                }
            }
        }

        recommendations.add("Create crypto abstraction layer for algorithm agility")
        recommendations.add("Use configuration-driven algorithm selection")
        recommendations.add("Plan migration path for post-quantum cryptography")
        recommendations.add("Implement key rotation policies")

        return CryptoAgilityReport(filePath, findings, migrationPaths, recommendations)
    }

    /**
     * Sidecar Proxy Security (Envoy, Istio)
     */
    fun analyzeSidecarProxySecurity(content: String, filePath: String): SidecarSecurityReport {

        val findings = mutableListOf<SidecarFinding>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val sidecarPatterns = listOf(
            SidecarPattern("MTLS_DISABLED", """mtls.*DISABLE|mode:\s*DISABLE|tls.*false""",
                "mTLS disabled - service communication unencrypted", Severity.CRITICAL),
            SidecarPattern("PERMISSIVE_MODE", """mode:\s*PERMISSIVE|mtls.*permissive""",
                "Permissive mTLS mode - allows unencrypted traffic", Severity.HIGH),
            SidecarPattern("NO_AUTH_POLICY", """AuthorizationPolicy[^}]*rules:\s*\[\]|allow.*all""",
                "Missing or permissive authorization policy", Severity.HIGH),
            SidecarPattern("WILDCARD_PRINCIPAL", """principals:\s*\["\*"\]|from:\s*-\s*source:\s*\{\}""",
                "Wildcard principal allows any service", Severity.HIGH),
            SidecarPattern("INSECURE_UPSTREAM", """upstream.*http://|cluster.*http://""",
                "Insecure HTTP upstream connection", Severity.MEDIUM),
            SidecarPattern("NO_RATE_LIMIT", """rateLimit.*null|rateLimiting:\s*false""",
                "Rate limiting not configured", Severity.MEDIUM),
            SidecarPattern("DEBUG_ENDPOINTS", """admin.*enable|healthCheck.*exposed|metrics.*public""",
                "Debug/admin endpoints may be exposed", Severity.MEDIUM),
            SidecarPattern("WEAK_CIPHER", """cipher.*CBC|TLS_RSA|cipher.*RC4""",
                "Weak TLS cipher suite configured", Severity.HIGH)
        )

        lines.forEachIndexed { index, line ->
            sidecarPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    findings.add(SidecarFinding(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity
                    ))
                }
            }
        }

        recommendations.add("Enable STRICT mTLS mode for all services")
        recommendations.add("Implement fine-grained AuthorizationPolicy per service")
        recommendations.add("Configure rate limiting at the gateway level")
        recommendations.add("Use PeerAuthentication to enforce mTLS globally")

        return SidecarSecurityReport(filePath, findings, recommendations)
    }

    /**
     * Edge Computing Security
     * Edge/CDN security configuration analysis
     */
    fun analyzeEdgeComputingSecurity(content: String, filePath: String): EdgeSecurityReport {

        val findings = mutableListOf<EdgeSecurityFinding>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val edgePatterns = listOf(
            EdgePattern("NO_WAF", """waf.*disabled|waf.*false|security.*none""",
                "WAF not enabled at edge", Severity.HIGH),
            EdgePattern("CACHE_SENSITIVE", """cache.*authorization|cache.*cookie|private.*public""",
                "Potentially caching sensitive data", Severity.HIGH),
            EdgePattern("NO_CACHE_CONTROL", """Cache-Control.*missing|no-cache.*false""",
                "Missing cache control headers", Severity.MEDIUM),
            EdgePattern("CORS_WILDCARD", """Access-Control-Allow-Origin.*\*|cors.*\*""",
                "CORS allows all origins", Severity.HIGH),
            EdgePattern("TLS_VERSION_OLD", """TLSv1\.0|TLSv1\.1|ssl.*3""",
                "Outdated TLS version configured", Severity.CRITICAL),
            EdgePattern("NO_HSTS", """Strict-Transport-Security.*missing|hsts.*false""",
                "HSTS not configured", Severity.MEDIUM),
            EdgePattern("ORIGIN_EXPOSED", """origin.*public|backend.*exposed|upstream.*direct""",
                "Origin server may be directly accessible", Severity.HIGH),
            EdgePattern("BOT_PROTECTION_OFF", """botManagement.*off|bot.*disabled""",
                "Bot protection not enabled", Severity.MEDIUM),
            EdgePattern("DDoS_NO_PROTECTION", """ddos.*disabled|rateLimit.*none""",
                "DDoS protection not configured", Severity.HIGH)
        )

        lines.forEachIndexed { index, line ->
            edgePatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    findings.add(EdgeSecurityFinding(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity
                    ))
                }
            }
        }

        recommendations.add("Enable WAF with OWASP Core Rule Set")
        recommendations.add("Configure proper Cache-Control headers for sensitive endpoints")
        recommendations.add("Use TLS 1.3 with modern cipher suites")
        recommendations.add("Implement DDoS protection and rate limiting at edge")

        return EdgeSecurityReport(filePath, findings, recommendations)
    }

    // Helper pattern classes
    private data class MemPattern(val name: String, val regex: String, val description: String, val severity: Severity, val language: String)
    private data class FWPattern(val name: String, val regex: String, val description: String, val severity: Severity)
    private data class SCPattern(val name: String, val regex: String, val description: String, val severity: Severity, val platform: String)
    private data class OAuthPattern(val name: String, val regex: String, val description: String, val severity: Severity)
    private data class CryptoAlgo(val name: String, val regex: String, val replacement: String, val eolDate: String, val severity: Severity)
    private data class SidecarPattern(val name: String, val regex: String, val description: String, val severity: Severity)
    private data class EdgePattern(val name: String, val regex: String, val description: String, val severity: Severity)
}

// Report data classes
data class MemorySafetyReport(
    val filePath: String,
    val vulnerabilities: List<MemoryVulnerability>,
    val recommendations: List<String>,
    val safetyScore: Double
)

data class MemoryVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity,
    val language: String
)

data class FirmwareSecurityReport(
    val filePath: String,
    val vulnerabilities: List<FirmwareVulnerability>,
    val recommendations: List<String>
)

data class FirmwareVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class SmartContractReport(
    val filePath: String,
    val vulnerabilities: List<SmartContractVulnerability>,
    val recommendations: List<String>,
    val auditScore: Double
)

data class SmartContractVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity,
    val platform: String
)

data class OAuthOIDCReport(
    val filePath: String,
    val vulnerabilities: List<OAuthVulnerability>,
    val recommendations: List<String>
)

data class OAuthVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class CryptoAgilityReport(
    val filePath: String,
    val findings: List<CryptoAgilityFinding>,
    val migrationPaths: Map<String, String>,
    val recommendations: List<String>
)

data class CryptoAgilityFinding(
    val algorithm: String,
    val description: String,
    val line: Int,
    val severity: Severity,
    val eolDate: String
)

data class SidecarSecurityReport(
    val filePath: String,
    val findings: List<SidecarFinding>,
    val recommendations: List<String>
)

data class SidecarFinding(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class EdgeSecurityReport(
    val filePath: String,
    val findings: List<EdgeSecurityFinding>,
    val recommendations: List<String>
)

data class EdgeSecurityFinding(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)
