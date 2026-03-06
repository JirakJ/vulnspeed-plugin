package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.Severity

/**
 * Next-Generation Security Analyzers v2025.8.0
 * Advanced security analysis features for enterprise and professional customers
 */
class NextGenSecurityAnalyzers {

    /**
     * Quantum-Safe Cryptography Scanner
     * Validates quantum-resistant cryptography implementations
     */
    fun analyzeQuantumSafeCrypto(content: String, filePath: String): QuantumCryptoReport {

        val vulnerabilities = mutableListOf<CryptoVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // Detect vulnerable crypto algorithms (not quantum-safe)
        val vulnerableAlgorithms = listOf(
            CryptoPattern("RSA", """RSA|RSA/ECB|RSA/PKCS1""", "RSA is vulnerable to Shor's algorithm", Severity.HIGH),
            CryptoPattern("ECDSA", """ECDSA|EC/DSA|secp256|secp384""", "ECDSA is vulnerable to quantum attacks", Severity.HIGH),
            CryptoPattern("ECDH", """ECDH|X25519|X448""", "ECDH key exchange is quantum-vulnerable", Severity.HIGH),
            CryptoPattern("DSA", """DSA|DSS""", "DSA is vulnerable to quantum attacks", Severity.HIGH),
            CryptoPattern("DH", """DiffieHellman|DHParameterSpec""", "Diffie-Hellman is quantum-vulnerable", Severity.MEDIUM),
            CryptoPattern("SHA-1", """SHA-?1|MessageDigest\.getInstance\("SHA-1"\)""", "SHA-1 is deprecated", Severity.MEDIUM),
            CryptoPattern("MD5", """MD5|MessageDigest\.getInstance\("MD5"\)""", "MD5 is cryptographically broken", Severity.HIGH)
        )

        // Detect quantum-safe algorithms (good)
        val quantumSafeAlgorithms = listOf(
            "CRYSTALS-Kyber", "CRYSTALS-Dilithium", "FALCON", "SPHINCS+",
            "Classic McEliece", "BIKE", "HQC", "NTRU", "SABER"
        )

        lines.forEachIndexed { lineNum, line ->
            vulnerableAlgorithms.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(CryptoVulnerability(
                        algorithm = pattern.name,
                        line = lineNum + 1,
                        severity = pattern.severity,
                        description = pattern.description,
                        recommendation = "Consider migrating to post-quantum cryptography (e.g., CRYSTALS-Kyber, CRYSTALS-Dilithium)"
                    ))
                }
            }
        }

        // Check for quantum-safe implementations
        val hasQuantumSafe = quantumSafeAlgorithms.any { algo ->
            content.contains(algo, ignoreCase = true)
        }

        if (!hasQuantumSafe && vulnerabilities.isNotEmpty()) {
            recommendations.add("Consider implementing hybrid cryptography with post-quantum algorithms")
            recommendations.add("NIST recommends CRYSTALS-Kyber for key encapsulation and CRYSTALS-Dilithium for signatures")
        }

        val quantumReadinessScore = calculateQuantumReadiness(vulnerabilities, hasQuantumSafe)

        return QuantumCryptoReport(filePath, vulnerabilities, recommendations, quantumReadinessScore)
    }

    /**
     * Microservices Security Analyzer
     * Analyzes microservices architecture security patterns
     */
    fun analyzeMicroservicesSecurity(content: String, filePath: String): MicroservicesSecurityReport {

        val issues = mutableListOf<MicroserviceIssue>()
        val patterns = mutableListOf<SecurityPattern>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // Service discovery security
        val servicePatterns = listOf(
            ServicePattern("Eureka Client", """@EnableEurekaClient|eureka\.client""", "service-discovery"),
            ServicePattern("Consul", """spring\.cloud\.consul|ConsulClient""", "service-discovery"),
            ServicePattern("Kubernetes Service", """kubernetes\.io/service|ClusterIP|LoadBalancer""", "k8s-service"),
            ServicePattern("API Gateway", """@EnableZuulProxy|spring\.cloud\.gateway""", "api-gateway"),
            ServicePattern("Circuit Breaker", """@CircuitBreaker|Resilience4j|Hystrix""", "resilience"),
            ServicePattern("Service Mesh", """istio|linkerd|envoy""", "service-mesh")
        )

        lines.forEachIndexed { lineNum, line ->
            servicePatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    patterns.add(SecurityPattern(
                        name = pattern.name,
                        type = pattern.type,
                        line = lineNum + 1,
                        status = "detected"
                    ))
                }
            }

            // Check for security issues
            if (line.contains("http://") && !line.contains("localhost") && !line.contains("127.0.0.1")) {
                issues.add(MicroserviceIssue(
                    type = "insecure-communication",
                    description = "HTTP communication detected - use HTTPS for inter-service communication",
                    line = lineNum + 1,
                    severity = Severity.HIGH
                ))
            }

            if (Regex("""hardcoded.*secret|password\s*=\s*["'][^"']+["']""", RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                issues.add(MicroserviceIssue(
                    type = "hardcoded-secret",
                    description = "Hardcoded secret detected - use secret management (Vault, K8s Secrets)",
                    line = lineNum + 1,
                    severity = Severity.CRITICAL
                ))
            }
        }

        // Check for missing security patterns
        if (patterns.none { it.type == "service-mesh" }) {
            recommendations.add("Consider implementing a service mesh (Istio, Linkerd) for mTLS and traffic management")
        }
        if (patterns.none { it.type == "resilience" }) {
            recommendations.add("Implement circuit breakers for resilience against cascading failures")
        }

        return MicroservicesSecurityReport(filePath, issues, patterns, recommendations)
    }

    /**
     * Cloud Security Posture Analyzer
     * Scans AWS/Azure/GCP security configurations
     */
    fun analyzeCloudSecurityPosture(content: String, filePath: String): CloudSecurityReport {

        val misconfigurations = mutableListOf<CloudMisconfiguration>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // AWS misconfigurations
        val awsPatterns = listOf(
            CloudPattern("S3 Public Access", """PublicReadGetObject|public-read|public-read-write""", "aws", Severity.CRITICAL),
            CloudPattern("Wildcard IAM", """\*.*Action.*\*|"Action":\s*"\*"""", "aws", Severity.HIGH),
            CloudPattern("Unencrypted EBS", """Encrypted:\s*false|encrypted\s*=\s*false""", "aws", Severity.HIGH),
            CloudPattern("Open Security Group", """0\.0\.0\.0/0.*:22|0\.0\.0\.0/0.*:3389""", "aws", Severity.CRITICAL),
            CloudPattern("Missing MFA", """mfa_delete\s*=\s*false|MFADelete.*Disabled""", "aws", Severity.MEDIUM)
        )

        // Azure misconfigurations
        val azurePatterns = listOf(
            CloudPattern("Storage Public Access", """allow_blob_public_access\s*=\s*true""", "azure", Severity.CRITICAL),
            CloudPattern("Network Security Rule", """destination_port_range\s*=\s*"\*"""", "azure", Severity.HIGH),
            CloudPattern("Disk Encryption", """encryption_settings.*enabled\s*=\s*false""", "azure", Severity.HIGH)
        )

        // GCP misconfigurations
        val gcpPatterns = listOf(
            CloudPattern("Public Bucket", """allUsers|allAuthenticatedUsers""", "gcp", Severity.CRITICAL),
            CloudPattern("Default Service Account", """compute@developer\.gserviceaccount\.com""", "gcp", Severity.MEDIUM),
            CloudPattern("Legacy Network", """legacy_network|autoCreateSubnetworks.*false""", "gcp", Severity.LOW)
        )

        val allPatterns = awsPatterns + azurePatterns + gcpPatterns

        lines.forEachIndexed { lineNum, line ->
            allPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    misconfigurations.add(CloudMisconfiguration(
                        name = pattern.name,
                        cloud = pattern.cloud,
                        line = lineNum + 1,
                        severity = pattern.severity,
                        description = "Cloud security misconfiguration: ${pattern.name}"
                    ))
                }
            }
        }

        // Detect cloud provider
        val cloudProvider = when {
            content.contains("aws_", ignoreCase = true) || content.contains("AWS::", ignoreCase = true) -> "AWS"
            content.contains("azurerm_", ignoreCase = true) || content.contains("Microsoft.") -> "Azure"
            content.contains("google_", ignoreCase = true) || content.contains("gcp", ignoreCase = true) -> "GCP"
            else -> "Unknown"
        }

        if (misconfigurations.isNotEmpty()) {
            recommendations.add("Review and remediate ${misconfigurations.size} cloud security misconfigurations")
            if (misconfigurations.any { it.severity == Severity.CRITICAL }) {
                recommendations.add("CRITICAL: Address public access and overly permissive IAM policies immediately")
            }
        }

        return CloudSecurityReport(filePath, misconfigurations, recommendations, cloudProvider)
    }

    /**
     * Data Flow Tracking
     * End-to-end data flow and leakage detection
     */
    fun analyzeDataFlow(content: String, filePath: String): DataFlowReport {

        val sources = mutableListOf<DataSource>()
        val sinks = mutableListOf<DataSink>()
        val flows = mutableListOf<DataFlow>()
        val lines = content.lines()

        // Detect data sources (where sensitive data enters)
        val sourcePatterns = listOf(
            DataPattern("User Input", """request\.getParameter|req\.body|req\.query|@RequestParam""", "user-input"),
            DataPattern("Database Query", """ResultSet|findBy|@Query|executeQuery""", "database"),
            DataPattern("File Read", """FileReader|Files\.read|BufferedReader""", "file"),
            DataPattern("Environment Variable", """System\.getenv|process\.env|os\.environ""", "environment"),
            DataPattern("API Response", """RestTemplate|HttpClient|fetch\(|axios""", "api")
        )

        // Detect data sinks (where data leaves)
        val sinkPatterns = listOf(
            DataPattern("Log Output", """logger\.|console\.log|print\(|System\.out""", "logging"),
            DataPattern("HTTP Response", """response\.send|ResponseEntity|return.*Response""", "http-response"),
            DataPattern("File Write", """FileWriter|Files\.write|BufferedWriter""", "file"),
            DataPattern("External API", """httpClient\.post|axios\.post|fetch.*POST""", "external-api"),
            DataPattern("Database Write", """save\(|insert|update|executeUpdate""", "database")
        )

        lines.forEachIndexed { lineNum, line ->
            sourcePatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    sources.add(DataSource(
                        type = pattern.type,
                        name = pattern.name,
                        line = lineNum + 1,
                        isSensitive = isSensitiveData(line)
                    ))
                }
            }

            sinkPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    sinks.add(DataSink(
                        type = pattern.type,
                        name = pattern.name,
                        line = lineNum + 1,
                        isSecure = isSecureSink(line)
                    ))
                }
            }
        }

        // Detect potential data leakage flows
        sources.filter { it.isSensitive }.forEach { source ->
            sinks.filter { it.type == "logging" || !it.isSecure }.forEach { sink ->
                flows.add(DataFlow(
                    source = source,
                    sink = sink,
                    severity = if (sink.type == "logging") Severity.HIGH else Severity.MEDIUM,
                    description = "Potential data leakage: ${source.name} → ${sink.name}"
                ))
            }
        }

        return DataFlowReport(filePath, sources, sinks, flows)
    }

    /**
     * Compliance Automation
     * Automated compliance reporting (SOC2, ISO27001, GDPR)
     */
    fun analyzeCompliance(content: String, filePath: String, framework: String): ComplianceAnalysisReport {

        val violations = mutableListOf<ComplianceViolationItem>()
        val controls = mutableListOf<ComplianceControlItem>()
        val lines = content.lines()

        when (framework.uppercase()) {
            "SOC2" -> analyzeSoc2Compliance(lines, violations, controls)
            "ISO27001" -> analyzeIso27001Compliance(lines, violations, controls)
            "GDPR" -> analyzeGdprCompliance(lines, violations, controls)
            "PCI-DSS" -> analyzePciDssCompliance(lines, violations, controls)
            "HIPAA" -> analyzeHipaaCompliance(lines, violations, controls)
            else -> analyzeGeneralCompliance(lines, violations, controls)
        }

        val complianceScore = if (controls.isNotEmpty()) {
            controls.count { it.status == "compliant" }.toDouble() / controls.size * 100
        } else 0.0

        return ComplianceAnalysisReport(filePath, framework, violations, controls, complianceScore)
    }

    /**
     * Security Chaos Testing
     * Chaos engineering for security testing
     */
    fun analyzeSecurityChaosReadiness(content: String, filePath: String): ChaosTestingReport {

        val experiments = mutableListOf<ChaosExperiment>()
        val weaknesses = mutableListOf<SecurityWeakness>()
        val lines = content.lines()

        // Detect resilience patterns
        val resiliencePatterns = listOf(
            ResiliencePattern("Rate Limiting", """@RateLimiter|rateLimit|throttle""", "rate-limiting"),
            ResiliencePattern("Circuit Breaker", """@CircuitBreaker|circuitBreaker|Resilience4j""", "circuit-breaker"),
            ResiliencePattern("Timeout", """@Timeout|setTimeout|withTimeout""", "timeout"),
            ResiliencePattern("Retry", """@Retry|retryWhen|maxRetries""", "retry"),
            ResiliencePattern("Bulkhead", """@Bulkhead|Semaphore|ThreadPoolBulkhead""", "bulkhead"),
            ResiliencePattern("Fallback", """@Fallback|fallbackMethod|onErrorReturn""", "fallback")
        )

        val foundPatterns = mutableSetOf<String>()
        lines.forEachIndexed { lineNum, line ->
            resiliencePatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    foundPatterns.add(pattern.type)
                }
            }
        }

        // Generate chaos experiments based on missing patterns
        if ("rate-limiting" !in foundPatterns) {
            experiments.add(ChaosExperiment(
                name = "DDoS Simulation",
                type = "load-test",
                description = "Simulate high traffic to test rate limiting effectiveness",
                risk = Severity.HIGH
            ))
            weaknesses.add(SecurityWeakness(
                type = "missing-rate-limiting",
                description = "No rate limiting detected - vulnerable to DDoS",
                severity = Severity.HIGH
            ))
        }

        if ("circuit-breaker" !in foundPatterns) {
            experiments.add(ChaosExperiment(
                name = "Cascading Failure Test",
                type = "fault-injection",
                description = "Inject failures to test cascading failure prevention",
                risk = Severity.MEDIUM
            ))
        }

        if ("timeout" !in foundPatterns) {
            weaknesses.add(SecurityWeakness(
                type = "missing-timeout",
                description = "No timeout configuration - vulnerable to slowloris attacks",
                severity = Severity.MEDIUM
            ))
        }

        val chaosReadinessScore = foundPatterns.size.toDouble() / resiliencePatterns.size * 100

        return ChaosTestingReport(filePath, experiments, weaknesses, chaosReadinessScore)
    }

    /**
     * API Fuzzing
     * Automated API fuzzing and mutation testing
     */
    fun analyzeApiFuzzing(content: String, filePath: String): ApiFuzzingReport {

        val endpoints = mutableListOf<ApiEndpoint>()
        val fuzzTargets = mutableListOf<FuzzTarget>()
        val mutations = mutableListOf<MutationTest>()
        val lines = content.lines()

        // Detect API endpoints
        val endpointPatterns = listOf(
            EndpointPattern("GET", """@GetMapping|@GET|get\(["']/""", "read"),
            EndpointPattern("POST", """@PostMapping|@POST|post\(["']/""", "create"),
            EndpointPattern("PUT", """@PutMapping|@PUT|put\(["']/""", "update"),
            EndpointPattern("DELETE", """@DeleteMapping|@DELETE|delete\(["']/""", "delete"),
            EndpointPattern("PATCH", """@PatchMapping|@PATCH|patch\(["']/""", "update")
        )

        lines.forEachIndexed { lineNum, line ->
            endpointPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    endpoints.add(ApiEndpoint(
                        method = pattern.method,
                        line = lineNum + 1,
                        operation = pattern.operation
                    ))

                    // Generate fuzz targets for this endpoint
                    fuzzTargets.add(FuzzTarget(
                        endpoint = "Line ${lineNum + 1}",
                        method = pattern.method,
                        payloads = generateFuzzPayloads(pattern.method, line)
                    ))
                }
            }

            // Detect input parameters for mutation testing
            if (Regex("""@RequestParam|@PathVariable|@RequestBody""").containsMatchIn(line)) {
                mutations.add(MutationTest(
                    line = lineNum + 1,
                    type = "boundary-test",
                    mutations = listOf("null", "empty", "overflow", "special-chars", "sql-injection", "xss")
                ))
            }
        }

        return ApiFuzzingReport(filePath, endpoints, fuzzTargets, mutations)
    }

    /**
     * Identity & Access Analysis
     * IAM policy and access control analysis
     */
    fun analyzeIdentityAccess(content: String, filePath: String): IdentityAccessReport {

        val policies = mutableListOf<IamPolicy>()
        val issues = mutableListOf<AccessControlIssue>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // Detect IAM patterns
        val iamPatterns = listOf(
            IamPattern("Role-Based Access", """@RolesAllowed|@Secured|hasRole""", "rbac"),
            IamPattern("Attribute-Based Access", """@PreAuthorize|hasPermission|SpEL""", "abac"),
            IamPattern("OAuth/OIDC", """@EnableOAuth2|oauth2Login|oidc""", "oauth"),
            IamPattern("JWT", """JwtDecoder|@JwtAuth|Bearer""", "jwt"),
            IamPattern("API Key", """ApiKeyAuth|X-API-Key|apiKey""", "api-key"),
            IamPattern("Basic Auth", """httpBasic|BasicAuth|Authorization: Basic""", "basic")
        )

        lines.forEachIndexed { lineNum, line ->
            iamPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    policies.add(IamPolicy(
                        type = pattern.type,
                        name = pattern.name,
                        line = lineNum + 1
                    ))
                }
            }

            // Detect access control issues
            if (Regex("""permitAll|anonymous|public""", RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                issues.add(AccessControlIssue(
                    type = "overly-permissive",
                    description = "Overly permissive access control detected",
                    line = lineNum + 1,
                    severity = Severity.MEDIUM
                ))
            }

            if (Regex("""Admin|ROLE_ADMIN|superuser""", RegexOption.IGNORE_CASE).containsMatchIn(line) &&
                !Regex("""@Secured|@RolesAllowed|hasRole""").containsMatchIn(line)) {
                issues.add(AccessControlIssue(
                    type = "admin-without-protection",
                    description = "Admin functionality without proper access control",
                    line = lineNum + 1,
                    severity = Severity.HIGH
                ))
            }
        }

        // Generate recommendations
        if (policies.any { it.type == "basic" }) {
            recommendations.add("Consider migrating from Basic Auth to OAuth2/OIDC for better security")
        }
        if (policies.none { it.type == "rbac" && it.type == "abac" }) {
            recommendations.add("Implement role-based or attribute-based access control")
        }

        return IdentityAccessReport(filePath, policies, issues, recommendations)
    }

    // Helper methods
    private fun calculateQuantumReadiness(vulnerabilities: List<CryptoVulnerability>, hasQuantumSafe: Boolean): Double {
        if (vulnerabilities.isEmpty() && hasQuantumSafe) return 100.0
        if (vulnerabilities.isEmpty()) return 50.0
        val criticalCount = vulnerabilities.count { it.severity == Severity.CRITICAL }
        val highCount = vulnerabilities.count { it.severity == Severity.HIGH }
        val score = 100.0 - (criticalCount * 30 + highCount * 15)
        return if (hasQuantumSafe) kotlin.math.min(score + 20, 100.0) else kotlin.math.max(score, 0.0)
    }

    private fun isSensitiveData(line: String): Boolean {
        val sensitivePatterns = listOf("password", "secret", "token", "apiKey", "credit", "ssn", "email", "phone")
        return sensitivePatterns.any { line.contains(it, ignoreCase = true) }
    }

    private fun isSecureSink(line: String): Boolean {
        return line.contains("encrypt", ignoreCase = true) || 
               line.contains("hash", ignoreCase = true) ||
               line.contains("mask", ignoreCase = true)
    }

    private fun generateFuzzPayloads(method: String, line: String): List<String> {
        return when (method) {
            "POST", "PUT", "PATCH" -> listOf(
                "{}", "null", "[]", 
                """{"id": -1}""", 
                """{"id": 999999999}""",
                """{"name": "<script>alert(1)</script>"}""",
                """{"query": "' OR 1=1 --"}"""
            )
            else -> listOf("../../../etc/passwd", "null", "-1", "999999999")
        }
    }

    private fun analyzeSoc2Compliance(lines: List<String>, violations: MutableList<ComplianceViolationItem>, controls: MutableList<ComplianceControlItem>) {
        // SOC2 Trust Service Criteria checks
        controls.add(ComplianceControlItem("CC6.1", "Logical Access Controls", 
            if (lines.any { it.contains("@Secured") || it.contains("@RolesAllowed") }) "compliant" else "non-compliant"))
        controls.add(ComplianceControlItem("CC6.6", "Encryption", 
            if (lines.any { it.contains("encrypt", ignoreCase = true) }) "compliant" else "non-compliant"))
        controls.add(ComplianceControlItem("CC7.2", "Monitoring", 
            if (lines.any { it.contains("logger", ignoreCase = true) || it.contains("audit") }) "compliant" else "non-compliant"))
    }

    private fun analyzeIso27001Compliance(lines: List<String>, violations: MutableList<ComplianceViolationItem>, controls: MutableList<ComplianceControlItem>) {
        controls.add(ComplianceControlItem("A.9.4.1", "Access Control", 
            if (lines.any { it.contains("authentication") || it.contains("authorization") }) "compliant" else "non-compliant"))
        controls.add(ComplianceControlItem("A.10.1.1", "Cryptography", 
            if (lines.any { it.contains("Cipher") || it.contains("encrypt") }) "compliant" else "non-compliant"))
    }

    private fun analyzeGdprCompliance(lines: List<String>, violations: MutableList<ComplianceViolationItem>, controls: MutableList<ComplianceControlItem>) {
        // GDPR specific checks
        if (lines.any { it.contains("email", ignoreCase = true) || it.contains("personalData") }) {
            if (!lines.any { it.contains("consent") || it.contains("gdpr") }) {
                violations.add(ComplianceViolationItem("GDPR", "Article 7", "Personal data processing without consent mechanism", Severity.HIGH))
            }
        }
        controls.add(ComplianceControlItem("Art.32", "Data Protection", 
            if (lines.any { it.contains("encrypt") || it.contains("pseudonymize") }) "compliant" else "non-compliant"))
    }

    private fun analyzePciDssCompliance(lines: List<String>, violations: MutableList<ComplianceViolationItem>, controls: MutableList<ComplianceControlItem>) {
        if (lines.any { it.contains("creditCard", ignoreCase = true) || it.contains("cardNumber") }) {
            if (!lines.any { it.contains("mask") || it.contains("tokenize") }) {
                violations.add(ComplianceViolationItem("PCI-DSS", "3.4", "Card data not properly masked/tokenized", Severity.CRITICAL))
            }
        }
    }

    private fun analyzeHipaaCompliance(lines: List<String>, violations: MutableList<ComplianceViolationItem>, controls: MutableList<ComplianceControlItem>) {
        controls.add(ComplianceControlItem("164.312(a)", "Access Control", 
            if (lines.any { it.contains("@Secured") || it.contains("authenticate") }) "compliant" else "non-compliant"))
        controls.add(ComplianceControlItem("164.312(e)", "Transmission Security", 
            if (lines.any { it.contains("TLS") || it.contains("SSL") || it.contains("https") }) "compliant" else "non-compliant"))
    }

    private fun analyzeGeneralCompliance(lines: List<String>, violations: MutableList<ComplianceViolationItem>, controls: MutableList<ComplianceControlItem>) {
        controls.add(ComplianceControlItem("AUTH", "Authentication", 
            if (lines.any { it.contains("auth", ignoreCase = true) }) "compliant" else "non-compliant"))
        controls.add(ComplianceControlItem("CRYPTO", "Encryption", 
            if (lines.any { it.contains("encrypt", ignoreCase = true) }) "compliant" else "non-compliant"))
        controls.add(ComplianceControlItem("LOG", "Logging", 
            if (lines.any { it.contains("log", ignoreCase = true) }) "compliant" else "non-compliant"))
    }

    // Pattern data classes
    private data class CryptoPattern(val name: String, val regex: String, val description: String, val severity: Severity)
    private data class ServicePattern(val name: String, val regex: String, val type: String)
    private data class CloudPattern(val name: String, val regex: String, val cloud: String, val severity: Severity)
    private data class DataPattern(val name: String, val regex: String, val type: String)
    private data class ResiliencePattern(val name: String, val regex: String, val type: String)
    private data class EndpointPattern(val method: String, val regex: String, val operation: String)
    private data class IamPattern(val name: String, val regex: String, val type: String)
}

// Report data classes
data class QuantumCryptoReport(
    val filePath: String,
    val vulnerabilities: List<CryptoVulnerability>,
    val recommendations: List<String>,
    val quantumReadinessScore: Double
)

data class CryptoVulnerability(
    val algorithm: String,
    val line: Int,
    val severity: Severity,
    val description: String,
    val recommendation: String
)

data class MicroservicesSecurityReport(
    val filePath: String,
    val issues: List<MicroserviceIssue>,
    val patterns: List<SecurityPattern>,
    val recommendations: List<String>
)

data class MicroserviceIssue(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class SecurityPattern(
    val name: String,
    val type: String,
    val line: Int,
    val status: String
)

data class CloudSecurityReport(
    val filePath: String,
    val misconfigurations: List<CloudMisconfiguration>,
    val recommendations: List<String>,
    val cloudProvider: String
)

data class CloudMisconfiguration(
    val name: String,
    val cloud: String,
    val line: Int,
    val severity: Severity,
    val description: String
)

data class DataFlowReport(
    val filePath: String,
    val sources: List<DataSource>,
    val sinks: List<DataSink>,
    val flows: List<DataFlow>
)

data class DataSource(
    val type: String,
    val name: String,
    val line: Int,
    val isSensitive: Boolean
)

data class DataSink(
    val type: String,
    val name: String,
    val line: Int,
    val isSecure: Boolean
)

data class DataFlow(
    val source: DataSource,
    val sink: DataSink,
    val severity: Severity,
    val description: String
)

data class ComplianceAnalysisReport(
    val filePath: String,
    val framework: String,
    val violations: List<ComplianceViolationItem>,
    val controls: List<ComplianceControlItem>,
    val complianceScore: Double
)

data class ComplianceViolationItem(
    val framework: String,
    val requirement: String,
    val description: String,
    val severity: Severity
)

data class ComplianceControlItem(
    val id: String,
    val name: String,
    val status: String
)

data class ChaosTestingReport(
    val filePath: String,
    val experiments: List<ChaosExperiment>,
    val weaknesses: List<SecurityWeakness>,
    val chaosReadinessScore: Double
)

data class ChaosExperiment(
    val name: String,
    val type: String,
    val description: String,
    val risk: Severity
)

data class SecurityWeakness(
    val type: String,
    val description: String,
    val severity: Severity
)

data class ApiFuzzingReport(
    val filePath: String,
    val endpoints: List<ApiEndpoint>,
    val fuzzTargets: List<FuzzTarget>,
    val mutations: List<MutationTest>
)

data class ApiEndpoint(
    val method: String,
    val line: Int,
    val operation: String
)

data class FuzzTarget(
    val endpoint: String,
    val method: String,
    val payloads: List<String>
)

data class MutationTest(
    val line: Int,
    val type: String,
    val mutations: List<String>
)

data class IdentityAccessReport(
    val filePath: String,
    val policies: List<IamPolicy>,
    val issues: List<AccessControlIssue>,
    val recommendations: List<String>
)

data class IamPolicy(
    val type: String,
    val name: String,
    val line: Int
)

data class AccessControlIssue(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)
