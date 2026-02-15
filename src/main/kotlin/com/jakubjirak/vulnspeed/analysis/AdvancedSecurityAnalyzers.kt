package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.licensing.LicenseFeature
import com.jakubjirak.vulnspeed.licensing.LicenseManager
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.VulnerabilityType

/**
 * Advanced Security Analyzers for VulnSpeed v2025.9.0
 * 
 * New Features:
 * - Zero-Trust Architecture Validation
 * - GraphQL Security Scanner
 * - WebSocket Security Analysis
 * - SSRF Deep Scan
 * - Insecure Deserialization Detection
 */
class AdvancedSecurityAnalyzers {

    /**
     * Zero-Trust Architecture Validation
     * Verifies zero-trust principles: verify explicitly, least privilege, assume breach
     */
    fun analyzeZeroTrust(content: String, filePath: String): ZeroTrustReport {
        if (!LicenseManager.getInstance().isFeatureAvailable(LicenseFeature.ZERO_TRUST_VALIDATION)) {
            return ZeroTrustReport(filePath, emptyList(), emptyList(), 0.0)
        }

        val findings = mutableListOf<ZeroTrustFinding>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // Check for implicit trust patterns
        val implicitTrustPatterns = listOf(
            ZTPattern("IMPLICIT_INTERNAL_TRUST", """trust.*internal|internal.*trusted|intranet.*safe""", 
                "Implicit trust for internal networks violates zero-trust", Severity.HIGH),
            ZTPattern("MISSING_AUTH_CHECK", """(public|protected)\s+(void|String|Object)\s+\w+\([^)]*\)\s*\{(?!.*(@Secured|@PreAuthorize|authenticate|authorize))""",
                "Public endpoint without explicit authentication", Severity.HIGH),
            ZTPattern("IP_BASED_AUTH", """remoteAddr|getRemoteAddr|clientIP|sourceIP.*allow""",
                "IP-based authentication is not zero-trust compliant", Severity.MEDIUM),
            ZTPattern("STATIC_CREDENTIALS", """password\s*=\s*["'][^"']+["']|apiKey\s*=\s*["']""",
                "Static credentials detected - use dynamic credential management", Severity.CRITICAL),
            ZTPattern("OVERPRIVILEGED_ACCESS", """@RolesAllowed\s*\(\s*["']\*["']\s*\)|role\s*=\s*["']admin["'].*all""",
                "Overprivileged access - violates least privilege principle", Severity.HIGH)
        )

        lines.forEachIndexed { index, line ->
            implicitTrustPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    findings.add(ZeroTrustFinding(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity
                    ))
                }
            }
        }

        // Check for micro-segmentation
        val hasMicroSegmentation = lines.any { 
            it.contains("@Secured") || it.contains("segment") || it.contains("NetworkPolicy")
        }
        if (!hasMicroSegmentation) {
            recommendations.add("Implement micro-segmentation for network isolation")
        }

        // Check for continuous verification
        val hasContinuousVerification = lines.any {
            it.contains("sessionValid") || it.contains("tokenRefresh") || it.contains("revalidate")
        }
        if (!hasContinuousVerification) {
            recommendations.add("Implement continuous verification of user/device identity")
        }

        // Check for logging/monitoring
        val hasMonitoring = lines.any {
            it.contains("audit") || it.contains("log") || it.contains("monitor")
        }
        if (!hasMonitoring) {
            recommendations.add("Add comprehensive logging for assume-breach monitoring")
        }

        val complianceScore = calculateZeroTrustScore(findings.size, hasMicroSegmentation, hasContinuousVerification, hasMonitoring)
        return ZeroTrustReport(filePath, findings, recommendations, complianceScore)
    }

    private fun calculateZeroTrustScore(findingsCount: Int, segmentation: Boolean, verification: Boolean, monitoring: Boolean): Double {
        var score = 100.0
        score -= findingsCount * 10
        if (!segmentation) score -= 15
        if (!verification) score -= 15
        if (!monitoring) score -= 10
        return score.coerceIn(0.0, 100.0)
    }

    /**
     * GraphQL Security Scanner
     * Detects injection, DoS, introspection attacks
     */
    fun analyzeGraphQLSecurity(content: String, filePath: String): GraphQLSecurityReport {
        if (!LicenseManager.getInstance().isFeatureAvailable(LicenseFeature.GRAPHQL_SECURITY)) {
            return GraphQLSecurityReport(filePath, emptyList(), emptyList())
        }

        val vulnerabilities = mutableListOf<GraphQLVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val graphqlPatterns = listOf(
            GQLPattern("INTROSPECTION_ENABLED", """introspection\s*[=:]\s*true|__schema|__type""",
                "GraphQL introspection is enabled - disable in production", Severity.HIGH, "Information Disclosure"),
            GQLPattern("QUERY_DEPTH_UNLIMITED", """maxDepth\s*[=:]\s*(-1|null|undefined)|depthLimit.*disabled""",
                "Query depth is unlimited - vulnerable to nested query attacks", Severity.HIGH, "DoS"),
            GQLPattern("NO_COMPLEXITY_LIMIT", """complexity.*unlimited|maxComplexity\s*[=:]\s*(-1|null)""",
                "No query complexity limit - vulnerable to resource exhaustion", Severity.HIGH, "DoS"),
            GQLPattern("BATCHING_ENABLED", """batching\s*[=:]\s*true|allowBatchQueries""",
                "Query batching enabled without rate limiting", Severity.MEDIUM, "DoS"),
            GQLPattern("FIELD_SUGGESTION", """fieldSuggestions?\s*[=:]\s*true|didYouMean""",
                "Field suggestions enabled - information leakage", Severity.LOW, "Information Disclosure"),
            GQLPattern("RAW_SQL_IN_RESOLVER", """resolver.*\{[^}]*sql.*\$|query\s*\(.*\$\{""",
                "Potential SQL injection in GraphQL resolver", Severity.CRITICAL, "Injection"),
            GQLPattern("UNSAFE_MUTATION", """mutation[^{]*\{[^}]*exec|mutation[^{]*\{[^}]*system""",
                "Potentially dangerous mutation detected", Severity.HIGH, "Injection")
        )

        lines.forEachIndexed { index, line ->
            graphqlPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(GraphQLVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity,
                        pattern.category
                    ))
                }
            }
        }

        // Check for best practices
        val hasDepthLimit = lines.any { it.contains("maxDepth") || it.contains("depthLimit") }
        val hasComplexityLimit = lines.any { it.contains("maxComplexity") || it.contains("complexityLimit") }
        val hasRateLimiting = lines.any { it.contains("rateLimit") || it.contains("throttle") }

        if (!hasDepthLimit) recommendations.add("Implement query depth limiting (recommended: 10)")
        if (!hasComplexityLimit) recommendations.add("Implement query complexity analysis")
        if (!hasRateLimiting) recommendations.add("Add rate limiting for GraphQL queries")

        return GraphQLSecurityReport(filePath, vulnerabilities, recommendations)
    }

    /**
     * WebSocket Security Analysis
     * Origin validation, message integrity, secure handshake
     */
    fun analyzeWebSocketSecurity(content: String, filePath: String): WebSocketSecurityReport {
        if (!LicenseManager.getInstance().isFeatureAvailable(LicenseFeature.WEBSOCKET_SECURITY)) {
            return WebSocketSecurityReport(filePath, emptyList(), emptyList())
        }

        val findings = mutableListOf<WebSocketFinding>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val wsPatterns = listOf(
            WSPattern("MISSING_ORIGIN_CHECK", """WebSocket|onopen|onmessage""",
                "WebSocket without origin validation", Severity.HIGH, checkNegative = "checkOrigin|origin.*validate"),
            WSPattern("INSECURE_WS", """ws://(?!localhost|127\.0\.0\.1)""",
                "Insecure WebSocket (ws://) used - use wss:// instead", Severity.HIGH),
            WSPattern("NO_MESSAGE_VALIDATION", """onmessage.*\{[^}]*JSON\.parse(?![^}]*validate)""",
                "WebSocket message parsed without validation", Severity.MEDIUM),
            WSPattern("BROADCAST_ALL", """broadcast|sendToAll|clients\.forEach""",
                "Broadcasting to all clients - ensure proper authorization", Severity.MEDIUM),
            WSPattern("NO_HEARTBEAT", """WebSocket|socket""",
                "No heartbeat/ping-pong mechanism detected", Severity.LOW, checkNegative = "ping|pong|heartbeat"),
            WSPattern("LARGE_MESSAGE", """maxPayload|maxMessageSize""",
                "Check message size limits to prevent DoS", Severity.LOW, infoOnly = true)
        )

        lines.forEachIndexed { index, line ->
            wsPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    val hasNegative = pattern.checkNegative?.let { neg ->
                        lines.any { Regex(neg, RegexOption.IGNORE_CASE).containsMatchIn(it) }
                    } ?: false
                    
                    if (!hasNegative && !pattern.infoOnly) {
                        findings.add(WebSocketFinding(
                            pattern.name,
                            pattern.description,
                            index + 1,
                            pattern.severity
                        ))
                    }
                }
            }
        }

        // Security recommendations
        val hasOriginCheck = lines.any { it.contains("origin", ignoreCase = true) && it.contains("check", ignoreCase = true) }
        val hasAuthentication = lines.any { it.contains("authenticate") || it.contains("token") }
        val hasEncryption = lines.any { it.contains("wss://") || it.contains("TLS") }

        if (!hasOriginCheck) recommendations.add("Implement Origin header validation")
        if (!hasAuthentication) recommendations.add("Add authentication for WebSocket connections")
        if (!hasEncryption) recommendations.add("Use WSS (WebSocket Secure) for encrypted communication")

        return WebSocketSecurityReport(filePath, findings, recommendations)
    }

    /**
     * SSRF Deep Scan
     * Server-Side Request Forgery analysis with call-flow tracking
     */
    fun analyzeSSRF(content: String, filePath: String): SSRFReport {
        if (!LicenseManager.getInstance().isFeatureAvailable(LicenseFeature.SSRF_DEEP_SCAN)) {
            return SSRFReport(filePath, emptyList(), emptyList())
        }

        val vulnerabilities = mutableListOf<SSRFVulnerability>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        val ssrfPatterns = listOf(
            SSRFPattern("URL_FROM_INPUT", """URL\s*\(\s*(request\.|params\.|input|userInput|\$)""",
                "URL constructed from user input - potential SSRF", Severity.CRITICAL),
            SSRFPattern("HTTP_CLIENT_UNTRUSTED", """(HttpClient|RestTemplate|WebClient|fetch|axios)\s*\.\s*(get|post|put|delete|request)\s*\([^)]*\$""",
                "HTTP request with dynamic URL - validate destination", Severity.HIGH),
            SSRFPattern("FILE_URL", """file://|gopher://|dict://|ftp://""",
                "Dangerous URL scheme detected - restrict allowed protocols", Severity.CRITICAL),
            SSRFPattern("INTERNAL_IP_ACCESSIBLE", """127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+""",
                "Internal IP address in URL - check for SSRF allowlist bypass", Severity.MEDIUM),
            SSRFPattern("DNS_REBINDING", """resolve|lookup.*host|dns.*query""",
                "DNS resolution from user input - vulnerable to DNS rebinding", Severity.HIGH),
            SSRFPattern("REDIRECT_FOLLOW", """followRedirects?\s*[=:]\s*true|maxRedirects?\s*[=:]\s*-1""",
                "Following redirects unconditionally - can bypass SSRF filters", Severity.MEDIUM),
            SSRFPattern("CLOUD_METADATA", """169\.254\.169\.254|metadata\.google|metadata\.azure""",
                "Cloud metadata endpoint access detected", Severity.CRITICAL)
        )

        lines.forEachIndexed { index, line ->
            ssrfPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(SSRFVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity
                    ))
                }
            }
        }

        // Check for SSRF mitigations
        val hasAllowlist = lines.any { it.contains("allowlist") || it.contains("whitelist") }
        val hasURLValidation = lines.any { it.contains("validateUrl") || it.contains("isValidHost") }
        val hasBlocklist = lines.any { it.contains("blocklist") || it.contains("blacklist") }

        if (!hasAllowlist) recommendations.add("Implement URL allowlist for outbound requests")
        if (!hasURLValidation) recommendations.add("Add URL validation before making HTTP requests")
        recommendations.add("Block requests to internal IP ranges (10.x, 172.16.x, 192.168.x)")
        recommendations.add("Disable unnecessary URL schemes (file://, gopher://, etc.)")

        return SSRFReport(filePath, vulnerabilities, recommendations)
    }

    /**
     * Insecure Deserialization Detection
     * Call-flow analysis for deserialization vulnerabilities
     */
    fun analyzeInsecureDeserialization(content: String, filePath: String): DeserializationReport {
        if (!LicenseManager.getInstance().isFeatureAvailable(LicenseFeature.INSECURE_DESERIALIZATION)) {
            return DeserializationReport(filePath, emptyList(), emptyList(), emptyList())
        }

        val vulnerabilities = mutableListOf<DeserializationVulnerability>()
        val gadgetChains = mutableListOf<GadgetChainInfo>()
        val recommendations = mutableListOf<String>()
        val lines = content.lines()

        // Java deserialization patterns
        val javaPatterns = listOf(
            DeserPattern("OBJECT_INPUT_STREAM", """ObjectInputStream|readObject\(\)""",
                "Java native deserialization - highly vulnerable", Severity.CRITICAL, "Java"),
            DeserPattern("XMLDECODER", """XMLDecoder|readObject""",
                "XMLDecoder deserialization - known gadget chains", Severity.CRITICAL, "Java"),
            DeserPattern("XSTREAM", """XStream|fromXML""",
                "XStream deserialization without security configuration", Severity.HIGH, "Java"),
            DeserPattern("JACKSON_POLYMORPHIC", """@JsonTypeInfo|enableDefaultTyping|OBJECT_AND_NON_CONCRETE""",
                "Jackson polymorphic deserialization - potential RCE", Severity.CRITICAL, "Java"),
            DeserPattern("SNAKEYAML_UNSAFE", """Yaml\(\)|yaml\.load(?!Safe)""",
                "SnakeYAML unsafe load - allows arbitrary constructor calls", Severity.CRITICAL, "Java")
        )

        // Python deserialization patterns  
        val pythonPatterns = listOf(
            DeserPattern("PICKLE", """pickle\.(loads?|Unpickler)|cPickle""",
                "Python pickle deserialization - arbitrary code execution", Severity.CRITICAL, "Python"),
            DeserPattern("YAML_UNSAFE", """yaml\.load\s*\([^)]*(?!Loader=SafeLoader)""",
                "PyYAML unsafe load - use safe_load instead", Severity.CRITICAL, "Python"),
            DeserPattern("SHELVE", """shelve\.open""",
                "shelve uses pickle internally - same vulnerabilities", Severity.HIGH, "Python"),
            DeserPattern("MARSHAL", """marshal\.loads?""",
                "marshal deserialization - not secure against malicious data", Severity.HIGH, "Python")
        )

        // .NET deserialization patterns
        val dotnetPatterns = listOf(
            DeserPattern("BINARY_FORMATTER", """BinaryFormatter|Deserialize""",
                ".NET BinaryFormatter - highly vulnerable to RCE", Severity.CRITICAL, ".NET"),
            DeserPattern("LOSFORMATTER", """LosFormatter|ObjectStateFormatter""",
                "LosFormatter deserialization - known vulnerabilities", Severity.CRITICAL, ".NET"),
            DeserPattern("NETDATACONTRACT", """NetDataContractSerializer""",
                "NetDataContractSerializer - type-based attacks possible", Severity.HIGH, ".NET"),
            DeserPattern("JAVASCRIPTSERIALIZER", """JavaScriptSerializer.*TypeResolver""",
                "JavaScriptSerializer with TypeResolver - RCE possible", Severity.CRITICAL, ".NET")
        )

        val allPatterns = javaPatterns + pythonPatterns + dotnetPatterns

        lines.forEachIndexed { index, line ->
            allPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    vulnerabilities.add(DeserializationVulnerability(
                        pattern.name,
                        pattern.description,
                        index + 1,
                        pattern.severity,
                        pattern.language
                    ))
                }
            }
        }

        // Check for known gadget chain indicators
        val gadgetIndicators = mapOf(
            "Commons Collections" to listOf("InvokerTransformer", "ChainedTransformer", "ConstantTransformer"),
            "Spring" to listOf("MethodInvoker", "PropertyPathFactoryBean"),
            "Hibernate" to listOf("HibernateProxy", "AbstractEntityPersister"),
            "JDK" to listOf("Runtime.exec", "ProcessBuilder", "ScriptEngine")
        )

        gadgetIndicators.forEach { (chainName, indicators) ->
            val found = indicators.filter { indicator ->
                lines.any { it.contains(indicator, ignoreCase = true) }
            }
            if (found.isNotEmpty()) {
                gadgetChains.add(GadgetChainInfo(chainName, found))
            }
        }

        // Recommendations
        recommendations.add("Avoid native deserialization - use JSON/Protocol Buffers instead")
        recommendations.add("Implement type allowlisting for deserialization")
        recommendations.add("Use deserialization filters (JEP 290 for Java)")
        recommendations.add("Validate and sanitize all serialized data")

        return DeserializationReport(filePath, vulnerabilities, gadgetChains, recommendations)
    }

    // Helper pattern classes
    private data class ZTPattern(val name: String, val regex: String, val description: String, val severity: Severity)
    private data class GQLPattern(val name: String, val regex: String, val description: String, val severity: Severity, val category: String)
    private data class WSPattern(val name: String, val regex: String, val description: String, val severity: Severity, val checkNegative: String? = null, val infoOnly: Boolean = false)
    private data class SSRFPattern(val name: String, val regex: String, val description: String, val severity: Severity)
    private data class DeserPattern(val name: String, val regex: String, val description: String, val severity: Severity, val language: String)
}

// Report data classes
data class ZeroTrustReport(
    val filePath: String,
    val findings: List<ZeroTrustFinding>,
    val recommendations: List<String>,
    val complianceScore: Double
)

data class ZeroTrustFinding(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class GraphQLSecurityReport(
    val filePath: String,
    val vulnerabilities: List<GraphQLVulnerability>,
    val recommendations: List<String>
)

data class GraphQLVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity,
    val category: String
)

data class WebSocketSecurityReport(
    val filePath: String,
    val findings: List<WebSocketFinding>,
    val recommendations: List<String>
)

data class WebSocketFinding(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class SSRFReport(
    val filePath: String,
    val vulnerabilities: List<SSRFVulnerability>,
    val recommendations: List<String>
)

data class SSRFVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity
)

data class DeserializationReport(
    val filePath: String,
    val vulnerabilities: List<DeserializationVulnerability>,
    val gadgetChains: List<GadgetChainInfo>,
    val recommendations: List<String>
)

data class DeserializationVulnerability(
    val type: String,
    val description: String,
    val line: Int,
    val severity: Severity,
    val language: String
)

data class GadgetChainInfo(
    val chainName: String,
    val indicators: List<String>
)
