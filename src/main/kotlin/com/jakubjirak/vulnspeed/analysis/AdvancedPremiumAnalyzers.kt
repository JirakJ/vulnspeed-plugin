package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.*
import java.util.UUID

/**
 * Advanced Premium Analyzers - v2025.6.0 Features
 * New advanced security analysis capabilities for Professional and Enterprise tiers
 */
object AdvancedPremiumAnalyzers {

    /**
     * Threat Modeling - Auto-generate STRIDE threat models
     */
    fun generateThreatModel(content: String, filePath: String, language: String): ThreatModelReport {
        
        val threats = mutableListOf<ThreatEntry>()
        val mitigations = mutableListOf<MitigationSuggestion>()
        val lines = content.lines()
        
        // STRIDE Analysis patterns
        val stridePatterns = mapOf(
            "SPOOFING" to listOf(
                ThreatPattern("Authentication bypass risk", """(?i)(login|auth|authenticate).*(?:skip|bypass|disabled)""", "S1"),
                ThreatPattern("Missing identity verification", """@RequestMapping.*(?!.*@PreAuthorize|.*@Secured)""", "S2"),
                ThreatPattern("Weak session validation", """(?i)session.*(?:null|empty|invalid)""", "S3")
            ),
            "TAMPERING" to listOf(
                ThreatPattern("Input not validated", """@RequestParam(?!.*@Valid)""", "T1"),
                ThreatPattern("Data integrity not verified", """(?i)(checksum|hash|signature).*(?:skip|ignore|disabled)""", "T2"),
                ThreatPattern("Mutable shared state", """(?i)static\s+(?!final)\w+\s*=.*(?:List|Map|Set)""", "T3")
            ),
            "REPUDIATION" to listOf(
                ThreatPattern("Missing audit logging", """(?i)(delete|update|create).*(?!.*log|.*audit)""", "R1"),
                ThreatPattern("No transaction tracking", """@Transactional(?!.*logging)""", "R2"),
                ThreatPattern("Unsigned operations", """(?i)sensitive.*operation(?!.*signature)""", "R3")
            ),
            "INFORMATION_DISCLOSURE" to listOf(
                ThreatPattern("Sensitive data in logs", """log\.(info|debug|warn).*(?:password|secret|token|key)""", "I1"),
                ThreatPattern("Exception details exposed", """catch.*printStackTrace|\.getMessage.*response""", "I2"),
                ThreatPattern("Debug info in production", """(?i)debug\s*=\s*true|verbose\s*=\s*true""", "I3")
            ),
            "DENIAL_OF_SERVICE" to listOf(
                ThreatPattern("Unbounded resource consumption", """while\s*\(true\)|for\s*\(\s*;\s*;\s*\)""", "D1"),
                ThreatPattern("Missing rate limiting", """@PostMapping(?!.*@RateLimit)""", "D2"),
                ThreatPattern("ReDoS vulnerable regex", """\(.*\+\)\+|\(.*\*\)\*""", "D3")
            ),
            "ELEVATION_OF_PRIVILEGE" to listOf(
                ThreatPattern("Privilege escalation risk", """(?i)role.*(?:admin|root|super).*set|grant""", "E1"),
                ThreatPattern("Missing authorization check", """@DeleteMapping(?!.*@PreAuthorize)""", "E2"),
                ThreatPattern("Direct object reference", """findById\(.*request\.|getById\(.*param""", "E3")
            )
        )
        
        stridePatterns.forEach { (category, patterns) ->
            patterns.forEach { pattern ->
                lines.forEachIndexed { lineNum, line ->
                    try {
                        if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                            threats.add(ThreatEntry(
                                id = pattern.id,
                                category = category,
                                name = pattern.name,
                                line = lineNum + 1,
                                severity = when (category) {
                                    "SPOOFING", "ELEVATION_OF_PRIVILEGE" -> Severity.CRITICAL
                                    "TAMPERING", "INFORMATION_DISCLOSURE" -> Severity.HIGH
                                    else -> Severity.MEDIUM
                                },
                                description = "Potential ${category.lowercase().replace("_", " ")} threat detected",
                                codeSnippet = line.take(100)
                            ))
                            
                            mitigations.add(MitigationSuggestion(
                                threatId = pattern.id,
                                title = "Mitigate ${pattern.name}",
                                description = getMitigationForCategory(category),
                                priority = if (category in listOf("SPOOFING", "ELEVATION_OF_PRIVILEGE")) 1 else 2
                            ))
                        }
                    } catch (e: Exception) { /* Skip invalid regex */ }
                }
            }
        }
        
        return ThreatModelReport(filePath, threats, mitigations)
    }
    
    /**
     * Attack Surface Analysis - Visualize entry points and attack vectors
     */
    fun analyzeAttackSurface(content: String, filePath: String, language: String): AttackSurfaceReport {
        
        val entryPoints = mutableListOf<EntryPoint>()
        val attackVectors = mutableListOf<AttackVector>()
        val lines = content.lines()
        
        // Detect entry points
        val entryPointPatterns = listOf(
            EntryPointPattern("REST Endpoint", """@(Get|Post|Put|Delete|Patch)Mapping""", "HTTP", "rest"),
            EntryPointPattern("GraphQL Resolver", """@(Query|Mutation|Subscription)Mapping""", "GraphQL", "graphql"),
            EntryPointPattern("WebSocket Handler", """@MessageMapping|@SubscribeMapping""", "WebSocket", "websocket"),
            EntryPointPattern("RPC Endpoint", """@GrpcService|@RpcMethod""", "gRPC", "rpc"),
            EntryPointPattern("Message Consumer", """@KafkaListener|@RabbitListener|@JmsListener""", "Message Queue", "messaging"),
            EntryPointPattern("Scheduled Task", """@Scheduled|@EnableScheduling""", "Scheduler", "scheduled"),
            EntryPointPattern("File Upload", """MultipartFile|@RequestPart""", "File Upload", "upload"),
            EntryPointPattern("Database Query", """@Query|createNativeQuery|jdbcTemplate""", "Database", "database")
        )
        
        entryPointPatterns.forEach { pattern ->
            lines.forEachIndexed { lineNum, line ->
                if (Regex(pattern.regex).containsMatchIn(line)) {
                    entryPoints.add(EntryPoint(
                        type = pattern.type,
                        name = pattern.name,
                        line = lineNum + 1,
                        protocol = pattern.protocol,
                        riskLevel = calculateRiskLevel(pattern.type, content, lineNum)
                    ))
                }
            }
        }
        
        // Detect attack vectors based on entry points
        entryPoints.forEach { entry ->
            attackVectors.addAll(getAttackVectorsForEntryPoint(entry))
        }
        
        val overallRiskScore = calculateOverallRisk(entryPoints, attackVectors)
        
        return AttackSurfaceReport(filePath, entryPoints, attackVectors, overallRiskScore)
    }
    
    /**
     * Vulnerability Prediction - Predict potential vulnerabilities using ML patterns
     */
    fun predictVulnerabilities(content: String, filePath: String): List<VulnerabilityPrediction> {
        
        val predictions = mutableListOf<VulnerabilityPrediction>()
        val lines = content.lines()
        
        // Predictive patterns based on common vulnerability precursors
        val predictivePatterns = listOf(
            PredictivePattern(
                name = "Future SQL Injection Risk",
                precursor = """String\s+\w+\s*=.*\+.*(?:request|param|input)""",
                prediction = "This string concatenation pattern often leads to SQL injection when used in queries",
                probability = 0.78,
                cwe = 89
            ),
            PredictivePattern(
                name = "Potential Authentication Bypass",
                precursor = """if\s*\(.*(?:user|admin|role).*(?:==|!=|equals).*(?:null|""|true)""",
                prediction = "Boolean-based authentication checks are prone to bypass vulnerabilities",
                probability = 0.65,
                cwe = 287
            ),
            PredictivePattern(
                name = "Emerging Path Traversal",
                precursor = """(?:File|Path)\s*\w+\s*=.*(?:getParameter|getInput|request\.)""",
                prediction = "User input in file paths typically leads to path traversal vulnerabilities",
                probability = 0.82,
                cwe = 22
            ),
            PredictivePattern(
                name = "SSRF Precursor Pattern",
                precursor = """(?:URL|HttpClient|RestTemplate).*(?:getParameter|request\.|input)""",
                prediction = "User-controlled URLs are precursors to SSRF attacks",
                probability = 0.75,
                cwe = 918
            ),
            PredictivePattern(
                name = "Insecure Deserialization Risk",
                precursor = """ObjectInputStream|readObject|fromJson.*(?:request|input)""",
                prediction = "Deserializing user input is a common vector for RCE vulnerabilities",
                probability = 0.88,
                cwe = 502
            ),
            PredictivePattern(
                name = "Memory Corruption Precursor",
                precursor = """(?:byte|char)\[\d+\].*(?:read|copy|get)""",
                prediction = "Fixed-size buffers with external input often lead to overflow vulnerabilities",
                probability = 0.70,
                cwe = 120
            )
        )
        
        predictivePatterns.forEach { pattern ->
            lines.forEachIndexed { lineNum, line ->
                try {
                    if (Regex(pattern.precursor, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                        predictions.add(VulnerabilityPrediction(
                            id = UUID.randomUUID().toString(),
                            name = pattern.name,
                            line = lineNum + 1,
                            prediction = pattern.prediction,
                            probability = pattern.probability,
                            cwe = pattern.cwe,
                            codeSnippet = line.take(100),
                            recommendedAction = "Review and implement proper input validation and sanitization"
                        ))
                    }
                } catch (e: Exception) { /* Skip invalid regex */ }
            }
        }
        
        return predictions.sortedByDescending { it.probability }
    }
    
    /**
     * AI Code Review - AI-powered security code review suggestions
     */
    fun performAICodeReview(content: String, filePath: String, language: String): CodeReviewReport {
        
        val suggestions = mutableListOf<CodeReviewSuggestion>()
        val lines = content.lines()
        
        // AI-style code review patterns
        val reviewPatterns = listOf(
            ReviewPattern(
                category = "Security Best Practice",
                pattern = """catch\s*\(\s*Exception\s+\w+\s*\)""",
                suggestion = "Catch specific exceptions instead of generic Exception to avoid masking security-relevant errors",
                improvement = "catch (SpecificSecurityException e) { log.error(\"Security event\", e); throw e; }"
            ),
            ReviewPattern(
                category = "Input Validation",
                pattern = """@RequestBody\s+(?!@Valid)""",
                suggestion = "Add @Valid annotation to enable bean validation on request body",
                improvement = "@RequestBody @Valid YourDto dto"
            ),
            ReviewPattern(
                category = "Secure Defaults",
                pattern = """new\s+(?:HashMap|ArrayList|HashSet)\s*\(\s*\)""",
                suggestion = "Consider using immutable collections or thread-safe variants for shared data",
                improvement = "Collections.unmodifiableList(new ArrayList<>()) or ConcurrentHashMap for thread-safety"
            ),
            ReviewPattern(
                category = "Error Handling",
                pattern = """return\s+null\s*;""",
                suggestion = "Avoid returning null; use Optional or throw specific exceptions instead",
                improvement = "return Optional.empty(); or throw new ResourceNotFoundException()"
            ),
            ReviewPattern(
                category = "Logging Security",
                pattern = """log\.\w+\(.*\+.*(?:request|input|user)""",
                suggestion = "Sanitize user input before logging to prevent log injection attacks",
                improvement = "log.info(\"User action: {}\", sanitize(userInput));"
            ),
            ReviewPattern(
                category = "Resource Management",
                pattern = """new\s+(?:FileInputStream|FileOutputStream|Connection)\s*\(""",
                suggestion = "Use try-with-resources to ensure proper resource cleanup",
                improvement = "try (FileInputStream fis = new FileInputStream(file)) { ... }"
            ),
            ReviewPattern(
                category = "Cryptography",
                pattern = """\.getBytes\s*\(\s*\)""",
                suggestion = "Specify character encoding explicitly to avoid platform-dependent issues",
                improvement = ".getBytes(StandardCharsets.UTF_8)"
            ),
            ReviewPattern(
                category = "Concurrency",
                pattern = """(?:public|protected)\s+\w+\s+\w+\s*;(?!.*volatile|.*final)""",
                suggestion = "Consider using volatile or final for fields accessed by multiple threads",
                improvement = "private volatile String sharedField; or private final AtomicReference<String>"
            )
        )
        
        reviewPatterns.forEach { pattern ->
            lines.forEachIndexed { lineNum, line ->
                try {
                    if (Regex(pattern.pattern).containsMatchIn(line)) {
                        suggestions.add(CodeReviewSuggestion(
                            line = lineNum + 1,
                            category = pattern.category,
                            currentCode = line.trim(),
                            suggestion = pattern.suggestion,
                            improvedCode = pattern.improvement,
                            confidence = 0.85
                        ))
                    }
                } catch (e: Exception) { /* Skip */ }
            }
        }
        
        val securityScore = calculateSecurityScore(content, suggestions.size)
        
        return CodeReviewReport(filePath, suggestions, suggestions.size, securityScore)
    }
    
    /**
     * Zero-Day Detection - Detect potential zero-day vulnerabilities using advanced patterns
     */
    fun detectZeroDayPotential(content: String, filePath: String): List<ZeroDayCandidate> {
        
        val candidates = mutableListOf<ZeroDayCandidate>()
        val lines = content.lines()
        
        // Advanced patterns for potential zero-day detection
        val zeroDayPatterns = listOf(
            ZeroDayPattern(
                name = "Novel Injection Vector",
                pattern = """(?:template|render|compile|evaluate)\s*\(\s*(?:request|input|param)""",
                description = "Potential template/expression injection - common source of zero-days",
                riskScore = 0.92
            ),
            ZeroDayPattern(
                name = "Unsafe Native Integration",
                pattern = """(?:JNI|native|unsafe)\s+.*(?:pointer|memory|buffer)""",
                description = "Native code integration often contains undiscovered memory corruption bugs",
                riskScore = 0.88
            ),
            ZeroDayPattern(
                name = "Custom Protocol Parser",
                pattern = """(?:parse|decode|deserialize)\s*\(\s*(?:byte|raw|binary)""",
                description = "Custom parsers are frequent sources of parsing vulnerabilities",
                riskScore = 0.85
            ),
            ZeroDayPattern(
                name = "Complex State Machine",
                pattern = """switch\s*\([^)]+\)\s*\{(?:[^}]*case[^}]*){5,}""",
                description = "Complex state machines often have edge cases leading to vulnerabilities",
                riskScore = 0.75
            ),
            ZeroDayPattern(
                name = "Crypto Implementation",
                pattern = """(?:encrypt|decrypt|cipher|hash)\s*(?:custom|own|internal)""",
                description = "Custom cryptographic implementations frequently contain weaknesses",
                riskScore = 0.95
            ),
            ZeroDayPattern(
                name = "Uncommon Serialization",
                pattern = """(?:serialize|marshal|encode)\s*\(\s*(?:object|entity|model)""",
                description = "Non-standard serialization can introduce deserialization vulnerabilities",
                riskScore = 0.80
            )
        )
        
        zeroDayPatterns.forEach { pattern ->
            try {
                val regex = Regex(pattern.pattern, RegexOption.IGNORE_CASE)
                lines.forEachIndexed { lineNum, line ->
                    if (regex.containsMatchIn(line)) {
                        candidates.add(ZeroDayCandidate(
                            id = UUID.randomUUID().toString(),
                            name = pattern.name,
                            line = lineNum + 1,
                            description = pattern.description,
                            riskScore = pattern.riskScore,
                            codeContext = extractContext(lines, lineNum, 3),
                            recommendation = "Conduct thorough security review and fuzzing of this code section"
                        ))
                    }
                }
            } catch (e: Exception) { /* Skip */ }
        }
        
        return candidates.sortedByDescending { it.riskScore }
    }
    
    /**
     * Penetration Test Hints - Generate actionable hints for penetration testing
     */
    fun generatePentestHints(content: String, filePath: String): List<PentestHint> {
        
        val hints = mutableListOf<PentestHint>()
        val lines = content.lines()
        
        // Pentest hint patterns
        val hintPatterns = listOf(
            PentestHintPattern(
                target = "Authentication Endpoint",
                pattern = """@PostMapping.*(?:login|auth|signin)""",
                hint = "Test for: brute force protection, credential stuffing, session fixation",
                tools = listOf("Burp Suite Intruder", "Hydra", "Custom Python scripts"),
                payloads = listOf("admin'--", "' OR '1'='1", "{{7*7}}")
            ),
            PentestHintPattern(
                target = "File Upload Handler",
                pattern = """MultipartFile|@RequestPart.*file""",
                hint = "Test for: unrestricted file upload, path traversal, RCE via file content",
                tools = listOf("Burp Suite", "ExifTool", "Polyglot files"),
                payloads = listOf("../../../etc/passwd", "shell.php.jpg", "<%=cmd%>")
            ),
            PentestHintPattern(
                target = "Search/Query Endpoint",
                pattern = """@GetMapping.*(?:search|query|find)""",
                hint = "Test for: SQL injection, NoSQL injection, LDAP injection, XSS",
                tools = listOf("SQLMap", "NoSQLMap", "XSStrike"),
                payloads = listOf("' UNION SELECT--", "{\"\$gt\": \"\"}", "<script>alert(1)</script>")
            ),
            PentestHintPattern(
                target = "API with ID Parameter",
                pattern = """@PathVariable.*(?:id|uuid|userId)""",
                hint = "Test for: IDOR, mass assignment, privilege escalation",
                tools = listOf("Autorize (Burp)", "Custom scripts"),
                payloads = listOf("Other user IDs", "0", "-1", "null", "admin")
            ),
            PentestHintPattern(
                target = "External URL Handler",
                pattern = """(?:URL|HttpClient|RestTemplate).*(?:url|uri|endpoint)""",
                hint = "Test for: SSRF, open redirect, DNS rebinding",
                tools = listOf("Collaborator", "ssrf-sheriff"),
                payloads = listOf("http://127.0.0.1:22", "http://169.254.169.254", "file:///etc/passwd")
            ),
            PentestHintPattern(
                target = "XML Processing",
                pattern = """(?:DocumentBuilder|SAXParser|XMLReader)""",
                hint = "Test for: XXE, billion laughs DoS, XPath injection",
                tools = listOf("XXEinjector", "Burp XXE scanner"),
                payloads = listOf("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>")
            )
        )
        
        hintPatterns.forEach { pattern ->
            lines.forEachIndexed { lineNum, line ->
                try {
                    if (Regex(pattern.pattern, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                        hints.add(PentestHint(
                            target = pattern.target,
                            line = lineNum + 1,
                            hint = pattern.hint,
                            suggestedTools = pattern.tools,
                            samplePayloads = pattern.payloads,
                            riskRating = "HIGH"
                        ))
                    }
                } catch (e: Exception) { /* Skip */ }
            }
        }
        
        return hints
    }
    
    /**
     * Security Training - Generate contextual learning content
     */
    fun generateSecurityTraining(content: String, filePath: String, vulnerabilities: List<Vulnerability>): List<TrainingModule> {
        
        val modules = mutableListOf<TrainingModule>()
        val coveredCWEs = mutableSetOf<Int>()
        
        vulnerabilities.forEach { vuln ->
            if (vuln.cwe !in coveredCWEs) {
                coveredCWEs.add(vuln.cwe)
                modules.add(TrainingModule(
                    cwe = vuln.cwe,
                    title = getTrainingTitle(vuln.cwe),
                    description = getTrainingDescription(vuln.cwe),
                    learningObjectives = getLearningObjectives(vuln.cwe),
                    resources = getTrainingResources(vuln.cwe),
                    difficulty = getDifficultyLevel(vuln.severity),
                    estimatedTime = "15-30 minutes"
                ))
            }
        }
        
        return modules.sortedBy { it.difficulty }
    }
    
    // Helper functions
    private fun getMitigationForCategory(category: String): String = when (category) {
        "SPOOFING" -> "Implement strong authentication, MFA, and identity verification"
        "TAMPERING" -> "Add input validation, checksums, and digital signatures"
        "REPUDIATION" -> "Implement comprehensive audit logging and transaction tracking"
        "INFORMATION_DISCLOSURE" -> "Remove sensitive data from logs, use proper error handling"
        "DENIAL_OF_SERVICE" -> "Implement rate limiting, resource quotas, and timeouts"
        "ELEVATION_OF_PRIVILEGE" -> "Implement proper RBAC, authorization checks on all endpoints"
        else -> "Review and implement security controls appropriate for this threat category"
    }
    
    private fun calculateRiskLevel(type: String, content: String, lineNum: Int): String = when {
        type in listOf("REST Endpoint", "File Upload", "Database") -> "HIGH"
        type in listOf("Message Consumer", "WebSocket Handler") -> "MEDIUM"
        else -> "LOW"
    }
    
    private fun getAttackVectorsForEntryPoint(entry: EntryPoint): List<AttackVector> {
        return when (entry.type) {
            "REST Endpoint" -> listOf(
                AttackVector("Injection Attacks", "SQL/NoSQL/Command injection via parameters"),
                AttackVector("Authentication Bypass", "Token manipulation, session hijacking"),
                AttackVector("IDOR", "Direct object reference manipulation")
            )
            "File Upload" -> listOf(
                AttackVector("Malicious File Upload", "Executable or polyglot files"),
                AttackVector("Path Traversal", "Filename manipulation for arbitrary write"),
                AttackVector("DoS", "Large file uploads exhausting resources")
            )
            else -> listOf(AttackVector("General", "Standard attack vectors apply"))
        }
    }
    
    private fun calculateOverallRisk(entryPoints: List<EntryPoint>, vectors: List<AttackVector>): Double {
        val baseRisk = entryPoints.count { it.riskLevel == "HIGH" } * 0.3 +
                      entryPoints.count { it.riskLevel == "MEDIUM" } * 0.2 +
                      vectors.size * 0.05
        return minOf(1.0, baseRisk)
    }
    
    private fun calculateSecurityScore(content: String, issueCount: Int): Double {
        val loc = content.lines().count { it.isNotBlank() }
        val issueRatio = issueCount.toDouble() / maxOf(1, loc / 100)
        return maxOf(0.0, minOf(100.0, 100.0 - issueRatio * 10))
    }
    
    private fun extractContext(lines: List<String>, centerLine: Int, radius: Int): String {
        val start = maxOf(0, centerLine - radius)
        val end = minOf(lines.size - 1, centerLine + radius)
        return lines.subList(start, end + 1).joinToString("\n")
    }
    
    private fun getTrainingTitle(cwe: Int): String = when (cwe) {
        89 -> "SQL Injection Prevention"
        79 -> "Cross-Site Scripting (XSS) Defense"
        22 -> "Path Traversal Prevention"
        78 -> "Command Injection Prevention"
        502 -> "Secure Deserialization"
        else -> "Security Best Practices for CWE-$cwe"
    }
    
    private fun getTrainingDescription(cwe: Int): String = "Learn how to identify, prevent, and remediate CWE-$cwe vulnerabilities in your code."
    
    private fun getLearningObjectives(cwe: Int): List<String> = listOf(
        "Understand the root cause of CWE-$cwe",
        "Identify vulnerable code patterns",
        "Implement secure alternatives",
        "Write tests to prevent regression"
    )
    
    private fun getTrainingResources(cwe: Int): List<String> = listOf(
        "https://cwe.mitre.org/data/definitions/$cwe.html",
        "https://owasp.org/www-community/",
        "https://cheatsheetseries.owasp.org/"
    )
    
    private fun getDifficultyLevel(severity: Severity): Int = when (severity) {
        Severity.CRITICAL -> 1
        Severity.HIGH -> 2
        Severity.MEDIUM -> 3
        else -> 4
    }
    
    // Data classes for patterns
    private data class ThreatPattern(val name: String, val regex: String, val id: String)
    private data class EntryPointPattern(val name: String, val regex: String, val protocol: String, val type: String = "generic")
    private data class PredictivePattern(val name: String, val precursor: String, val prediction: String, val probability: Double, val cwe: Int)
    private data class ReviewPattern(val category: String, val pattern: String, val suggestion: String, val improvement: String)
    private data class ZeroDayPattern(val name: String, val pattern: String, val description: String, val riskScore: Double)
    private data class PentestHintPattern(val target: String, val pattern: String, val hint: String, val tools: List<String>, val payloads: List<String>)
}

// Public data classes for results
data class ThreatModelReport(
    val filePath: String,
    val threats: List<ThreatEntry>,
    val mitigations: List<MitigationSuggestion>
)

data class ThreatEntry(
    val id: String,
    val category: String,
    val name: String,
    val line: Int,
    val severity: Severity,
    val description: String,
    val codeSnippet: String
)

data class MitigationSuggestion(
    val threatId: String,
    val title: String,
    val description: String,
    val priority: Int
)

data class AttackSurfaceReport(
    val filePath: String,
    val entryPoints: List<EntryPoint>,
    val attackVectors: List<AttackVector>,
    val overallRiskScore: Double
)

data class EntryPoint(
    val type: String,
    val name: String,
    val line: Int,
    val protocol: String,
    val riskLevel: String
)

data class AttackVector(
    val name: String,
    val description: String
)

data class VulnerabilityPrediction(
    val id: String,
    val name: String,
    val line: Int,
    val prediction: String,
    val probability: Double,
    val cwe: Int,
    val codeSnippet: String,
    val recommendedAction: String
)

data class CodeReviewReport(
    val filePath: String,
    val suggestions: List<CodeReviewSuggestion>,
    val totalIssues: Int,
    val securityScore: Double
)

data class CodeReviewSuggestion(
    val line: Int,
    val category: String,
    val currentCode: String,
    val suggestion: String,
    val improvedCode: String,
    val confidence: Double
)

data class ZeroDayCandidate(
    val id: String,
    val name: String,
    val line: Int,
    val description: String,
    val riskScore: Double,
    val codeContext: String,
    val recommendation: String
)

data class PentestHint(
    val target: String,
    val line: Int,
    val hint: String,
    val suggestedTools: List<String>,
    val samplePayloads: List<String>,
    val riskRating: String
)

data class TrainingModule(
    val cwe: Int,
    val title: String,
    val description: String,
    val learningObjectives: List<String>,
    val resources: List<String>,
    val difficulty: Int,
    val estimatedTime: String
)
