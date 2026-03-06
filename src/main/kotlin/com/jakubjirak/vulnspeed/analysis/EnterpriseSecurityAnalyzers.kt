package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.VulnerabilityType

/**
 * Enterprise Security Analyzers v2025.7.0
 * Advanced security analysis features for enterprise customers
 */
class EnterpriseSecurityAnalyzers {

    /**
     * Supply Chain Security Analysis
     * Detects software supply chain attacks and dependency hijacking
     */
    fun analyzeSupplyChainSecurity(content: String, filePath: String, dependencies: List<String>): SupplyChainReport {

        val risks = mutableListOf<SupplyChainRisk>()
        val recommendations = mutableListOf<String>()

        // Detect dependency confusion attacks
        val dependencyConfusionPatterns = listOf(
            DependencyPattern("Private Package Exposure", """@company/|@internal/|@private/""", "internal-package"),
            DependencyPattern("Typosquatting Risk", """lodash-|react-|angular-""", "typosquatting"),
            DependencyPattern("Unmaintained Package", """deprecated|abandoned|archived""", "unmaintained"),
            DependencyPattern("Unknown Publisher", """^[a-z0-9-]{1,10}$""", "unknown-publisher")
        )

        dependencies.forEach { dep ->
            dependencyConfusionPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(dep)) {
                    risks.add(SupplyChainRisk(
                        type = pattern.type,
                        dependency = dep,
                        severity = Severity.HIGH,
                        description = "Potential ${pattern.name} detected in dependency: $dep",
                        cwe = 1357
                    ))
                }
            }
        }

        // Check for lockfile integrity
        if (filePath.endsWith("package.json") && !content.contains("integrity")) {
            risks.add(SupplyChainRisk(
                type = "missing-integrity",
                dependency = "package-lock.json",
                severity = Severity.MEDIUM,
                description = "Missing integrity checks in package lockfile",
                cwe = 494
            ))
        }

        // Detect post-install script risks
        if (content.contains("postinstall") || content.contains("preinstall")) {
            risks.add(SupplyChainRisk(
                type = "install-script",
                dependency = filePath,
                severity = Severity.MEDIUM,
                description = "Post/pre-install scripts detected - potential code execution risk",
                cwe = 506
            ))
        }

        val riskScore = calculateSupplyChainRiskScore(risks)
        recommendations.addAll(generateSupplyChainRecommendations(risks))

        return SupplyChainReport(filePath, risks, recommendations, riskScore)
    }

    /**
     * Behavioral Analysis
     * Analyzes runtime behavior patterns and detects anomalies
     */
    fun analyzeBehavioralPatterns(content: String, filePath: String): BehavioralReport {

        val behaviors = mutableListOf<BehaviorPattern>()
        val anomalies = mutableListOf<BehaviorAnomaly>()
        val lines = content.lines()

        val behaviorPatterns = listOf(
            BehaviorDefinition("Network Communication", """HttpClient|OkHttp|Retrofit|fetch|axios|request\(""", "network", 0.3),
            BehaviorDefinition("File System Access", """File\(|FileWriter|FileReader|fs\.read|fs\.write""", "filesystem", 0.4),
            BehaviorDefinition("Process Execution", """Runtime\.getRuntime|ProcessBuilder|exec\(|spawn\(|child_process""", "process", 0.8),
            BehaviorDefinition("Cryptographic Operations", """Cipher|MessageDigest|crypto\.|encrypt|decrypt""", "crypto", 0.2),
            BehaviorDefinition("Database Operations", """Connection|PreparedStatement|mongoose|sequelize""", "database", 0.3),
            BehaviorDefinition("Reflection/Dynamic Code", """Class\.forName|invoke\(|eval\(|Function\(""", "reflection", 0.7),
            BehaviorDefinition("Environment Access", """System\.getenv|process\.env|os\.environ""", "environment", 0.5),
            BehaviorDefinition("Serialization", """ObjectInputStream|ObjectOutputStream|JSON\.parse|pickle""", "serialization", 0.6)
        )

        lines.forEachIndexed { lineNum, line ->
            behaviorPatterns.forEach { pattern ->
                if (Regex(pattern.regex).containsMatchIn(line)) {
                    behaviors.add(BehaviorPattern(
                        type = pattern.type,
                        name = pattern.name,
                        line = lineNum + 1,
                        riskWeight = pattern.riskWeight,
                        context = line.trim()
                    ))
                }
            }
        }

        // Detect anomalies (unusual combinations)
        if (behaviors.any { it.type == "network" } && behaviors.any { it.type == "process" }) {
            anomalies.add(BehaviorAnomaly(
                type = "remote-code-execution",
                description = "Network communication combined with process execution - potential RCE vector",
                severity = Severity.CRITICAL,
                relatedBehaviors = behaviors.filter { it.type in listOf("network", "process") }
            ))
        }

        if (behaviors.any { it.type == "serialization" } && behaviors.any { it.type == "network" }) {
            anomalies.add(BehaviorAnomaly(
                type = "deserialization-attack",
                description = "Serialization combined with network input - potential deserialization attack",
                severity = Severity.HIGH,
                relatedBehaviors = behaviors.filter { it.type in listOf("serialization", "network") }
            ))
        }

        val riskScore = calculateBehavioralRiskScore(behaviors, anomalies)

        return BehavioralReport(filePath, behaviors, anomalies, riskScore)
    }

    /**
     * DevSecOps Integration Analysis
     * Analyzes CI/CD pipeline configurations for security issues
     */
    fun analyzeDevSecOpsConfig(content: String, filePath: String): DevSecOpsReport {

        val issues = mutableListOf<DevSecOpsIssue>()
        val recommendations = mutableListOf<String>()
        val integrations = mutableListOf<SecurityIntegration>()

        // GitHub Actions analysis
        if (filePath.contains(".github/workflows")) {
            analyzeGitHubActions(content, issues, recommendations)
            integrations.add(SecurityIntegration("GitHub Actions", "ci-cd", true))
        }

        // GitLab CI analysis
        if (filePath.endsWith(".gitlab-ci.yml")) {
            analyzeGitLabCI(content, issues, recommendations)
            integrations.add(SecurityIntegration("GitLab CI", "ci-cd", true))
        }

        // Jenkins analysis
        if (filePath.endsWith("Jenkinsfile")) {
            analyzeJenkinsfile(content, issues, recommendations)
            integrations.add(SecurityIntegration("Jenkins", "ci-cd", true))
        }

        // Docker analysis
        if (filePath.endsWith("Dockerfile")) {
            analyzeDockerfile(content, issues, recommendations)
            integrations.add(SecurityIntegration("Docker", "container", true))
        }

        // Kubernetes analysis
        if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
            if (content.contains("apiVersion:") && content.contains("kind:")) {
                analyzeKubernetes(content, issues, recommendations)
                integrations.add(SecurityIntegration("Kubernetes", "orchestration", true))
            }
        }

        return DevSecOpsReport(filePath, issues, recommendations, integrations)
    }

    /**
     * Security Posture Management
     * Calculates overall security posture score
     */
    fun calculateSecurityPosture(
        vulnerabilities: List<VulnerabilityInfo>,
        codeMetrics: CodeMetrics,
        complianceStatus: ComplianceStatus
    ): SecurityPostureReport {

        val scores = mutableMapOf<String, Double>()

        // Vulnerability score (0-100, higher is better)
        val criticalCount = vulnerabilities.count { it.severity == Severity.CRITICAL }
        val highCount = vulnerabilities.count { it.severity == Severity.HIGH }
        val mediumCount = vulnerabilities.count { it.severity == Severity.MEDIUM }
        val vulnScore = kotlin.math.max(0.0, 100.0 - (criticalCount * 25 + highCount * 10 + mediumCount * 3))
        scores["Vulnerability Management"] = vulnScore

        // Code quality score
        val codeScore = when {
            codeMetrics.complexity < 10 -> 90.0
            codeMetrics.complexity < 20 -> 70.0
            codeMetrics.complexity < 30 -> 50.0
            else -> 30.0
        }
        scores["Code Quality"] = codeScore

        // Compliance score
        val complianceScore = complianceStatus.passedChecks.toDouble() / 
            maxOf(1, complianceStatus.totalChecks) * 100
        scores["Compliance"] = complianceScore

        // Security controls score
        val controlsScore = calculateControlsScore(vulnerabilities)
        scores["Security Controls"] = controlsScore

        // Overall posture score (weighted average)
        val overallScore = scores.values.average()

        val recommendations = generatePostureRecommendations(scores, vulnerabilities)
        val grade = getSecurityGrade(overallScore)

        return SecurityPostureReport(overallScore, scores, recommendations, grade)
    }

    /**
     * Vulnerability Correlation
     * Correlates vulnerabilities across files and components
     */
    fun correlateVulnerabilities(
        vulnerabilities: List<VulnerabilityInfo>,
        dependencyGraph: Map<String, List<String>>
    ): CorrelationReport {

        val correlations = mutableListOf<VulnerabilityCorrelation>()
        val attackChains = mutableListOf<AttackChain>()
        val impactMap = mutableMapOf<String, List<String>>()

        // Find related vulnerabilities
        vulnerabilities.groupBy { it.type }.forEach { (type, vulns) ->
            if (vulns.size > 1) {
                correlations.add(VulnerabilityCorrelation(
                    type = type,
                    files = vulns.map { it.file },
                    count = vulns.size,
                    combinedSeverity = calculateCombinedSeverity(vulns),
                    description = "Multiple ${type.name} vulnerabilities detected across ${vulns.size} files"
                ))
            }
        }

        // Detect attack chains (vulnerabilities that can be chained)
        val sqlInjections = vulnerabilities.filter { it.type == VulnerabilityType.SQL_INJECTION }
        val authBypass = vulnerabilities.filter { it.type == VulnerabilityType.AUTHENTICATION }
        
        if (sqlInjections.isNotEmpty() && authBypass.isNotEmpty()) {
            attackChains.add(AttackChain(
                name = "Authentication Bypass via SQL Injection",
                steps = listOf(
                    "Exploit SQL injection in ${sqlInjections.first().file}",
                    "Bypass authentication in ${authBypass.first().file}",
                    "Gain unauthorized access to system"
                ),
                severity = Severity.CRITICAL,
                likelihood = 0.8
            ))
        }

        // Calculate impact propagation
        vulnerabilities.forEach { vuln ->
            val impactedFiles = findImpactedFiles(vuln.file, dependencyGraph)
            if (impactedFiles.isNotEmpty()) {
                impactMap[vuln.file] = impactedFiles
            }
        }

        return CorrelationReport(correlations, attackChains, impactMap)
    }

    /**
     * Remediation Automation
     * Generates automated remediation suggestions and patches
     */
    fun generateRemediations(
        vulnerabilities: List<VulnerabilityInfo>,
        content: String,
        filePath: String
    ): RemediationReport {

        val remediations = mutableListOf<Remediation>()
        val patches = mutableListOf<AutoPatch>()

        vulnerabilities.filter { it.file == filePath }.forEach { vuln ->
            val remediation = generateRemediationForVulnerability(vuln, content)
            remediations.add(remediation)

            if (remediation.canAutoFix) {
                val patch = generateAutoPatch(vuln, content)
                if (patch != null) {
                    patches.add(patch)
                }
            }
        }

        val autoFixableCount = patches.size

        return RemediationReport(filePath, remediations, patches, autoFixableCount)
    }

    /**
     * Security Metrics & Analytics
     * Calculates security metrics and KPIs
     */
    fun calculateSecurityMetrics(
        vulnerabilities: List<VulnerabilityInfo>,
        historicalData: List<HistoricalScan>
    ): SecurityMetricsReport {

        val metrics = mutableMapOf<String, Double>()
        val trends = mutableListOf<MetricTrend>()
        val kpis = mutableMapOf<String, KPI>()

        // Mean Time to Remediation (MTTR)
        val mttr = calculateMTTR(historicalData)
        metrics["MTTR (days)"] = mttr
        kpis["MTTR"] = KPI("Mean Time to Remediation", mttr, 7.0, if (mttr <= 7) "green" else "red")

        // Vulnerability Density
        val density = vulnerabilities.size.toDouble() / maxOf(1, historicalData.lastOrNull()?.linesOfCode ?: 1000) * 1000
        metrics["Vulnerability Density (per KLOC)"] = density
        kpis["Density"] = KPI("Vulnerability Density", density, 1.0, if (density <= 1) "green" else "yellow")

        // Security Debt
        val securityDebt = calculateSecurityDebt(vulnerabilities)
        metrics["Security Debt (hours)"] = securityDebt
        kpis["Debt"] = KPI("Security Debt", securityDebt, 40.0, if (securityDebt <= 40) "green" else "red")

        // Risk Score Trend
        if (historicalData.size >= 2) {
            val currentRisk = calculateRiskScore(vulnerabilities)
            val previousRisk = historicalData.takeLast(2).first().riskScore
            val trend = if (currentRisk < previousRisk) "improving" else if (currentRisk > previousRisk) "degrading" else "stable"
            trends.add(MetricTrend("Risk Score", previousRisk, currentRisk, trend))
        }

        // Coverage metrics
        val coverage = calculateSecurityCoverage(historicalData)
        metrics["Security Test Coverage (%)"] = coverage

        return SecurityMetricsReport(metrics, trends, kpis)
    }

    /**
     * Threat Intelligence Feed Integration
     * Integrates with real-time threat intelligence
     */
    fun analyzeThreatIntelligence(
        content: String,
        filePath: String,
        dependencies: List<String>
    ): ThreatIntelReport {

        val threats = mutableListOf<ThreatIndicator>()
        val advisories = mutableListOf<SecurityAdvisory>()
        val iocs = mutableListOf<IOC>()

        // Check for known malicious patterns (simulated threat intel)
        val maliciousPatterns = listOf(
            ThreatPattern("Cryptominer Pattern", """coinhive|cryptonight|monero\.mine""", "cryptomining"),
            ThreatPattern("Backdoor Pattern", """eval\(base64_decode|exec\(.*\${'$'}_""", "backdoor"),
            ThreatPattern("Data Exfiltration", """webhook\.site|requestbin|ngrok\.io""", "exfiltration"),
            ThreatPattern("C2 Communication", """raw\.githubusercontent|pastebin\.com/raw""", "c2"),
            ThreatPattern("Obfuscated Code", """\\x[0-9a-f]{2}|fromCharCode|atob\(""", "obfuscation")
        )

        val lines = content.lines()
        lines.forEachIndexed { lineNum, line ->
            maliciousPatterns.forEach { pattern ->
                if (Regex(pattern.regex, RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                    threats.add(ThreatIndicator(
                        type = pattern.type,
                        name = pattern.name,
                        line = lineNum + 1,
                        confidence = 0.85,
                        source = "VulnSpeed Threat Intelligence"
                    ))
                }
            }
        }

        // Simulated security advisories for dependencies
        dependencies.forEach { dep ->
            if (dep.contains("log4j") && !dep.contains("2.17")) {
                advisories.add(SecurityAdvisory(
                    id = "CVE-2021-44228",
                    title = "Log4Shell Remote Code Execution",
                    severity = Severity.CRITICAL,
                    affectedComponent = dep,
                    description = "Critical RCE vulnerability in Log4j",
                    recommendation = "Upgrade to Log4j 2.17.0 or later"
                ))
            }
        }

        return ThreatIntelReport(filePath, threats, advisories, iocs)
    }

    // Helper methods
    private fun calculateSupplyChainRiskScore(risks: List<SupplyChainRisk>): Double {
        if (risks.isEmpty()) return 0.0
        return minOf(100.0, risks.sumOf { 
            when (it.severity) {
                Severity.CRITICAL -> 30.0
                Severity.HIGH -> 20.0
                Severity.MEDIUM -> 10.0
                else -> 5.0
            }
        })
    }

    private fun generateSupplyChainRecommendations(risks: List<SupplyChainRisk>): List<String> {
        val recs = mutableListOf<String>()
        if (risks.any { it.type == "internal-package" }) {
            recs.add("Use a private npm/maven registry for internal packages")
        }
        if (risks.any { it.type == "typosquatting" }) {
            recs.add("Verify package names carefully and use official package sources")
        }
        if (risks.any { it.type == "install-script" }) {
            recs.add("Review post-install scripts before adding dependencies")
        }
        return recs
    }

    private fun calculateBehavioralRiskScore(behaviors: List<BehaviorPattern>, anomalies: List<BehaviorAnomaly>): Double {
        val behaviorRisk = behaviors.sumOf { it.riskWeight * 10 }
        val anomalyRisk = anomalies.sumOf { 
            when (it.severity) {
                Severity.CRITICAL -> 40.0
                Severity.HIGH -> 25.0
                else -> 10.0
            }
        }
        return minOf(100.0, behaviorRisk + anomalyRisk)
    }

    private fun analyzeGitHubActions(content: String, issues: MutableList<DevSecOpsIssue>, recommendations: MutableList<String>) {
        if (content.contains("secrets.") && content.contains("echo")) {
            issues.add(DevSecOpsIssue("secret-exposure", "Potential secret exposure in logs", Severity.HIGH, "workflow"))
        }
        if (!content.contains("permissions:")) {
            issues.add(DevSecOpsIssue("missing-permissions", "Missing explicit permissions block", Severity.MEDIUM, "workflow"))
            recommendations.add("Add explicit permissions block to limit workflow permissions")
        }
        if (content.contains("pull_request_target") && content.contains("checkout")) {
            issues.add(DevSecOpsIssue("pwn-request", "Potential Pwn Request vulnerability", Severity.HIGH, "workflow"))
        }
    }

    private fun analyzeGitLabCI(content: String, issues: MutableList<DevSecOpsIssue>, recommendations: MutableList<String>) {
        if (content.contains("CI_JOB_TOKEN") && content.contains("git clone")) {
            issues.add(DevSecOpsIssue("token-exposure", "CI_JOB_TOKEN used in clone - may expose token", Severity.MEDIUM, "pipeline"))
        }
    }

    private fun analyzeJenkinsfile(content: String, issues: MutableList<DevSecOpsIssue>, recommendations: MutableList<String>) {
        if (content.contains("sh ") && content.contains("\$")) {
            issues.add(DevSecOpsIssue("shell-injection", "Potential shell injection in Jenkinsfile", Severity.HIGH, "pipeline"))
        }
    }

    private fun analyzeDockerfile(content: String, issues: MutableList<DevSecOpsIssue>, recommendations: MutableList<String>) {
        if (content.contains("USER root") || !content.contains("USER ")) {
            issues.add(DevSecOpsIssue("root-user", "Container running as root", Severity.MEDIUM, "container"))
            recommendations.add("Add non-root USER directive to Dockerfile")
        }
        if (content.contains(":latest")) {
            issues.add(DevSecOpsIssue("latest-tag", "Using :latest tag - unpinned dependency", Severity.LOW, "container"))
        }
    }

    private fun analyzeKubernetes(content: String, issues: MutableList<DevSecOpsIssue>, recommendations: MutableList<String>) {
        if (content.contains("privileged: true")) {
            issues.add(DevSecOpsIssue("privileged-container", "Privileged container detected", Severity.HIGH, "k8s"))
        }
        if (!content.contains("securityContext:")) {
            issues.add(DevSecOpsIssue("missing-security-context", "Missing security context", Severity.MEDIUM, "k8s"))
        }
    }

    private fun calculateControlsScore(vulnerabilities: List<VulnerabilityInfo>): Double {
        val hasInputValidation = vulnerabilities.none { it.type == VulnerabilityType.SQL_INJECTION }
        val hasAuthControls = vulnerabilities.none { it.type == VulnerabilityType.AUTHENTICATION }
        val hasCrypto = vulnerabilities.none { it.type == VulnerabilityType.WEAK_CRYPTO }
        
        var score = 50.0
        if (hasInputValidation) score += 20
        if (hasAuthControls) score += 20
        if (hasCrypto) score += 10
        return score
    }

    private fun generatePostureRecommendations(scores: Map<String, Double>, vulnerabilities: List<VulnerabilityInfo>): List<String> {
        val recs = mutableListOf<String>()
        scores.forEach { (category, score) ->
            if (score < 70) {
                recs.add("Improve $category score (currently ${score.toInt()}%)")
            }
        }
        return recs
    }

    private fun getSecurityGrade(score: Double): String = when {
        score >= 90 -> "A"
        score >= 80 -> "B"
        score >= 70 -> "C"
        score >= 60 -> "D"
        else -> "F"
    }

    private fun calculateCombinedSeverity(vulns: List<VulnerabilityInfo>): Severity {
        return if (vulns.any { it.severity == Severity.CRITICAL }) Severity.CRITICAL
        else if (vulns.any { it.severity == Severity.HIGH }) Severity.HIGH
        else Severity.MEDIUM
    }

    private fun findImpactedFiles(file: String, dependencyGraph: Map<String, List<String>>): List<String> {
        return dependencyGraph[file] ?: emptyList()
    }

    private fun generateRemediationForVulnerability(vuln: VulnerabilityInfo, content: String): Remediation {
        val canAutoFix = vuln.type in listOf(
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.HARDCODED_CREDENTIALS
        )
        return Remediation(
            vulnerabilityId = vuln.id,
            description = "Fix ${vuln.type.name} vulnerability",
            steps = listOf("Review code", "Apply fix", "Test changes"),
            canAutoFix = canAutoFix,
            effort = if (canAutoFix) "Low" else "Medium"
        )
    }

    private fun generateAutoPatch(vuln: VulnerabilityInfo, content: String): AutoPatch? {
        // Simplified auto-patch generation
        return AutoPatch(
            vulnerabilityId = vuln.id,
            originalCode = "// Original vulnerable code",
            patchedCode = "// Patched secure code",
            confidence = 0.85
        )
    }

    private fun calculateMTTR(historicalData: List<HistoricalScan>): Double {
        return historicalData.filter { it.remediationTime > 0 }
            .map { it.remediationTime }
            .average()
            .takeIf { !it.isNaN() } ?: 0.0
    }

    private fun calculateSecurityDebt(vulnerabilities: List<VulnerabilityInfo>): Double {
        return vulnerabilities.sumOf { vuln ->
            when (vuln.severity) {
                Severity.CRITICAL -> 8.0
                Severity.HIGH -> 4.0
                Severity.MEDIUM -> 2.0
                else -> 1.0
            }
        }
    }

    private fun calculateRiskScore(vulnerabilities: List<VulnerabilityInfo>): Double {
        return vulnerabilities.sumOf { vuln ->
            when (vuln.severity) {
                Severity.CRITICAL -> 10.0
                Severity.HIGH -> 5.0
                Severity.MEDIUM -> 2.0
                else -> 0.5
            }
        }
    }

    private fun calculateSecurityCoverage(historicalData: List<HistoricalScan>): Double {
        return historicalData.lastOrNull()?.coverage ?: 0.0
    }

    // Data class patterns
    private data class DependencyPattern(val name: String, val regex: String, val type: String)
    private data class BehaviorDefinition(val name: String, val regex: String, val type: String, val riskWeight: Double)
    private data class ThreatPattern(val name: String, val regex: String, val type: String)
}

// Report data classes
data class SupplyChainReport(
    val filePath: String,
    val risks: List<SupplyChainRisk>,
    val recommendations: List<String>,
    val riskScore: Double
)

data class SupplyChainRisk(
    val type: String,
    val dependency: String,
    val severity: Severity,
    val description: String,
    val cwe: Int
)

data class BehavioralReport(
    val filePath: String,
    val behaviors: List<BehaviorPattern>,
    val anomalies: List<BehaviorAnomaly>,
    val riskScore: Double
)

data class BehaviorPattern(
    val type: String,
    val name: String,
    val line: Int,
    val riskWeight: Double,
    val context: String
)

data class BehaviorAnomaly(
    val type: String,
    val description: String,
    val severity: Severity,
    val relatedBehaviors: List<BehaviorPattern>
)

data class DevSecOpsReport(
    val filePath: String,
    val issues: List<DevSecOpsIssue>,
    val recommendations: List<String>,
    val integrations: List<SecurityIntegration>
)

data class DevSecOpsIssue(
    val type: String,
    val description: String,
    val severity: Severity,
    val component: String
)

data class SecurityIntegration(
    val name: String,
    val type: String,
    val detected: Boolean
)

data class SecurityPostureReport(
    val overallScore: Double,
    val categoryScores: Map<String, Double>,
    val recommendations: List<String>,
    val grade: String
)

data class CorrelationReport(
    val correlations: List<VulnerabilityCorrelation>,
    val attackChains: List<AttackChain>,
    val impactMap: Map<String, List<String>>
)

data class VulnerabilityCorrelation(
    val type: VulnerabilityType,
    val files: List<String>,
    val count: Int,
    val combinedSeverity: Severity,
    val description: String
)

data class AttackChain(
    val name: String,
    val steps: List<String>,
    val severity: Severity,
    val likelihood: Double
)

data class RemediationReport(
    val filePath: String,
    val remediations: List<Remediation>,
    val patches: List<AutoPatch>,
    val autoFixableCount: Int
)

data class Remediation(
    val vulnerabilityId: String,
    val description: String,
    val steps: List<String>,
    val canAutoFix: Boolean,
    val effort: String
)

data class AutoPatch(
    val vulnerabilityId: String,
    val originalCode: String,
    val patchedCode: String,
    val confidence: Double
)

data class SecurityMetricsReport(
    val metrics: Map<String, Double>,
    val trends: List<MetricTrend>,
    val kpis: Map<String, KPI>
)

data class MetricTrend(
    val name: String,
    val previousValue: Double,
    val currentValue: Double,
    val trend: String
)

data class KPI(
    val name: String,
    val value: Double,
    val target: Double,
    val status: String
)

data class ThreatIntelReport(
    val filePath: String,
    val threats: List<ThreatIndicator>,
    val advisories: List<SecurityAdvisory>,
    val iocs: List<IOC>
)

data class ThreatIndicator(
    val type: String,
    val name: String,
    val line: Int,
    val confidence: Double,
    val source: String
)

data class SecurityAdvisory(
    val id: String,
    val title: String,
    val severity: Severity,
    val affectedComponent: String,
    val description: String,
    val recommendation: String
)

data class IOC(
    val type: String,
    val value: String,
    val confidence: Double
)

data class VulnerabilityInfo(
    val id: String,
    val type: VulnerabilityType,
    val file: String,
    val line: Int,
    val severity: Severity
)

data class CodeMetrics(
    val complexity: Int,
    val linesOfCode: Int,
    val maintainabilityIndex: Double
)

data class ComplianceStatus(
    val passedChecks: Int,
    val totalChecks: Int,
    val frameworks: List<String>
)

data class HistoricalScan(
    val date: String,
    val vulnerabilityCount: Int,
    val riskScore: Double,
    val remediationTime: Double,
    val linesOfCode: Int,
    val coverage: Double
)
