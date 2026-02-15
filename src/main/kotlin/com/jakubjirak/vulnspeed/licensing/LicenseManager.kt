package com.jakubjirak.vulnspeed.licensing

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.util.xmlb.XmlSerializerUtil
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.math.min

/**
 * License tiers - defines available features
 */
enum class LicenseTier {
    FREE {
        override val maxScansPerDay = 50
        override val maxProjectSize = 100_000 // LOC
        override val gpuAcceleration = false
        override val advancedPatterns = false
        override val customRules = false
        override val prioritySupport = false
        override val teamCollaboration = false
        override val cicdIntegration = false
        override val securityReports = false
        override val aiCodeAnalysis = false
        override val dependencyScanning = false
        override val complianceDashboard = false
        override val sbomGeneration = false
        override val secretDetection = false
        override val iacScanning = false
        override val apiSecurityTesting = false
        override val codeComplexityAnalysis = false
        // v2025.6.0 features
        override val threatModeling = false
        override val attackSurfaceAnalysis = false
        override val realtimeCollaboration = false
        override val securityTraining = false
        override val vulnerabilityPrediction = false
        override val codeReviewAI = false
        override val penetrationTestHints = false
        override val zeroDayDetection = false
        // v2025.7.0 features
        override val supplyChainSecurity = false
        override val behavioralAnalysis = false
        override val devSecOpsIntegration = false
        override val securityPostureManagement = false
        override val vulnerabilityCorrelation = false
        override val remediationAutomation = false
        override val securityMetricsAnalytics = false
        override val threatIntelligenceFeed = false
        // v2025.8.0 features
        override val quantumSafeCryptoScan = false
        override val microservicesSecurity = false
        override val cloudSecurityPosture = false
        override val dataFlowTracking = false
        override val complianceAutomation = false
        override val securityChaosTesting = false
        override val apiFuzzing = false
        override val identityAccessAnalysis = false
        // v2025.9.0 features
        override val zeroTrustValidation = false
        override val graphqlSecurity = false
        override val websocketSecurity = false
        override val ssrfDeepScan = false
        override val insecureDeserialization = false
        // v2025.10.0 features
        override val memorySafetyAnalysis = false
        override val firmwareSecurityScan = false
        override val blockchainSmartContract = false
        override val oauthOidcAnalysis = false
        override val cryptographicAgility = false
        override val sidecarProxySecurity = false
        override val edgeComputingSecurity = false
        override val displayName = "Free"
        override val monthlyPrice = 0.0
    },
    PROFESSIONAL {
        override val maxScansPerDay = 1000
        override val maxProjectSize = 1_000_000 // LOC
        override val gpuAcceleration = true
        override val advancedPatterns = true
        override val customRules = false
        override val prioritySupport = false
        override val teamCollaboration = false
        override val cicdIntegration = false
        override val securityReports = false
        override val aiCodeAnalysis = true
        override val dependencyScanning = true
        override val complianceDashboard = true
        override val sbomGeneration = true
        override val secretDetection = true
        override val iacScanning = false
        override val apiSecurityTesting = true
        override val codeComplexityAnalysis = true
        // v2025.6.0 features
        override val threatModeling = true
        override val attackSurfaceAnalysis = true
        override val realtimeCollaboration = false
        override val securityTraining = true
        override val vulnerabilityPrediction = true
        override val codeReviewAI = true
        override val penetrationTestHints = false
        override val zeroDayDetection = false
        // v2025.7.0 features
        override val supplyChainSecurity = true
        override val behavioralAnalysis = true
        override val devSecOpsIntegration = false
        override val securityPostureManagement = true
        override val vulnerabilityCorrelation = true
        override val remediationAutomation = false
        override val securityMetricsAnalytics = true
        override val threatIntelligenceFeed = false
        // v2025.8.0 features
        override val quantumSafeCryptoScan = true
        override val microservicesSecurity = true
        override val cloudSecurityPosture = true
        override val dataFlowTracking = true
        override val complianceAutomation = false
        override val securityChaosTesting = false
        override val apiFuzzing = true
        override val identityAccessAnalysis = true
        // v2025.9.0 features
        override val zeroTrustValidation = true
        override val graphqlSecurity = true
        override val websocketSecurity = true
        override val ssrfDeepScan = true
        override val insecureDeserialization = false
        // v2025.10.0 features
        override val memorySafetyAnalysis = true
        override val firmwareSecurityScan = false
        override val blockchainSmartContract = true
        override val oauthOidcAnalysis = true
        override val cryptographicAgility = true
        override val sidecarProxySecurity = true
        override val edgeComputingSecurity = false
        override val displayName = "Professional"
        override val monthlyPrice = 29.0
    },
    ENTERPRISE {
        override val maxScansPerDay = Int.MAX_VALUE
        override val maxProjectSize = Int.MAX_VALUE
        override val gpuAcceleration = true
        override val advancedPatterns = true
        override val customRules = true
        override val prioritySupport = true
        override val teamCollaboration = true
        override val cicdIntegration = true
        override val securityReports = true
        override val aiCodeAnalysis = true
        override val dependencyScanning = true
        override val complianceDashboard = true
        override val sbomGeneration = true
        override val secretDetection = true
        override val iacScanning = true
        override val apiSecurityTesting = true
        override val codeComplexityAnalysis = true
        // v2025.6.0 features
        override val threatModeling = true
        override val attackSurfaceAnalysis = true
        override val realtimeCollaboration = true
        override val securityTraining = true
        override val vulnerabilityPrediction = true
        override val codeReviewAI = true
        override val penetrationTestHints = true
        override val zeroDayDetection = true
        // v2025.7.0 features
        override val supplyChainSecurity = true
        override val behavioralAnalysis = true
        override val devSecOpsIntegration = true
        override val securityPostureManagement = true
        override val vulnerabilityCorrelation = true
        override val remediationAutomation = true
        override val securityMetricsAnalytics = true
        override val threatIntelligenceFeed = true
        // v2025.8.0 features
        override val quantumSafeCryptoScan = true
        override val microservicesSecurity = true
        override val cloudSecurityPosture = true
        override val dataFlowTracking = true
        override val complianceAutomation = true
        override val securityChaosTesting = true
        override val apiFuzzing = true
        override val identityAccessAnalysis = true
        // v2025.9.0 features
        override val zeroTrustValidation = true
        override val graphqlSecurity = true
        override val websocketSecurity = true
        override val ssrfDeepScan = true
        override val insecureDeserialization = true
        // v2025.10.0 features
        override val memorySafetyAnalysis = true
        override val firmwareSecurityScan = true
        override val blockchainSmartContract = true
        override val oauthOidcAnalysis = true
        override val cryptographicAgility = true
        override val sidecarProxySecurity = true
        override val edgeComputingSecurity = true
        override val displayName = "Enterprise"
        override val monthlyPrice = 99.0
    };

    abstract val maxScansPerDay: Int
    abstract val maxProjectSize: Int
    abstract val gpuAcceleration: Boolean
    abstract val advancedPatterns: Boolean
    abstract val customRules: Boolean
    abstract val prioritySupport: Boolean
    abstract val teamCollaboration: Boolean
    abstract val cicdIntegration: Boolean
    abstract val securityReports: Boolean
    abstract val aiCodeAnalysis: Boolean
    abstract val dependencyScanning: Boolean
    abstract val complianceDashboard: Boolean
    abstract val sbomGeneration: Boolean
    abstract val secretDetection: Boolean
    abstract val iacScanning: Boolean
    abstract val apiSecurityTesting: Boolean
    abstract val codeComplexityAnalysis: Boolean
    // v2025.6.0 features
    abstract val threatModeling: Boolean
    abstract val attackSurfaceAnalysis: Boolean
    abstract val realtimeCollaboration: Boolean
    abstract val securityTraining: Boolean
    abstract val vulnerabilityPrediction: Boolean
    abstract val codeReviewAI: Boolean
    abstract val penetrationTestHints: Boolean
    abstract val zeroDayDetection: Boolean
    // v2025.7.0 features
    abstract val supplyChainSecurity: Boolean
    abstract val behavioralAnalysis: Boolean
    abstract val devSecOpsIntegration: Boolean
    abstract val securityPostureManagement: Boolean
    abstract val vulnerabilityCorrelation: Boolean
    abstract val remediationAutomation: Boolean
    abstract val securityMetricsAnalytics: Boolean
    abstract val threatIntelligenceFeed: Boolean
    // v2025.8.0 features
    abstract val quantumSafeCryptoScan: Boolean
    abstract val microservicesSecurity: Boolean
    abstract val cloudSecurityPosture: Boolean
    abstract val dataFlowTracking: Boolean
    abstract val complianceAutomation: Boolean
    abstract val securityChaosTesting: Boolean
    abstract val apiFuzzing: Boolean
    abstract val identityAccessAnalysis: Boolean
    // v2025.9.0 features
    abstract val zeroTrustValidation: Boolean
    abstract val graphqlSecurity: Boolean
    abstract val websocketSecurity: Boolean
    abstract val ssrfDeepScan: Boolean
    abstract val insecureDeserialization: Boolean
    // v2025.10.0 features
    abstract val memorySafetyAnalysis: Boolean
    abstract val firmwareSecurityScan: Boolean
    abstract val blockchainSmartContract: Boolean
    abstract val oauthOidcAnalysis: Boolean
    abstract val cryptographicAgility: Boolean
    abstract val sidecarProxySecurity: Boolean
    abstract val edgeComputingSecurity: Boolean
    abstract val displayName: String
    abstract val monthlyPrice: Double

    companion object {
        fun fromString(name: String) = values().find { it.name == name } ?: FREE
    }
}

/**
 * License state data
 */
data class LicenseData(
    var licenseKey: String = "",
    var tier: String = LicenseTier.FREE.name,
    var licensedEmail: String = "",
    var expirationDate: String = "",
    var issuedDate: String = "",
    var activationCount: Int = 0,
    var scansToday: Int = 0,
    var lastScanDate: String = "",
    var isOnline: Boolean = true,
    var offlineGracePeriodDays: Int = 30,
    var trialDaysRemaining: Int = 14,
    var isTrialActive: Boolean = true,
    var jetbrainsOrderId: String = "",
    var isProfessional: Boolean = false,
    var isEnterprise: Boolean = false,
    var purchaseDate: String = ""
)

/**
 * License manager - handles licensing, activation, and feature gating
 */
@State(
    name = "VulnSpeedLicense",
    storages = [Storage("vulnspeed-license.xml")]
)
class LicenseManager : PersistentStateComponent<LicenseData> {

    private var state = LicenseData()
    private val dateFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME

    companion object {
        fun getInstance(): LicenseManager {
            return ApplicationManager.getApplication()
                .getService(LicenseManager::class.java)
        }
    }

    override fun getState(): LicenseData = state

    override fun loadState(state: LicenseData) {
        XmlSerializerUtil.copyBean(state, this.state)
        // Reset daily scan count if date changed
        if (state.lastScanDate != LocalDateTime.now().toLocalDate().toString()) {
            this.state.scansToday = 0
            this.state.lastScanDate = LocalDateTime.now().toLocalDate().toString()
        }
    }

    /**
     * Get current license tier
     */
    fun getCurrentTier(): LicenseTier = LicenseTier.fromString(state.tier)

    /**
     * Check if feature is available in current tier
     */
    fun isFeatureAvailable(feature: LicenseFeature): Boolean {
        val tier = getCurrentTier()
        return when (feature) {
            LicenseFeature.GPU_ACCELERATION -> tier.gpuAcceleration
            LicenseFeature.ADVANCED_PATTERNS -> tier.advancedPatterns
            LicenseFeature.CUSTOM_RULES -> tier.customRules
            LicenseFeature.PRIORITY_SUPPORT -> tier.prioritySupport
            LicenseFeature.TEAM_COLLABORATION -> tier.teamCollaboration
            LicenseFeature.CICD_INTEGRATION -> tier.cicdIntegration
            LicenseFeature.SECURITY_REPORTS -> tier.securityReports
            LicenseFeature.AI_CODE_ANALYSIS -> tier.aiCodeAnalysis
            LicenseFeature.DEPENDENCY_SCANNING -> tier.dependencyScanning
            LicenseFeature.COMPLIANCE_DASHBOARD -> tier.complianceDashboard
            LicenseFeature.SBOM_GENERATION -> tier.sbomGeneration
            LicenseFeature.SECRET_DETECTION -> tier.secretDetection
            LicenseFeature.IAC_SCANNING -> tier.iacScanning
            LicenseFeature.API_SECURITY_TESTING -> tier.apiSecurityTesting
            LicenseFeature.CODE_COMPLEXITY_ANALYSIS -> tier.codeComplexityAnalysis
            // v2025.6.0 features
            LicenseFeature.THREAT_MODELING -> tier.threatModeling
            LicenseFeature.ATTACK_SURFACE_ANALYSIS -> tier.attackSurfaceAnalysis
            LicenseFeature.REALTIME_COLLABORATION -> tier.realtimeCollaboration
            LicenseFeature.SECURITY_TRAINING -> tier.securityTraining
            LicenseFeature.VULNERABILITY_PREDICTION -> tier.vulnerabilityPrediction
            LicenseFeature.CODE_REVIEW_AI -> tier.codeReviewAI
            LicenseFeature.PENETRATION_TEST_HINTS -> tier.penetrationTestHints
            LicenseFeature.ZERO_DAY_DETECTION -> tier.zeroDayDetection
            // v2025.7.0 features
            LicenseFeature.SUPPLY_CHAIN_SECURITY -> tier.supplyChainSecurity
            LicenseFeature.BEHAVIORAL_ANALYSIS -> tier.behavioralAnalysis
            LicenseFeature.DEVSECOPS_INTEGRATION -> tier.devSecOpsIntegration
            LicenseFeature.SECURITY_POSTURE_MANAGEMENT -> tier.securityPostureManagement
            LicenseFeature.VULNERABILITY_CORRELATION -> tier.vulnerabilityCorrelation
            LicenseFeature.REMEDIATION_AUTOMATION -> tier.remediationAutomation
            LicenseFeature.SECURITY_METRICS_ANALYTICS -> tier.securityMetricsAnalytics
            LicenseFeature.THREAT_INTELLIGENCE_FEED -> tier.threatIntelligenceFeed
            // v2025.8.0 features
            LicenseFeature.QUANTUM_SAFE_CRYPTO_SCAN -> tier.quantumSafeCryptoScan
            LicenseFeature.MICROSERVICES_SECURITY -> tier.microservicesSecurity
            LicenseFeature.CLOUD_SECURITY_POSTURE -> tier.cloudSecurityPosture
            LicenseFeature.DATA_FLOW_TRACKING -> tier.dataFlowTracking
            LicenseFeature.COMPLIANCE_AUTOMATION -> tier.complianceAutomation
            LicenseFeature.SECURITY_CHAOS_TESTING -> tier.securityChaosTesting
            LicenseFeature.API_FUZZING -> tier.apiFuzzing
            LicenseFeature.IDENTITY_ACCESS_ANALYSIS -> tier.identityAccessAnalysis
            // v2025.9.0 features
            LicenseFeature.ZERO_TRUST_VALIDATION -> tier.zeroTrustValidation
            LicenseFeature.GRAPHQL_SECURITY -> tier.graphqlSecurity
            LicenseFeature.WEBSOCKET_SECURITY -> tier.websocketSecurity
            LicenseFeature.SSRF_DEEP_SCAN -> tier.ssrfDeepScan
            LicenseFeature.INSECURE_DESERIALIZATION -> tier.insecureDeserialization
            // v2025.10.0 features
            LicenseFeature.MEMORY_SAFETY_ANALYSIS -> tier.memorySafetyAnalysis
            LicenseFeature.FIRMWARE_SECURITY_SCAN -> tier.firmwareSecurityScan
            LicenseFeature.BLOCKCHAIN_SMART_CONTRACT -> tier.blockchainSmartContract
            LicenseFeature.OAUTH_OIDC_ANALYSIS -> tier.oauthOidcAnalysis
            LicenseFeature.CRYPTOGRAPHIC_AGILITY -> tier.cryptographicAgility
            LicenseFeature.SIDECAR_PROXY_SECURITY -> tier.sidecarProxySecurity
            LicenseFeature.EDGE_COMPUTING_SECURITY -> tier.edgeComputingSecurity
        }
    }

    /**
     * Check if license is valid (not expired and online/offline grace)
     */
    fun isLicenseValid(): Boolean {
        if (!state.isOnline) {
            // Check offline grace period
            val issuedLocal = LocalDateTime.parse(state.expirationDate, dateFormatter)
            val gracePeriodEnd = issuedLocal.plusDays(state.offlineGracePeriodDays.toLong())
            return LocalDateTime.now().isBefore(gracePeriodEnd)
        }

        if (state.expirationDate.isNotEmpty()) {
            val expiration = LocalDateTime.parse(state.expirationDate, dateFormatter)
            return LocalDateTime.now().isBefore(expiration)
        }

        // Trial mode
        if (state.isTrialActive && state.trialDaysRemaining > 0) {
            return true
        }

        return false
    }

    /**
     * Activate license with key from JetBrains Marketplace
     */
    fun activateLicense(licenseKey: String): Result<String> {
        return try {
            // Validate license format (would be verified with JetBrains marketplace)
            // Format: VULNSPEED-XXXX-XXXX-XXXX-XXXX
            if (!licenseKey.matches(Regex("VULNSPEED-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"))) {
                return Result.failure(Exception("Invalid license key format"))
            }

            state.licenseKey = licenseKey
            state.issuedDate = LocalDateTime.now().format(dateFormatter)
            state.tier = LicenseTier.PROFESSIONAL.name
            state.isTrialActive = false

            // In real implementation, would validate with JetBrains marketplace API
            // For now, set 1 year expiration
            state.expirationDate = LocalDateTime.now().plusYears(1).format(dateFormatter)
            state.activationCount++

            Result.success("License activated successfully. Tier: ${getCurrentTier().displayName}")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Check and increment daily scan quota
     */
    fun canPerformScan(): Boolean {
        val tier = getCurrentTier()
        if (state.scansToday >= tier.maxScansPerDay && tier.maxScansPerDay != Int.MAX_VALUE) {
            return false
        }

        // Update scan count
        if (state.lastScanDate != LocalDateTime.now().toLocalDate().toString()) {
            state.scansToday = 1
            state.lastScanDate = LocalDateTime.now().toLocalDate().toString()
        } else {
            state.scansToday++
        }

        return true
    }

    /**
     * Get remaining scans for today
     */
    fun getRemainingScansTodayCount(): Int {
        val tier = getCurrentTier()
        if (tier.maxScansPerDay == Int.MAX_VALUE) return Int.MAX_VALUE
        return maxOf(0, tier.maxScansPerDay - state.scansToday)
    }

    /**
     * Check project size limit
     */
    fun canScanProjectSize(projectLoc: Int): Boolean {
        val tier = getCurrentTier()
        return projectLoc <= tier.maxProjectSize
    }

    /**
     * Get trial days remaining
     */
    fun getTrialDaysRemaining(): Int {
        if (!state.isTrialActive) return 0
        return maxOf(0, state.trialDaysRemaining)
    }

    /**
     * Start trial (14 days free)
     */
    fun startTrial() {
        state.isTrialActive = true
        state.trialDaysRemaining = 14
        state.tier = LicenseTier.PROFESSIONAL.name
    }

    /**
     * Downgrade to free tier
     */
    fun downgradeToFree() {
        state.licenseKey = ""
        state.tier = LicenseTier.FREE.name
        state.isTrialActive = false
        state.trialDaysRemaining = 0
        state.expirationDate = ""
    }

    /**
     * Get license info for display
     */
    fun getLicenseInfo(): String {
        val tier = getCurrentTier()
        val info = StringBuilder()
        info.append("Tier: ${tier.displayName}\n")

        if (state.licenseKey.isNotEmpty()) {
            info.append("License Key: ${state.licenseKey.take(20)}...\n")
            info.append("Licensed Email: ${state.licensedEmail}\n")
        }

        if (state.isTrialActive && state.trialDaysRemaining > 0) {
            info.append("Trial Days Remaining: ${state.trialDaysRemaining}\n")
        }

        if (state.expirationDate.isNotEmpty()) {
            info.append("Expires: ${state.expirationDate.take(10)}\n")
        }

        info.append("Scans Today: ${state.scansToday}/${tier.maxScansPerDay}\n")

        return info.toString()
    }

    /**
     * Check if user has valid license from JetBrains Store
     */
    fun hasValidLicense(): Boolean {
        return state.isProfessional || state.isEnterprise || isLicenseValid()
    }

    /**
     * Get current license as License object
     */
    fun getCurrentLicense(): License? {
        if (!hasValidLicense()) return null
        
        val expiry = if (state.expirationDate.isNotEmpty()) {
            try {
                LocalDateTime.parse(state.expirationDate, dateFormatter).toLocalDate()
            } catch (e: Exception) {
                null
            }
        } else null
        
        val purchase = if (state.purchaseDate.isNotEmpty()) {
            try {
                LocalDateTime.parse(state.purchaseDate, dateFormatter).toLocalDate()
            } catch (e: Exception) {
                null
            }
        } else null
        
        return License(
            email = state.licensedEmail,
            tier = getCurrentTier(),
            expiryDate = expiry,
            purchaseDate = purchase,
            isTrialUsed = !state.isTrialActive && state.trialDaysRemaining == 0,
            isEnterprise = state.isEnterprise,
            isProfessional = state.isProfessional
        )
    }

    /**
     * Validate license from store
     */
    fun validateLicense(licenseKey: String): Boolean {
        // In real implementation, would validate with JetBrains Marketplace API
        return licenseKey.isNotEmpty() && licenseKey.length > 20
    }
}

/**
 * License data class for storage
 */
data class License(
    val email: String,
        val tier: LicenseTier,
    val expiryDate: java.time.LocalDate?,
    val purchaseDate: java.time.LocalDate?,
    val isTrialUsed: Boolean,
    val isEnterprise: Boolean,
    val isProfessional: Boolean
)

/**
 * Available license features
 */
enum class LicenseFeature {
    GPU_ACCELERATION,
    ADVANCED_PATTERNS,
    CUSTOM_RULES,
    PRIORITY_SUPPORT,
    TEAM_COLLABORATION,
    CICD_INTEGRATION,
    SECURITY_REPORTS,
    // Premium Features v2025.5.0
    AI_CODE_ANALYSIS,
    DEPENDENCY_SCANNING,
    COMPLIANCE_DASHBOARD,
    SBOM_GENERATION,
    SECRET_DETECTION,
    IAC_SCANNING,
    API_SECURITY_TESTING,
    CODE_COMPLEXITY_ANALYSIS,
    // New Premium Features v2025.6.0
    THREAT_MODELING,
    ATTACK_SURFACE_ANALYSIS,
    REALTIME_COLLABORATION,
    SECURITY_TRAINING,
    VULNERABILITY_PREDICTION,
    CODE_REVIEW_AI,
    PENETRATION_TEST_HINTS,
    ZERO_DAY_DETECTION,
    // New Premium Features v2025.7.0
    SUPPLY_CHAIN_SECURITY,        // Software supply chain attack detection
    BEHAVIORAL_ANALYSIS,          // Runtime behavior pattern analysis
    DEVSECOPS_INTEGRATION,        // Full DevSecOps pipeline integration
    SECURITY_POSTURE_MANAGEMENT,  // Overall security posture dashboard
    VULNERABILITY_CORRELATION,    // Cross-file vulnerability correlation
    REMEDIATION_AUTOMATION,       // Automated vulnerability remediation
    SECURITY_METRICS_ANALYTICS,   // Advanced security metrics and KPIs
    THREAT_INTELLIGENCE_FEED,     // Real-time threat intelligence integration
    // New Premium Features v2025.8.0
    QUANTUM_SAFE_CRYPTO_SCAN,     // Quantum-resistant cryptography validation
    MICROSERVICES_SECURITY,       // Microservices architecture security analysis
    CLOUD_SECURITY_POSTURE,       // AWS/Azure/GCP security configuration scanning
    DATA_FLOW_TRACKING,           // End-to-end data flow and leakage detection
    COMPLIANCE_AUTOMATION,        // Automated compliance reporting (SOC2, ISO27001, GDPR)
    SECURITY_CHAOS_TESTING,       // Chaos engineering for security testing
    API_FUZZING,                  // Automated API fuzzing and mutation testing
    IDENTITY_ACCESS_ANALYSIS,     // IAM policy and access control analysis
    // New Premium Features v2025.9.0
    ZERO_TRUST_VALIDATION,        // Zero-trust architecture validation
    GRAPHQL_SECURITY,             // GraphQL injection, DoS, introspection attacks
    WEBSOCKET_SECURITY,           // WebSocket origin validation, message integrity
    SSRF_DEEP_SCAN,               // Server-side request forgery deep analysis
    INSECURE_DESERIALIZATION,     // Insecure deserialization call-flow analysis
    // New Premium Features v2025.10.0
    MEMORY_SAFETY_ANALYSIS,       // Buffer overflow, use-after-free, memory corruption detection
    FIRMWARE_SECURITY_SCAN,       // IoT/embedded firmware vulnerability analysis
    BLOCKCHAIN_SMART_CONTRACT,    // Smart contract security auditing (Solidity, Rust)
    OAUTH_OIDC_ANALYSIS,          // OAuth2/OIDC misconfiguration detection
    CRYPTOGRAPHIC_AGILITY,        // Crypto algorithm deprecation and migration analysis
    SIDECAR_PROXY_SECURITY,       // Service mesh sidecar (Envoy, Istio) security validation
    EDGE_COMPUTING_SECURITY       // Edge/CDN security configuration analysis
}
