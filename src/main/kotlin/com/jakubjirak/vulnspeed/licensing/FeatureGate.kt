package com.jakubjirak.vulnspeed.licensing

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.project.Project
import com.jakubjirak.vulnspeed.ui.dialogs.LicenseUpgradeDialog

/**
 * Feature gate utilities - handles feature availability checking and upgrade prompts
 */
object FeatureGate {

    /**
     * Check if feature is available, show upgrade dialog if not
     */
    fun checkFeatureAvailable(
        feature: LicenseFeature,
        featureDisplayName: String,
        project: Project? = null
    ): Boolean {
        val manager = LicenseManager.getInstance()

        if (!manager.isLicenseValid()) {
            notifyExpiredLicense(project)
            return false
        }

        if (!manager.isFeatureAvailable(feature)) {
            showUpgradeDialog(featureDisplayName)
            return false
        }

        return true
    }

    /**
     * Check if user can perform a scan
     */
    fun canPerformScan(projectSize: Int, project: Project? = null): Boolean {
        val manager = LicenseManager.getInstance()

        if (!manager.isLicenseValid()) {
            notifyExpiredLicense(project)
            return false
        }

        if (!manager.canPerformScan()) {
            notifyDailyScanLimitReached(project)
            return false
        }

        if (!manager.canScanProjectSize(projectSize)) {
            notifyProjectSizeExceeded(project, projectSize)
            return false
        }

        return true
    }

    /**
     * Execute feature with license check
     */
    fun <T> withFeatureCheck(
        feature: LicenseFeature,
        featureDisplayName: String,
        project: Project? = null,
        block: () -> T
    ): T? {
        if (checkFeatureAvailable(feature, featureDisplayName, project)) {
            return block()
        }
        return null
    }

    /**
     * Show upgrade dialog
     */
    private fun showUpgradeDialog(featureDisplayName: String) {
        val dialog = LicenseUpgradeDialog(featureDisplayName)
        dialog.show()
    }

    /**
     * Notify expired license
     */
    private fun notifyExpiredLicense(project: Project?) {
        val message = "Your VulnSpeed license has expired. Please renew to continue using premium features."
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Notifications")
            .createNotification(message, NotificationType.WARNING)
            .notify(project)
    }

    /**
     * Notify daily scan limit reached
     */
    private fun notifyDailyScanLimitReached(project: Project?) {
        val manager = LicenseManager.getInstance()
        val tier = manager.getCurrentTier()
        val message = "Daily scan limit reached (${tier.maxScansPerDay} scans). " +
            "Please upgrade to Professional for unlimited scans."
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Notifications")
            .createNotification(message, NotificationType.INFORMATION)
            .notify(project)
    }

    /**
     * Notify project size exceeded
     */
    private fun notifyProjectSizeExceeded(project: Project?, projectSize: Int) {
        val manager = LicenseManager.getInstance()
        val tier = manager.getCurrentTier()
        val message = "Project size (${projectSize} LOC) exceeds limit for ${tier.displayName} tier " +
            "(max ${tier.maxProjectSize} LOC). Please upgrade to scan larger projects."
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Notifications")
            .createNotification(message, NotificationType.INFORMATION)
            .notify(project)
    }

    /**
     * Get feature availability badge text
     */
    fun getFeatureBadge(feature: LicenseFeature): String {
        val manager = LicenseManager.getInstance()
        return if (manager.isFeatureAvailable(feature)) {
            "✓ Included"
        } else {
            "⭐ Professional"
        }
    }

    /**
     * Get all features by tier
     */
    fun getFeaturesForTier(tier: LicenseTier): Map<LicenseFeature, Boolean> {
        return mapOf(
            LicenseFeature.GPU_ACCELERATION to tier.gpuAcceleration,
            LicenseFeature.ADVANCED_PATTERNS to tier.advancedPatterns,
            LicenseFeature.CUSTOM_RULES to tier.customRules,
            LicenseFeature.PRIORITY_SUPPORT to tier.prioritySupport,
            LicenseFeature.TEAM_COLLABORATION to tier.teamCollaboration,
            LicenseFeature.CICD_INTEGRATION to tier.cicdIntegration,
            LicenseFeature.SECURITY_REPORTS to tier.securityReports,
            LicenseFeature.AI_CODE_ANALYSIS to tier.aiCodeAnalysis,
            LicenseFeature.DEPENDENCY_SCANNING to tier.dependencyScanning,
            LicenseFeature.COMPLIANCE_DASHBOARD to tier.complianceDashboard,
            LicenseFeature.SBOM_GENERATION to tier.sbomGeneration,
            LicenseFeature.SECRET_DETECTION to tier.secretDetection,
            LicenseFeature.IAC_SCANNING to tier.iacScanning,
            LicenseFeature.API_SECURITY_TESTING to tier.apiSecurityTesting,
            LicenseFeature.CODE_COMPLEXITY_ANALYSIS to tier.codeComplexityAnalysis,
            // v2025.6.0 features
            LicenseFeature.THREAT_MODELING to tier.threatModeling,
            LicenseFeature.ATTACK_SURFACE_ANALYSIS to tier.attackSurfaceAnalysis,
            LicenseFeature.REALTIME_COLLABORATION to tier.realtimeCollaboration,
            LicenseFeature.SECURITY_TRAINING to tier.securityTraining,
            LicenseFeature.VULNERABILITY_PREDICTION to tier.vulnerabilityPrediction,
            LicenseFeature.CODE_REVIEW_AI to tier.codeReviewAI,
            LicenseFeature.PENETRATION_TEST_HINTS to tier.penetrationTestHints,
            LicenseFeature.ZERO_DAY_DETECTION to tier.zeroDayDetection,
            // v2025.7.0 features
            LicenseFeature.SUPPLY_CHAIN_SECURITY to tier.supplyChainSecurity,
            LicenseFeature.BEHAVIORAL_ANALYSIS to tier.behavioralAnalysis,
            LicenseFeature.DEVSECOPS_INTEGRATION to tier.devSecOpsIntegration,
            LicenseFeature.SECURITY_POSTURE_MANAGEMENT to tier.securityPostureManagement,
            LicenseFeature.VULNERABILITY_CORRELATION to tier.vulnerabilityCorrelation,
            LicenseFeature.REMEDIATION_AUTOMATION to tier.remediationAutomation,
            LicenseFeature.SECURITY_METRICS_ANALYTICS to tier.securityMetricsAnalytics,
            LicenseFeature.THREAT_INTELLIGENCE_FEED to tier.threatIntelligenceFeed,
            // v2025.8.0 features
            LicenseFeature.QUANTUM_SAFE_CRYPTO_SCAN to tier.quantumSafeCryptoScan,
            LicenseFeature.MICROSERVICES_SECURITY to tier.microservicesSecurity,
            LicenseFeature.CLOUD_SECURITY_POSTURE to tier.cloudSecurityPosture,
            LicenseFeature.DATA_FLOW_TRACKING to tier.dataFlowTracking,
            LicenseFeature.COMPLIANCE_AUTOMATION to tier.complianceAutomation,
            LicenseFeature.SECURITY_CHAOS_TESTING to tier.securityChaosTesting,
            LicenseFeature.API_FUZZING to tier.apiFuzzing,
            LicenseFeature.IDENTITY_ACCESS_ANALYSIS to tier.identityAccessAnalysis,
            // v2025.9.0 features
            LicenseFeature.ZERO_TRUST_VALIDATION to tier.zeroTrustValidation,
            LicenseFeature.GRAPHQL_SECURITY to tier.graphqlSecurity,
            LicenseFeature.WEBSOCKET_SECURITY to tier.websocketSecurity,
            LicenseFeature.SSRF_DEEP_SCAN to tier.ssrfDeepScan,
            LicenseFeature.INSECURE_DESERIALIZATION to tier.insecureDeserialization,
            // v2025.10.0 features
            LicenseFeature.MEMORY_SAFETY_ANALYSIS to tier.memorySafetyAnalysis,
            LicenseFeature.FIRMWARE_SECURITY_SCAN to tier.firmwareSecurityScan,
            LicenseFeature.BLOCKCHAIN_SMART_CONTRACT to tier.blockchainSmartContract,
            LicenseFeature.OAUTH_OIDC_ANALYSIS to tier.oauthOidcAnalysis,
            LicenseFeature.CRYPTOGRAPHIC_AGILITY to tier.cryptographicAgility,
            LicenseFeature.SIDECAR_PROXY_SECURITY to tier.sidecarProxySecurity,
            LicenseFeature.EDGE_COMPUTING_SECURITY to tier.edgeComputingSecurity
        )
    }
}
