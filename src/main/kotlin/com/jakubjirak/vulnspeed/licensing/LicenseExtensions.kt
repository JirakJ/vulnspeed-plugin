package com.jakubjirak.vulnspeed.licensing

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.MessageDialogBuilder
import com.intellij.openapi.ui.Messages

/**
 * Check if feature is available and show license dialog if not
 */
fun requireLicenseFeature(
    feature: LicenseFeature,
    onAuthorized: () -> Unit,
    project: Project? = null
) {
    val licenseManager = LicenseManager.getInstance()
    
    if (licenseManager.isFeatureAvailable(feature)) {
        onAuthorized()
        return
    }
    
    // Show license upgrade dialog
    showLicenseUpgradeDialog(feature, project)
}

/**
 * Check if scan can be performed
 */
fun canPerformScan(): Boolean {
    val licenseManager = LicenseManager.getInstance()
    
    if (!licenseManager.isLicenseValid()) {
        return false
    }
    
    return licenseManager.canPerformScan()
}

/**
 * Show license upgrade dialog
 */
fun showLicenseUpgradeDialog(feature: LicenseFeature, project: Project?) {
    val message = when (feature) {
        LicenseFeature.GPU_ACCELERATION -> 
            "GPU Acceleration requires Premium license.\n\nUpgrade to unlock sub-100ms scanning with Metal/CUDA/Vulkan."
        LicenseFeature.ADVANCED_PATTERNS ->
            "Advanced analysis requires Premium license.\n\nUpgrade to unlock taint flow, data flow, and control flow analysis."
        LicenseFeature.CUSTOM_RULES ->
            "Custom rules require Enterprise license.\n\nContact support for enterprise options."
        LicenseFeature.PRIORITY_SUPPORT ->
            "Priority support requires Premium license.\n\nUpgrade to get email and Slack support."
        LicenseFeature.TEAM_COLLABORATION ->
            "Team collaboration requires Enterprise license.\n\nContact support for enterprise options."
        LicenseFeature.CICD_INTEGRATION ->
            "CI/CD Integration requires Enterprise license.\n\nContact support for enterprise options."
        LicenseFeature.SECURITY_REPORTS ->
            "Security reports require Premium license.\n\nUpgrade to unlock enterprise dashboard and SBOM generation."
        LicenseFeature.AI_CODE_ANALYSIS ->
            "AI-Powered Code Analysis requires Premium license.\n\nUpgrade to unlock deep learning vulnerability detection."
        LicenseFeature.DEPENDENCY_SCANNING ->
            "Dependency Scanning requires Premium license.\n\nUpgrade to enable CVE monitoring for all dependencies."
        LicenseFeature.COMPLIANCE_DASHBOARD ->
            "Compliance Dashboard requires Premium license.\n\nUpgrade to track OWASP Top 10, CWE Top 25, PCI-DSS compliance."
        LicenseFeature.SBOM_GENERATION ->
            "SBOM Generation requires Premium license.\n\nUpgrade to export Software Bill of Materials (CycloneDX/SPDX)."
        LicenseFeature.SECRET_DETECTION ->
            "Secret Detection requires Premium license.\n\nUpgrade to detect 50+ secret patterns including cloud credentials."
        LicenseFeature.IAC_SCANNING ->
            "IaC Scanning requires Enterprise license.\n\nUpgrade to scan Terraform, CloudFormation, and Kubernetes YAML."
        LicenseFeature.API_SECURITY_TESTING ->
            "API Security Testing requires Premium license.\n\nUpgrade to analyze OpenAPI/Swagger specifications."
        LicenseFeature.CODE_COMPLEXITY_ANALYSIS ->
            "Code Complexity Analysis requires Premium license.\n\nUpgrade to get cyclomatic complexity and maintainability index."
        // v2025.6.0 features
        LicenseFeature.THREAT_MODELING ->
            "Threat Modeling requires Premium license.\n\nUpgrade to auto-generate STRIDE threat models for your application."
        LicenseFeature.ATTACK_SURFACE_ANALYSIS ->
            "Attack Surface Analysis requires Premium license.\n\nUpgrade to visualize entry points and potential attack vectors."
        LicenseFeature.REALTIME_COLLABORATION ->
            "Real-time Collaboration requires Enterprise license.\n\nUpgrade to share findings and collaborate with your team live."
        LicenseFeature.SECURITY_TRAINING ->
            "Security Training requires Premium license.\n\nUpgrade to get contextual security learning integrated in your IDE."
        LicenseFeature.VULNERABILITY_PREDICTION ->
            "Vulnerability Prediction requires Premium license.\n\nUpgrade to predict potential vulnerabilities using ML models."
        LicenseFeature.CODE_REVIEW_AI ->
            "AI Code Review requires Premium license.\n\nUpgrade to get AI-powered security code review suggestions."
        LicenseFeature.PENETRATION_TEST_HINTS ->
            "Penetration Test Hints requires Enterprise license.\n\nUpgrade to get actionable hints for penetration testing."
        LicenseFeature.ZERO_DAY_DETECTION ->
            "Zero-Day Detection requires Enterprise license.\n\nUpgrade to detect potential zero-day vulnerabilities using AI."
        // v2025.7.0 features
        LicenseFeature.SUPPLY_CHAIN_SECURITY ->
            "Supply Chain Security requires Premium license.\n\nUpgrade to detect software supply chain attacks and dependency hijacking."
        LicenseFeature.BEHAVIORAL_ANALYSIS ->
            "Behavioral Analysis requires Premium license.\n\nUpgrade to analyze runtime behavior patterns and detect anomalies."
        LicenseFeature.DEVSECOPS_INTEGRATION ->
            "DevSecOps Integration requires Enterprise license.\n\nUpgrade to integrate with CI/CD pipelines, SIEM, and security tools."
        LicenseFeature.SECURITY_POSTURE_MANAGEMENT ->
            "Security Posture Management requires Premium license.\n\nUpgrade to get overall security posture dashboard and scoring."
        LicenseFeature.VULNERABILITY_CORRELATION ->
            "Vulnerability Correlation requires Premium license.\n\nUpgrade to correlate vulnerabilities across files and components."
        LicenseFeature.REMEDIATION_AUTOMATION ->
            "Remediation Automation requires Enterprise license.\n\nUpgrade to automatically generate and apply security fixes."
        LicenseFeature.SECURITY_METRICS_ANALYTICS ->
            "Security Metrics & Analytics requires Premium license.\n\nUpgrade to track security KPIs and trend analysis."
        LicenseFeature.THREAT_INTELLIGENCE_FEED ->
            "Threat Intelligence Feed requires Enterprise license.\n\nUpgrade to integrate real-time threat intelligence feeds."
        // v2025.8.0 features
        LicenseFeature.QUANTUM_SAFE_CRYPTO_SCAN ->
            "Quantum-Safe Crypto Scan requires Premium license.\n\nUpgrade to validate quantum-resistant cryptography implementations."
        LicenseFeature.MICROSERVICES_SECURITY ->
            "Microservices Security requires Premium license.\n\nUpgrade to analyze microservices architecture security patterns."
        LicenseFeature.CLOUD_SECURITY_POSTURE ->
            "Cloud Security Posture requires Premium license.\n\nUpgrade to scan AWS/Azure/GCP security configurations."
        LicenseFeature.DATA_FLOW_TRACKING ->
            "Data Flow Tracking requires Premium license.\n\nUpgrade to detect end-to-end data flow and leakage patterns."
        LicenseFeature.COMPLIANCE_AUTOMATION ->
            "Compliance Automation requires Enterprise license.\n\nUpgrade to automate SOC2, ISO27001, GDPR compliance reporting."
        LicenseFeature.SECURITY_CHAOS_TESTING ->
            "Security Chaos Testing requires Enterprise license.\n\nUpgrade to perform chaos engineering for security testing."
        LicenseFeature.API_FUZZING ->
            "API Fuzzing requires Premium license.\n\nUpgrade to perform automated API fuzzing and mutation testing."
        LicenseFeature.IDENTITY_ACCESS_ANALYSIS ->
            "Identity & Access Analysis requires Premium license.\n\nUpgrade to analyze IAM policies and access control configurations."
        // v2025.9.0 features
        LicenseFeature.ZERO_TRUST_VALIDATION ->
            "Zero-Trust Validation requires Premium license.\n\nUpgrade to verify zero-trust architecture principles in your code."
        LicenseFeature.GRAPHQL_SECURITY ->
            "GraphQL Security requires Premium license.\n\nUpgrade to detect GraphQL injection, DoS, and introspection attacks."
        LicenseFeature.WEBSOCKET_SECURITY ->
            "WebSocket Security requires Premium license.\n\nUpgrade to validate WebSocket origin, message integrity, and security."
        LicenseFeature.SSRF_DEEP_SCAN ->
            "SSRF Deep Scan requires Premium license.\n\nUpgrade to perform deep server-side request forgery analysis."
        LicenseFeature.INSECURE_DESERIALIZATION ->
            "Insecure Deserialization requires Enterprise license.\n\nUpgrade to analyze deserialization call-flow and detect gadget chains."
        // v2025.10.0 features
        LicenseFeature.MEMORY_SAFETY_ANALYSIS ->
            "Memory Safety Analysis requires Premium license.\n\nUpgrade to detect buffer overflows, use-after-free, and memory corruption."
        LicenseFeature.FIRMWARE_SECURITY_SCAN ->
            "Firmware Security Scan requires Enterprise license.\n\nUpgrade to analyze IoT/embedded firmware vulnerabilities."
        LicenseFeature.BLOCKCHAIN_SMART_CONTRACT ->
            "Blockchain Smart Contract Analysis requires Premium license.\n\nUpgrade to audit Solidity and Rust smart contracts."
        LicenseFeature.OAUTH_OIDC_ANALYSIS ->
            "OAuth/OIDC Analysis requires Premium license.\n\nUpgrade to detect OAuth2 and OpenID Connect misconfigurations."
        LicenseFeature.CRYPTOGRAPHIC_AGILITY ->
            "Cryptographic Agility requires Premium license.\n\nUpgrade to analyze crypto algorithm deprecation and migration paths."
        LicenseFeature.SIDECAR_PROXY_SECURITY ->
            "Sidecar Proxy Security requires Premium license.\n\nUpgrade to validate Envoy, Istio, and service mesh security."
        LicenseFeature.EDGE_COMPUTING_SECURITY ->
            "Edge Computing Security requires Enterprise license.\n\nUpgrade to analyze edge/CDN security configurations."
    }
    
    val result = MessageDialogBuilder
        .yesNo("Premium Feature Required", message)
        .yesText("Activate License")
        .noText("Cancel")
        .ask(project)
    
    if (result) {
        // Open license activation dialog
        showLicenseActivationDialog(project)
    }
}

/**
 * Show license activation dialog
 */
fun showLicenseActivationDialog(project: Project?) {
    val key = Messages.showInputDialog(
        project,
        "Enter your VulnSpeed license key from JetBrains Store:",
        "Activate License",
        Messages.getInformationIcon()
    ) ?: return
    
    val licenseManager = LicenseManager.getInstance()
    val result = licenseManager.activateLicense(key)
    
    result.fold(
        onSuccess = { message ->
            Messages.showInfoMessage(
                project,
                message,
                "License Activated"
            )
        },
        onFailure = { error ->
            Messages.showErrorDialog(
                project,
                "Failed to activate license: ${error.message}",
                "Activation Failed"
            )
        }
    )
}

/**
 * Show trial start dialog
 */
fun showTrialStartDialog(project: Project?): Boolean {
    val result = MessageDialogBuilder
        .yesNo(
            "Start Free Trial",
            "Start a 14-day free trial of VulnSpeed Premium?\n\n" +
            "You'll get access to GPU acceleration, advanced analysis, and more."
        )
        .yesText("Start Trial")
        .noText("Cancel")
        .ask(project)
    
    if (result) {
        LicenseManager.getInstance().startTrial()
        Messages.showInfoMessage(
            project,
            "Trial activated! You have 14 days of premium access.",
            "Trial Started"
        )
    }
    
    return result
}

/**
 * Check scan limit and show message if exceeded
 */
fun checkScanLimit(project: Project?): Boolean {
    val licenseManager = LicenseManager.getInstance()
    
    if (!licenseManager.canPerformScan()) {
        val remaining = licenseManager.getRemainingScansTodayCount()
        Messages.showInfoMessage(
            project,
            "You've reached your daily scan limit (${licenseManager.getCurrentTier().maxScansPerDay}).\n\n" +
            "Remaining: $remaining\n\n" +
            "Upgrade to Premium for unlimited scans.",
            "Scan Limit Reached"
        )
        return false
    }
    
    return true
}

/**
 * Get human-readable license status
 */
fun getLicenseStatus(): String {
    val licenseManager = LicenseManager.getInstance()
    val tier = licenseManager.getCurrentTier()
    val valid = licenseManager.isLicenseValid()
    
    return buildString {
        append("Tier: ${tier.displayName}\n")
        append("Status: ${if (valid) "Active" else "Inactive"}\n")
        append(licenseManager.getLicenseInfo())
    }
}
