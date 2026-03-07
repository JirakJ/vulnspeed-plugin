/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the terms of the JetBrains Marketplace EULA.
 */
package com.jakubjirak.vulnspeed.licensing

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.ui.LicensingFacade

@Service(Service.Level.APP)
class FreemiumGate {

    enum class LicenseStatus { FREE, TRIAL, PAID }

    companion object {
        const val PRODUCT_CODE = "PVULNSPEED"

        const val FEATURE_GPU_ACCELERATION = "gpu_acceleration"
        const val FEATURE_TAINT_ANALYSIS = "taint_analysis"
        const val FEATURE_AI_FILTERING = "ai_filtering"
        const val FEATURE_CUSTOM_RULES = "custom_rules"
        const val FEATURE_PROJECT_SCAN = "project_scan"
        const val FEATURE_COMPLIANCE_REPORTS = "compliance_reports"
        const val FEATURE_CICD_INTEGRATION = "cicd_integration"
        const val FEATURE_EXTENDED_LANGUAGES = "extended_languages"
        const val FEATURE_ADVANCED_AUTOFIX = "advanced_autofix"
        const val FEATURE_VULNERABILITY_TRACKING = "vulnerability_tracking"

        private val PREMIUM_FEATURES = setOf(
            FEATURE_GPU_ACCELERATION, FEATURE_TAINT_ANALYSIS, FEATURE_AI_FILTERING,
            FEATURE_CUSTOM_RULES, FEATURE_PROJECT_SCAN, FEATURE_COMPLIANCE_REPORTS,
            FEATURE_CICD_INTEGRATION, FEATURE_EXTENDED_LANGUAGES, FEATURE_ADVANCED_AUTOFIX,
            FEATURE_VULNERABILITY_TRACKING
        )

        fun getInstance(): FreemiumGate =
            ApplicationManager.getApplication().getService(FreemiumGate::class.java)
    }

    fun getLicenseStatus(): LicenseStatus {
        val facade = LicensingFacade.getInstance() ?: return LicenseStatus.FREE
        val stamp = facade.getConfirmationStamp(PRODUCT_CODE) ?: return LicenseStatus.FREE
        return if (stamp.startsWith("eval:")) LicenseStatus.TRIAL else LicenseStatus.PAID
    }

    fun isPaidFeatureAvailable(featureId: String): Boolean {
        if (featureId !in PREMIUM_FEATURES) return true
        return getLicenseStatus() != LicenseStatus.FREE
    }

    fun isPremiumUser(): Boolean = getLicenseStatus() != LicenseStatus.FREE
}
