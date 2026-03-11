/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the terms of the JetBrains Marketplace EULA.
 */
package com.jakubjirak.vulnspeed.licensing

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class FreemiumGateTest {

    private val gate = FreemiumGate()

    @Test
    fun testProductCodeIsCorrect() {
        assertEquals("PVULNSPEEDGPUAC", FreemiumGate.PRODUCT_CODE)
    }

    @Test
    fun testGetLicenseStatusReturnsFreeWithoutLicense() {
        val status = gate.getLicenseStatus()
        assertEquals(FreemiumGate.LicenseStatus.FREE, status)
    }

    @Test
    fun testIsPremiumUserReturnsFalseWithoutLicense() {
        assertFalse(gate.isPremiumUser())
    }

    @Test
    fun testNonPremiumFeatureIsAlwaysAvailable() {
        assertTrue(gate.isPaidFeatureAvailable("basic_scan"))
    }

    @Test
    fun testPremiumFeatureGpuAccelerationBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_GPU_ACCELERATION))
    }

    @Test
    fun testPremiumFeatureTaintAnalysisBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_TAINT_ANALYSIS))
    }

    @Test
    fun testPremiumFeatureAiFilteringBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_AI_FILTERING))
    }

    @Test
    fun testPremiumFeatureCustomRulesBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_CUSTOM_RULES))
    }

    @Test
    fun testPremiumFeatureProjectScanBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_PROJECT_SCAN))
    }

    @Test
    fun testPremiumFeatureComplianceReportsBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_COMPLIANCE_REPORTS))
    }

    @Test
    fun testPremiumFeatureCicdIntegrationBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_CICD_INTEGRATION))
    }

    @Test
    fun testPremiumFeatureExtendedLanguagesBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_EXTENDED_LANGUAGES))
    }

    @Test
    fun testPremiumFeatureAdvancedAutofixBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_ADVANCED_AUTOFIX))
    }

    @Test
    fun testPremiumFeatureVulnerabilityTrackingBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_VULNERABILITY_TRACKING))
    }

    @Test
    fun testLicenseStatusEnumValues() {
        val values = FreemiumGate.LicenseStatus.entries
        assertEquals(3, values.size)
        assertTrue(values.contains(FreemiumGate.LicenseStatus.FREE))
        assertTrue(values.contains(FreemiumGate.LicenseStatus.TRIAL))
        assertTrue(values.contains(FreemiumGate.LicenseStatus.PAID))
    }

}
