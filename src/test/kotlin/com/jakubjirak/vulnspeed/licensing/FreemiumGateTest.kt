/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the terms of the JetBrains Marketplace EULA.
 */
package com.jakubjirak.vulnspeed.licensing

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class FreemiumGateTest : BasePlatformTestCase() {

    private lateinit var gate: FreemiumGate

    override fun setUp() {
        super.setUp()
        gate = FreemiumGate.getInstance()
    }

    fun testProductCodeIsCorrect() {
        assertEquals("PVULNSPEEDGPUAC", FreemiumGate.PRODUCT_CODE)
    }

    fun testGetLicenseStatusReturnsFreeWithoutLicense() {
        val status = gate.getLicenseStatus()
        assertEquals(FreemiumGate.LicenseStatus.FREE, status)
    }

    fun testIsPremiumUserReturnsFalseWithoutLicense() {
        assertFalse(gate.isPremiumUser())
    }

    fun testNonPremiumFeatureIsAlwaysAvailable() {
        assertTrue(gate.isPaidFeatureAvailable("basic_scan"))
    }

    fun testPremiumFeatureGpuAccelerationBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_GPU_ACCELERATION))
    }

    fun testPremiumFeatureTaintAnalysisBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_TAINT_ANALYSIS))
    }

    fun testPremiumFeatureAiFilteringBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_AI_FILTERING))
    }

    fun testPremiumFeatureCustomRulesBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_CUSTOM_RULES))
    }

    fun testPremiumFeatureProjectScanBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_PROJECT_SCAN))
    }

    fun testPremiumFeatureComplianceReportsBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_COMPLIANCE_REPORTS))
    }

    fun testPremiumFeatureCicdIntegrationBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_CICD_INTEGRATION))
    }

    fun testPremiumFeatureExtendedLanguagesBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_EXTENDED_LANGUAGES))
    }

    fun testPremiumFeatureAdvancedAutofixBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_ADVANCED_AUTOFIX))
    }

    fun testPremiumFeatureVulnerabilityTrackingBlockedForFreeUser() {
        assertFalse(gate.isPaidFeatureAvailable(FreemiumGate.FEATURE_VULNERABILITY_TRACKING))
    }

    fun testLicenseStatusEnumValues() {
        val values = FreemiumGate.LicenseStatus.entries
        assertEquals(3, values.size)
        assertTrue(values.contains(FreemiumGate.LicenseStatus.FREE))
        assertTrue(values.contains(FreemiumGate.LicenseStatus.TRIAL))
        assertTrue(values.contains(FreemiumGate.LicenseStatus.PAID))
    }

    fun testGetInstanceReturnsSameInstance() {
        val instance1 = FreemiumGate.getInstance()
        val instance2 = FreemiumGate.getInstance()
        assertSame(instance1, instance2)
    }
}
