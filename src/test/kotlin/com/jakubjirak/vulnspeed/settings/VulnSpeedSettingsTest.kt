/*
 * Copyright (c) 2025 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.settings

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class VulnSpeedSettingsTest {

    @Test
    fun `VulnSpeedAppSettings has correct defaults`() {
        val settings = VulnSpeedAppSettings()

        assertTrue(settings.enableRealTimeScanning)
        assertTrue(settings.enableAutoFix)
        assertEquals(1000, settings.maxFileSizeKb)
        assertFalse(settings.enableTelemetry)
    }

    @Test
    fun `VulnSpeedAppSettings getState returns self`() {
        val settings = VulnSpeedAppSettings()
        assertSame(settings, settings.state)
    }

    @Test
    fun `VulnSpeedAppSettings loadState copies properties`() {
        val source = VulnSpeedAppSettings().apply {
            enableRealTimeScanning = false
            enableAutoFix = false
            maxFileSizeKb = 2000
            enableTelemetry = true
        }

        val target = VulnSpeedAppSettings()
        target.loadState(source)

        assertFalse(target.enableRealTimeScanning)
        assertFalse(target.enableAutoFix)
        assertEquals(2000, target.maxFileSizeKb)
        assertTrue(target.enableTelemetry)
    }

    @Test
    fun `VulnSpeedProjectSettings has correct defaults`() {
        val settings = VulnSpeedProjectSettings()

        assertEquals(3, settings.excludePatterns.size)
        assertTrue(settings.excludePatterns.contains("**/node_modules/**"))
        assertTrue(settings.excludePatterns.contains("**/build/**"))
        assertTrue(settings.excludePatterns.contains("**/.git/**"))
        assertFalse(settings.scanOnSave)
        assertFalse(settings.autoFixOnSave)
    }

    @Test
    fun `VulnSpeedProjectSettings getState returns self`() {
        val settings = VulnSpeedProjectSettings()
        assertSame(settings, settings.state)
    }

    @Test
    fun `VulnSpeedProjectSettings loadState copies properties`() {
        val source = VulnSpeedProjectSettings().apply {
            excludePatterns = listOf("**/dist/**")
            scanOnSave = true
            autoFixOnSave = true
        }

        val target = VulnSpeedProjectSettings()
        target.loadState(source)

        assertEquals(1, target.excludePatterns.size)
        assertEquals("**/dist/**", target.excludePatterns[0])
        assertTrue(target.scanOnSave)
        assertTrue(target.autoFixOnSave)
    }

    @Test
    fun `VulnSpeedAppSettings can toggle all settings`() {
        val settings = VulnSpeedAppSettings()

        settings.enableRealTimeScanning = false
        settings.enableAutoFix = false
        settings.enableTelemetry = true
        settings.maxFileSizeKb = 5000

        assertFalse(settings.enableRealTimeScanning)
        assertFalse(settings.enableAutoFix)
        assertTrue(settings.enableTelemetry)
        assertEquals(5000, settings.maxFileSizeKb)
    }
}
