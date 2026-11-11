/*
 * Copyright (c) 2025 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.settings

import com.jakubjirak.vulnspeed.core.ScanPolicy
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class VulnSpeedSettingsTest {

    @Test
    fun `VulnSpeedAppSettings has correct defaults`() {
        val settings = VulnSpeedAppSettings()

        assertTrue(settings.enableRealTimeScanning)
        assertEquals(ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB, settings.maxFileSizeKb)
        assertEquals(1000, settings.maxFileSizeKb)
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
            maxFileSizeKb = 2000
        }

        val target = VulnSpeedAppSettings()
        target.loadState(source)

        assertFalse(target.enableRealTimeScanning)
        assertEquals(2000, target.maxFileSizeKb)
    }

    @Test
    fun `VulnSpeedProjectSettings has correct defaults`() {
        val settings = VulnSpeedProjectSettings()
        assertFalse(settings.scanOnSave)
    }

    @Test
    fun `VulnSpeedProjectSettings getState returns self`() {
        val settings = VulnSpeedProjectSettings()
        assertSame(settings, settings.state)
    }

    @Test
    fun `VulnSpeedProjectSettings loadState copies properties`() {
        val source = VulnSpeedProjectSettings().apply { scanOnSave = true }

        val target = VulnSpeedProjectSettings()
        target.loadState(source)

        assertTrue(target.scanOnSave)
    }

    @Test
    fun `settings expose no telemetry or auto-fix switches`() {
        // A free OSS plugin collects no telemetry and has no auto-fix engine, so the
        // settings must not offer switches for them (they used to exist but did nothing).
        val appFields = VulnSpeedAppSettings::class.java.declaredFields.map { it.name }.toSet()
        val projectFields = VulnSpeedProjectSettings::class.java.declaredFields.map { it.name }.toSet()

        assertFalse("enableTelemetry" in appFields)
        assertFalse("enableAutoFix" in appFields)
        assertFalse("autoFixOnSave" in projectFields)
        assertFalse("excludePatterns" in projectFields)
    }
}
