/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.settings.VulnSpeedAppSettings
import com.jakubjirak.vulnspeed.settings.VulnSpeedProjectSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Settings → behaviour wiring: real-time scanning, max file size and scan on save. */
class ScanPolicyTest {

    private val engine = VulnSpeedEngine()
    private val secretLine = "val key = \"AKIAIOSFODNN7EXAMPLE\"\n"

    // --- max file size ---

    @Test
    fun `max bytes converts KB and clamps non-positive values to 1 KB`() {
        assertEquals(1000L * 1024, ScanPolicy.maxBytes(1000))
        assertEquals(1024L, ScanPolicy.maxBytes(0))
        assertEquals(1024L, ScanPolicy.maxBytes(-5))
    }

    @Test
    fun `file at the limit is scanned, one byte over is skipped`() {
        assertFalse(ScanPolicy.isTooLarge(1024, 1))
        assertTrue(ScanPolicy.isTooLarge(1025, 1))
    }

    @Test
    fun `engine scans content within the configured max file size`() {
        val result = engine.scanContent(secretLine, "/p/Main.kt", "kotlin", maxFileSizeKb = 1)

        assertEquals(1, result.stats.filesScanned)
        assertTrue(result.vulnerabilities.isNotEmpty(), "AWS key should be reported")
    }

    @Test
    fun `engine skips content larger than the configured max file size`() {
        val big = secretLine + "// padding\n".repeat(200) // > 1 KB

        val result = engine.scanContent(big, "/p/Main.kt", "kotlin", maxFileSizeKb = 1)

        assertEquals(0, result.stats.filesScanned)
        assertTrue(result.vulnerabilities.isEmpty())
    }

    @Test
    fun `raising the limit lets the same large content be scanned`() {
        val big = secretLine + "// padding\n".repeat(200)

        val result = engine.scanContent(big, "/p/Main.kt", "kotlin", maxFileSizeKb = 10)

        assertEquals(1, result.stats.filesScanned)
        assertTrue(result.vulnerabilities.isNotEmpty())
    }

    @Test
    fun `max file size setting value drives the engine limit`() {
        val settings = VulnSpeedAppSettings().apply { maxFileSizeKb = 1 }
        val big = secretLine + "// padding\n".repeat(200)

        val skipped = engine.scanContent(big, "/p/Main.kt", "kotlin", settings.maxFileSizeKb)
        settings.maxFileSizeKb = ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB
        val scanned = engine.scanContent(big, "/p/Main.kt", "kotlin", settings.maxFileSizeKb)

        assertEquals(0, skipped.stats.filesScanned)
        assertEquals(1, scanned.stats.filesScanned)
    }

    // --- real-time scanning ---

    @Test
    fun `annotator runs only when real-time scanning is enabled`() {
        val settings = VulnSpeedAppSettings()
        assertTrue(ScanPolicy.shouldAnnotate(settings.enableRealTimeScanning))

        settings.enableRealTimeScanning = false
        assertFalse(ScanPolicy.shouldAnnotate(settings.enableRealTimeScanning))
    }

    // --- scan on save ---

    @Test
    fun `scan on save is off by default`() {
        val settings = VulnSpeedProjectSettings()
        assertFalse(ScanPolicy.shouldScanOnSave(settings.scanOnSave, "Main.java"))
    }

    @Test
    fun `scan on save triggers for supported files when enabled`() {
        val settings = VulnSpeedProjectSettings().apply { scanOnSave = true }

        assertTrue(ScanPolicy.shouldScanOnSave(settings.scanOnSave, "Main.java"))
        assertTrue(ScanPolicy.shouldScanOnSave(settings.scanOnSave, "app.PY"))
        assertFalse(ScanPolicy.shouldScanOnSave(settings.scanOnSave, "README.md"))
        assertFalse(ScanPolicy.shouldScanOnSave(settings.scanOnSave, "Makefile"))
    }

    @Test
    fun `supported file detection uses the extension only`() {
        assertTrue(ScanPolicy.isSupportedFile("a.kt"))
        assertTrue(ScanPolicy.isSupportedFile("dir.with.dots.ts"))
        assertFalse(ScanPolicy.isSupportedFile("kt"))
        assertFalse(ScanPolicy.isSupportedFile("image.png"))
    }
}
