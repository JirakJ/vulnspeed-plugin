/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EnrichmentPolicyTest {

    @Test
    fun `defaults are online, osv-first and anonymous`() {
        val p = EnrichmentPolicy()
        assertFalse(p.offline)
        assertTrue(p.preferOsv)
        assertEquals(7, p.maxAgeDays)
        assertEquals(3, p.maxRetries)
        assertNull(p.nvdApiKey)
    }

    @Test
    fun `zero values are accepted`() {
        val p = EnrichmentPolicy(maxAgeDays = 0, rateLimitPerMin = 0, maxRetries = 0)
        assertEquals(0, p.maxAgeDays)
    }

    @Test
    fun `negative values are rejected`() {
        assertThrows(IllegalArgumentException::class.java) { EnrichmentPolicy(maxAgeDays = -1) }
        assertThrows(IllegalArgumentException::class.java) { EnrichmentPolicy(rateLimitPerMin = -1) }
        assertThrows(IllegalArgumentException::class.java) { EnrichmentPolicy(maxRetries = -1) }
    }
}
