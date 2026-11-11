/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.model.ScanStats
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test

class LastScanResultHolderTest {

    private fun result(id: String) = ScanResult(
        scanId = id,
        timestamp = 0L,
        durationMs = 1L,
        vulnerabilities = emptyList(),
        stats = ScanStats(0, 0, 0, 0, 0, 0, 0L),
    )

    @Test
    fun `empty until first scan`() {
        assertNull(LastScanResultHolder().get())
    }

    @Test
    fun `latest scan replaces previous`() {
        val holder = LastScanResultHolder()
        val first = result("a")
        val second = result("b")
        holder.set(first)
        assertSame(first, holder.get())
        holder.set(second)
        assertSame(second, holder.get())
    }
}
