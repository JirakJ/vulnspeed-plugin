/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project
import com.jakubjirak.vulnspeed.model.ScanResult
import java.util.concurrent.atomic.AtomicReference

/**
 * Project-level service that caches the most recent [ScanResult] so it can be
 * consumed by downstream actions (e.g. SARIF export) without re-running a scan.
 */
@Service(Service.Level.PROJECT)
class LastScanResultHolder {

    private val ref = AtomicReference<ScanResult?>(null)

    /** Store the most recent scan result. */
    fun set(result: ScanResult) {
        ref.set(result)
    }

    /** Return the most recent scan result, or null if no scan has run yet. */
    fun get(): ScanResult? = ref.get()

    companion object {
        /** Retrieve the project-scoped instance. */
        fun getInstance(project: Project): LastScanResultHolder =
            project.getService(LastScanResultHolder::class.java)
    }
}
