/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

/**
 * Pure decisions that turn VulnSpeed settings into scanning behaviour. Kept free of
 * IntelliJ platform types so the settings → behaviour wiring is unit-testable.
 */
object ScanPolicy {

    /** Default for the "Max file size" setting, in KB. */
    const val DEFAULT_MAX_FILE_SIZE_KB = 1000

    private const val BYTES_PER_KB = 1024L

    /** File extensions VulnSpeed scans (project scan and scan-on-save). */
    val SUPPORTED_EXTENSIONS: Set<String> =
        setOf("java", "kt", "py", "js", "ts", "swift", "cpp", "c", "h", "go", "rs")

    /** Size limit in bytes for a max-file-size setting; non-positive values are treated as 1 KB. */
    fun maxBytes(maxFileSizeKb: Int): Long = maxFileSizeKb.coerceAtLeast(1) * BYTES_PER_KB

    /** True when a file of [sizeBytes] exceeds the configured limit and must be skipped. */
    fun isTooLarge(sizeBytes: Long, maxFileSizeKb: Int): Boolean = sizeBytes > maxBytes(maxFileSizeKb)

    /** True when [fileName] has an extension VulnSpeed knows how to scan. */
    fun isSupportedFile(fileName: String): Boolean {
        if (!fileName.contains('.')) return false
        return fileName.substringAfterLast('.').lowercase() in SUPPORTED_EXTENSIONS
    }

    /** The editor annotator (as-you-type highlighting) runs only when real-time scanning is enabled. */
    fun shouldAnnotate(realTimeScanningEnabled: Boolean): Boolean = realTimeScanningEnabled

    /** A saved file is scanned only when scan-on-save is enabled and the file type is supported. */
    fun shouldScanOnSave(scanOnSaveEnabled: Boolean, fileName: String): Boolean =
        scanOnSaveEnabled && isSupportedFile(fileName)
}
