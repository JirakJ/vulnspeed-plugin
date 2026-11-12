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

    /**
     * File extensions VulnSpeed scans (project scan and scan-on-save): source code plus
     * YAML and `.properties` configuration. Dockerfiles are recognised by name.
     */
    val SUPPORTED_EXTENSIONS: Set<String> = SourceLanguages.EXTENSIONS

    /**
     * Directory names never descended into by a project scan (besides hidden `.`-directories):
     * dependencies, virtual environments and build output.
     */
    val EXCLUDED_DIRECTORIES: Set<String> = setOf(
        "node_modules", "bower_components", "vendor", "build", "dist", "target", "out",
        "__pycache__", "venv", "site-packages",
    )

    /** Upper bound on the number of files a single project scan covers. */
    const val MAX_FILES_PER_SCAN = 1000

    /** True when a project scan must not descend into a directory called [name]. */
    fun isExcludedDirectory(name: String): Boolean = name.startsWith(".") || name in EXCLUDED_DIRECTORIES

    /** Size limit in bytes for a max-file-size setting; non-positive values are treated as 1 KB. */
    fun maxBytes(maxFileSizeKb: Int): Long = maxFileSizeKb.coerceAtLeast(1) * BYTES_PER_KB

    /** True when a file of [sizeBytes] exceeds the configured limit and must be skipped. */
    fun isTooLarge(sizeBytes: Long, maxFileSizeKb: Int): Boolean = sizeBytes > maxBytes(maxFileSizeKb)

    /**
     * True when VulnSpeed knows how to scan [fileName]: a supported extension or a Dockerfile,
     * excluding minified / bundled JavaScript (`*.min.js`, `*.bundle.js`).
     */
    fun isSupportedFile(fileName: String): Boolean {
        if (SourceLanguages.isDockerfileName(fileName)) return true
        if (!fileName.contains('.') || SourceLanguages.isMinifiedName(fileName)) return false
        return fileName.substringAfterLast('.').lowercase() in SUPPORTED_EXTENSIONS
    }

    /** The editor annotator (as-you-type highlighting) runs only when real-time scanning is enabled. */
    fun shouldAnnotate(realTimeScanningEnabled: Boolean): Boolean = realTimeScanningEnabled

    /** A saved file is scanned only when scan-on-save is enabled and the file type is supported. */
    fun shouldScanOnSave(scanOnSaveEnabled: Boolean, fileName: String): Boolean =
        scanOnSaveEnabled && isSupportedFile(fileName)
}
