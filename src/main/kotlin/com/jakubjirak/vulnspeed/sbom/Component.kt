/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.sbom

/**
 * Immutable SBOM component descriptor used by the CycloneDX 1.5 exporter.
 *
 * @property bomRef Stable, document-unique reference (typically a Package URL).
 * @property type   Component classification per CycloneDX spec.
 * @property name   Human-readable package name.
 * @property version Version string, or `null` when unknown.
 * @property purl   Package URL (`pkg:maven/...`, `pkg:npm/...`, `pkg:pypi/...`), or null.
 * @property licenses License identifiers (SPDX short IDs preferred) associated with this component.
 * @property hashes Map of hash algorithm (e.g. `SHA-256`) to hex digest.
 * @property description Optional free-form description.
 */
data class Component(
    val bomRef: String,
    val type: Type,
    val name: String,
    val version: String?,
    val purl: String?,
    val licenses: List<String> = emptyList(),
    val hashes: Map<String, String> = emptyMap(),
    val description: String? = null
) {
    /** CycloneDX component.type enumeration (subset relevant for VulnSpeed). */
    enum class Type(val wireValue: String) {
        LIBRARY("library"),
        APPLICATION("application"),
        FRAMEWORK("framework"),
        OPERATING_SYSTEM("operating-system")
    }
}

/**
 * Metadata describing the application being scanned. Emitted into
 * `metadata.component` of the CycloneDX document.
 *
 * @property name Application / project name.
 * @property version Application version string, or `null` if unknown.
 * @property bomRef Stable bom-ref used for the application component; vulnerabilities
 *                 without a matching library component fall back to this ref.
 * @property toolVersion VulnSpeed plugin/engine version string.
 */
data class AppMetadata(
    val name: String,
    val version: String?,
    val bomRef: String,
    val toolVersion: String
)
