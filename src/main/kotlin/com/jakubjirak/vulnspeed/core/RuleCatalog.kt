/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

/** Shared building blocks of the built-in rule catalogue. */
internal object RuleCatalog {
    const val A01 = "A01:2021 - Broken Access Control"
    const val A02 = "A02:2021 - Cryptographic Failures"
    const val A03 = "A03:2021 - Injection"
    const val A05 = "A05:2021 - Security Misconfiguration"
    const val A07 = "A07:2021 - Identification and Authentication Failures"
    const val A08 = "A08:2021 - Software and Data Integrity Failures"
    const val A09 = "A09:2021 - Security Logging and Monitoring Failures"
    const val A10 = "A10:2021 - Server-Side Request Forgery"

    val JVM: Set<String> = SourceLanguages.JVM
    val JS: Set<String> = SourceLanguages.JS
    val NATIVE: Set<String> = SourceLanguages.NATIVE

    /** Languages of typical web back ends (request-data rules). */
    val WEB_BACKENDS: Set<String> = JVM + JS + SourceLanguages.PYTHON

    /** Managed / scripting languages that share crypto and network APIs. */
    val MANAGED: Set<String> = JVM + JS + setOf(SourceLanguages.PYTHON, SourceLanguages.GO)

    /** Column list of a SELECT: `*`, `a, b`, `t.a AS x`, `COUNT(*)`. */
    const val SQL_COLUMNS = """(?:distinct\s+)?[\w.*()]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.*()]+(?:\s+as\s+\w+)?)*"""

    /** Start of a SQL statement with real structure, so prose such as "select a file from" does not match. */
    const val SQL_STMT = """(?i:select\s+$SQL_COLUMNS\s+from\s+[\w.]+|insert\s+into\s+[\w.]+|""" +
        """update\s+[\w.]+\s+set\s+\w+\s*=|delete\s+from\s+[\w.]+)"""

    /** User-controlled request data in common web frameworks. */
    const val REQUEST_DATA = """(?:req\.(?:query|body|params)|request\.(?:getParameter|getHeader|args|form|values|GET|POST|""" +
        """query_params|json))"""
}
