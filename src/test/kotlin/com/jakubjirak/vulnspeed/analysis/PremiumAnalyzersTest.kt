/*
 * Copyright (c) 2025 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PremiumAnalyzersTest {

    @Test
    fun `analyzeWithAI detects unsafe data flow pattern`() {
        val code = """val result = request.data.exec("cmd")"""
        val vulns = PremiumAnalyzers.analyzeWithAI(code, "/test.kt", "kotlin")

        assertTrue(vulns.isNotEmpty())
        assertTrue(vulns.any { it.severity == Severity.HIGH })
    }

    @Test
    fun `analyzeWithAI detects insecure configuration`() {
        val code = """enable_ssl = false"""
        val vulns = PremiumAnalyzers.analyzeWithAI(code, "/config.py", "python")

        assertTrue(vulns.isNotEmpty())
    }

    @Test
    fun `analyzeWithAI returns empty for clean code`() {
        val code = """
            fun greet(name: String): String {
                return "Hello, ${'$'}name!"
            }
        """.trimIndent()
        val vulns = PremiumAnalyzers.analyzeWithAI(code, "/clean.kt", "kotlin")

        assertTrue(vulns.isEmpty())
    }

    @Test
    fun `analyzeWithAI includes correct metadata`() {
        val code = """user input eval("code")"""
        val vulns = PremiumAnalyzers.analyzeWithAI(code, "/test.js", "javascript")

        if (vulns.isNotEmpty()) {
            val vuln = vulns.first()
            assertEquals(VulnerabilityType.CODE_INJECTION, vuln.type)
            assertEquals("/test.js", vuln.filePath)
            assertTrue(vuln.tags.contains("javascript"))
            assertTrue(vuln.tags.contains("ai-analysis"))
            assertEquals(0.75f, vuln.confidence)
        }
    }

    @Test
    fun `detectSecrets finds AWS access key pattern`() {
        val code = """val key = "AKIAIOSFODNN7EXAMPLE" """
        val vulns = PremiumAnalyzers.detectSecrets(code, "/config.kt")

        assertTrue(vulns.isNotEmpty())
        assertTrue(vulns.any { it.severity == Severity.CRITICAL })
    }

    @Test
    fun `detectSecrets finds private key pattern`() {
        val code = """-----BEGIN RSA PRIVATE KEY-----"""
        val vulns = PremiumAnalyzers.detectSecrets(code, "/key.pem")

        assertTrue(vulns.isNotEmpty())
        assertTrue(vulns.any { it.ruleName.contains("Private Key") })
    }

    @Test
    fun `detectSecrets finds GitHub token pattern`() {
        // Pattern requires exactly 36 alphanumeric chars after ghp_
        val code = """token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" """
        val vulns = PremiumAnalyzers.detectSecrets(code, "/config.yml")

        assertTrue(vulns.isNotEmpty())
    }

    @Test
    fun `detectSecrets returns empty for clean code`() {
        val code = """
            fun add(a: Int, b: Int): Int = a + b
        """.trimIndent()
        val vulns = PremiumAnalyzers.detectSecrets(code, "/clean.kt")

        assertTrue(vulns.isEmpty())
    }

    @Test
    fun `detectSecrets records correct line number`() {
        val code = """
            line one
            line two
            token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        """.trimIndent()
        val vulns = PremiumAnalyzers.detectSecrets(code, "/test.kt")

        if (vulns.isNotEmpty()) {
            assertEquals(3, vulns.first().line)
        }
    }
}
