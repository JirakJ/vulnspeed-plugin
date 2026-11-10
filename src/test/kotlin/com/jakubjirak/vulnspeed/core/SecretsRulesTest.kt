/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.Severity
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SecretsRulesTest {

    private fun ruleFor(id: String) = SecretsRules.RULES.first { it.id == id }

    private fun matches(ruleId: String, text: String): Boolean =
        Regex(ruleFor(ruleId).pattern).containsMatchIn(text)

    @Test
    fun `ruleset has 12 rules with unique ids`() {
        assertEquals(12, SecretsRules.RULES.size)
        assertEquals(SecretsRules.RULES.size, SecretsRules.RULES.map { it.id }.toSet().size)
    }

    @Test
    fun `all rules use CWE-798 and SECRET prefix`() {
        SecretsRules.RULES.forEach { rule ->
            assertEquals(798, rule.cwe, rule.id)
            assertTrue(rule.id.startsWith("SECRET_"), rule.id)
            assertTrue(rule.enabled, rule.id)
        }
    }

    @Test
    fun `all patterns compile`() {
        SecretsRules.RULES.forEach { rule ->
            assertDoesNotThrow({ Regex(rule.pattern) }, "Pattern of ${rule.id} must compile")
        }
    }

    @Test
    fun `detects AWS access key id`() {
        assertTrue(matches("SECRET_AWS_001", """aws_key = "AKIAIOSFODNN7EXAMPLE""""))
        assertTrue(matches("SECRET_AWS_001", "ASIAIOSFODNN7EXAMPLE"))
        assertFalse(matches("SECRET_AWS_001", "AKIA_TOO_SHORT"))
    }

    @Test
    fun `detects GitHub tokens`() {
        assertTrue(matches("SECRET_GITHUB_001", "ghp_0123456789abcdefghijABCDEFGHIJ123456"))
        assertTrue(matches("SECRET_GITHUB_001", "ghs_0123456789abcdefghijABCDEFGHIJ123456"))
        assertFalse(matches("SECRET_GITHUB_001", "ghp_short"))
    }

    @Test
    fun `detects GitLab personal access token`() {
        assertTrue(matches("SECRET_GITLAB_001", "glpat-AbCdEfGhIjKlMnOpQrSt"))
        assertFalse(matches("SECRET_GITLAB_001", "glpat-short"))
    }

    @Test
    fun `detects Slack tokens`() {
        assertTrue(matches("SECRET_SLACK_001", "xoxb-123456789012-ABCdefGHIjkl"))
        assertFalse(matches("SECRET_SLACK_001", "xoxz-123456789012"))
    }

    @Test
    fun `detects Stripe live keys but not test keys`() {
        assertTrue(matches("SECRET_STRIPE_001", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
        assertTrue(matches("SECRET_STRIPE_001", "rk_live_4eC39HqLyjWDarjtT1zdp7dc"))
        assertFalse(matches("SECRET_STRIPE_001", "sk_test_4eC39HqLyjWDarjtT1zdp7dc"))
    }

    @Test
    fun `detects Google API key`() {
        assertTrue(matches("SECRET_GOOGLE_001", "AIzaSyA-1234567890abcdefghijklmnopqrstu"))
        assertFalse(matches("SECRET_GOOGLE_001", "AIzaShort"))
    }

    @Test
    fun `detects private key blocks`() {
        assertTrue(matches("SECRET_PEM_001", "-----BEGIN RSA PRIVATE KEY-----"))
        assertTrue(matches("SECRET_PEM_001", "-----BEGIN PRIVATE KEY-----"))
        assertTrue(matches("SECRET_PEM_001", "-----BEGIN OPENSSH PRIVATE KEY-----"))
        assertFalse(matches("SECRET_PEM_001", "-----BEGIN PUBLIC KEY-----"))
        assertFalse(matches("SECRET_PEM_001", "-----BEGIN CERTIFICATE-----"))
    }

    @Test
    fun `detects npm token`() {
        assertTrue(matches("SECRET_NPM_001", "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"))
        assertFalse(matches("SECRET_NPM_001", "npm_short"))
    }

    @Test
    fun `detects SendGrid key`() {
        assertTrue(
            matches(
                "SECRET_SENDGRID_001",
                "SG.aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeF0"
            )
        )
        assertFalse(matches("SECRET_SENDGRID_001", "SG.short.key"))
    }

    @Test
    fun `detects Twilio API key sid`() {
        assertTrue(matches("SECRET_TWILIO_001", "SK0123456789abcdef0123456789abcdef"))
        assertFalse(matches("SECRET_TWILIO_001", "SK_not_hex"))
    }

    @Test
    fun `detects credentials embedded in URLs`() {
        assertTrue(matches("SECRET_URL_001", "https://admin:hunter2@db.internal:5432/prod"))
        assertTrue(matches("SECRET_URL_001", "postgres://user:pass@host/db"))
        assertFalse(matches("SECRET_URL_001", "https://example.com/path"))
    }

    @Test
    fun `detects hardcoded JWT`() {
        val jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ." +
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
        assertTrue(matches("SECRET_JWT_001", jwt))
        assertFalse(matches("SECRET_JWT_001", "eyJOnly.OnePart"))
    }

    @Test
    fun `severities are CRITICAL or HIGH except JWT`() {
        SecretsRules.RULES.forEach { rule ->
            if (rule.id == "SECRET_JWT_001") {
                assertEquals(Severity.MEDIUM, rule.severity)
            } else {
                assertTrue(
                    rule.severity == Severity.CRITICAL || rule.severity == Severity.HIGH,
                    "${rule.id} has ${rule.severity}"
                )
            }
        }
    }

    @Test
    fun `clean code produces no matches in any rule`() {
        val clean = """
            val apiKey = System.getenv("API_KEY")
            val url = "https://example.com/api/v1/users"
            println("hello world")
        """.trimIndent()
        SecretsRules.RULES.forEach { rule ->
            assertFalse(Regex(rule.pattern).containsMatchIn(clean), "${rule.id} false positive")
        }
    }
}
