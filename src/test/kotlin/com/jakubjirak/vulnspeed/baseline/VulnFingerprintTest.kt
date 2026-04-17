/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class VulnFingerprintTest {

    private fun v(
        ruleId: String = "R1",
        cwe: Int = 89,
        filePath: String = "/root/src/A.java",
        line: Int = 10,
        message: String = "SQL injection at column 5 via 'name'",
    ): Vulnerability = Vulnerability(
        id = "id",
        ruleId = ruleId,
        ruleName = "n",
        type = VulnerabilityType.SQL_INJECTION,
        severity = Severity.HIGH,
        cwe = cwe,
        filePath = filePath,
        line = line,
        column = 1,
        message = message,
        codeSnippet = "",
    )

    @Test
    fun `fingerprint is deterministic across calls`(@TempDir root: Path) {
        val vuln = v(filePath = root.resolve("src/A.java").toString())
        val a = VulnFingerprint.of(vuln, root)
        val b = VulnFingerprint.of(vuln, root)
        assertEquals(a, b)
        assertEquals(64, a.length)
    }

    @Test
    fun `fingerprint changes when ruleId changes`(@TempDir root: Path) {
        val a = VulnFingerprint.of(v(ruleId = "R1", filePath = root.resolve("A.java").toString()), root)
        val b = VulnFingerprint.of(v(ruleId = "R2", filePath = root.resolve("A.java").toString()), root)
        assertNotEquals(a, b)
    }

    @Test
    fun `fingerprint changes when cwe changes`(@TempDir root: Path) {
        val a = VulnFingerprint.of(v(cwe = 89, filePath = root.resolve("A.java").toString()), root)
        val b = VulnFingerprint.of(v(cwe = 79, filePath = root.resolve("A.java").toString()), root)
        assertNotEquals(a, b)
    }

    @Test
    fun `fingerprint changes when file changes`(@TempDir root: Path) {
        val a = VulnFingerprint.of(v(filePath = root.resolve("A.java").toString()), root)
        val b = VulnFingerprint.of(v(filePath = root.resolve("B.java").toString()), root)
        assertNotEquals(a, b)
    }

    @Test
    fun `fingerprint changes when line changes`(@TempDir root: Path) {
        val a = VulnFingerprint.of(v(line = 10, filePath = root.resolve("A.java").toString()), root)
        val b = VulnFingerprint.of(v(line = 11, filePath = root.resolve("A.java").toString()), root)
        assertNotEquals(a, b)
    }

    @Test
    fun `fingerprint changes when normalized message changes`(@TempDir root: Path) {
        val a = VulnFingerprint.of(v(message = "SQL injection — tainted input", filePath = root.resolve("A.java").toString()), root)
        val b = VulnFingerprint.of(v(message = "XSS detected", filePath = root.resolve("A.java").toString()), root)
        assertNotEquals(a, b)
    }

    @Test
    fun `fingerprint stable under number and whitespace differences`(@TempDir root: Path) {
        val p = root.resolve("A.java").toString()
        val a = VulnFingerprint.of(v(message = "Error on   line 123", filePath = p), root)
        val b = VulnFingerprint.of(v(message = "error on line 456", filePath = p), root)
        assertEquals(a, b)
    }

    @Test
    fun `fingerprint stable under quoted string differences`(@TempDir root: Path) {
        val p = root.resolve("A.java").toString()
        val a = VulnFingerprint.of(
            v(filePath = p, message = "Tainted variable 'userName' flows to sink"),
            root,
        )
        val b = VulnFingerprint.of(
            v(filePath = p, message = "Tainted variable 'email' flows to sink"),
            root,
        )
        assertEquals(a, b)
    }

    @Test
    fun `normalizeMessage lower-cases and strips numbers and quotes`() {
        val out = VulnFingerprint.normalizeMessage("ERROR in   'foo' at line 42 (0.25s)")
        assertEquals("error in <S> at line <N> (<N>s)", out)
    }

    @Test
    fun `normalizeMessage collapses whitespace`() {
        assertEquals("a b c", VulnFingerprint.normalizeMessage("  a\tb\n  c  "))
    }

    @Test
    fun `messageHash is 64 hex chars`() {
        val h = VulnFingerprint.messageHash("hello 1")
        assertEquals(64, h.length)
        assertTrue(h.all { it in '0'..'9' || it in 'a'..'f' })
        // Messages that normalize to same form hash identically
        assertEquals(
            VulnFingerprint.messageHash("hello 1"),
            VulnFingerprint.messageHash("  hello   2 "),
        )
    }

    @Test
    fun `relative path uses forward slashes inside root`(@TempDir root: Path) {
        val p = root.resolve("src").resolve("A.java").toString()
        val rel = VulnFingerprint.relativeFilePath(p, root)
        assertEquals("src/A.java", rel)
    }

    @Test
    fun `relative path for outside root uses file prefix`(@TempDir root: Path, @TempDir outside: Path) {
        val p = outside.resolve("X.java").toString()
        val rel = VulnFingerprint.relativeFilePath(p, root)
        assertTrue(rel.startsWith("file://"), "expected file:// prefix, got $rel")
        assertTrue(rel.contains("X.java"))
    }
}
