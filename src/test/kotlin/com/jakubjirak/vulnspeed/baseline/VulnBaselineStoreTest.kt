/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class VulnBaselineStoreTest {

    private fun sample(): VulnBaseline = VulnBaseline(
        generatedAtEpochMs = 1_700_000_000_000L,
        toolVersion = "2026.4.4",
        projectRootHash = "abc",
        entries = listOf(
            VulnBaselineEntry(
                fingerprint = "f1",
                ruleId = "R1",
                severity = "HIGH",
                cwe = 89,
                filePath = "src/A.java",
                startLine = 10,
                messageHash = "m1",
                acceptedReason = "legacy — tracked by TICKET-42",
                acceptedAtEpochMs = 1_700_000_000_000L,
            ),
        ),
    )

    @Test
    fun `load missing file returns null`(@TempDir dir: Path) {
        assertNull(VulnBaselineStore.load(dir.resolve("missing.json")))
    }

    @Test
    fun `save then load round-trips entries and reason`(@TempDir dir: Path) {
        val target = dir.resolve("baseline.json")
        VulnBaselineStore.save(sample(), target)
        val loaded = VulnBaselineStore.load(target)
        assertNotNull(loaded)
        assertEquals(sample(), loaded)
        assertEquals("legacy — tracked by TICKET-42", loaded!!.entries[0].acceptedReason)
    }

    @Test
    fun `save is atomic with no tmp leftover`(@TempDir dir: Path) {
        val target = dir.resolve("baseline.json")
        VulnBaselineStore.save(sample(), target)
        val names = Files.list(dir).use { stream -> stream.map { it.fileName.toString() }.toList() }
        assertTrue(names.contains("baseline.json"))
        assertTrue(names.none { it.endsWith(".tmp") }, "Unexpected tmp leftovers: $names")
    }

    @Test
    fun `saveDefault writes expected filename and overwrites`(@TempDir dir: Path) {
        val p1 = VulnBaselineStore.saveDefault(sample(), dir)
        val p2 = VulnBaselineStore.saveDefault(sample(), dir)
        assertEquals(p1, p2)
        assertEquals(".vulnspeed-baseline.json", p1.fileName.toString())
    }

    @Test
    fun `load throws on malformed JSON`(@TempDir dir: Path) {
        val target = dir.resolve("bad.json")
        Files.write(target, "{not-json".toByteArray(StandardCharsets.UTF_8))
        val ex = assertThrows(VulnBaselineIoException::class.java) {
            VulnBaselineStore.load(target)
        }
        assertTrue(ex.message!!.contains("Malformed") || ex.message!!.contains("parse"))
    }

    @Test
    fun `load throws on unknown schemaVersion`(@TempDir dir: Path) {
        val target = dir.resolve("baseline.json")
        val futureJson = """
            {"schemaVersion":999,"generatedAtEpochMs":0,"toolVersion":"x","projectRootHash":"y","entries":[]}
        """.trimIndent()
        Files.write(target, futureJson.toByteArray(StandardCharsets.UTF_8))
        val ex = assertThrows(VulnBaselineIoException::class.java) {
            VulnBaselineStore.load(target)
        }
        assertTrue(ex.message!!.contains("schemaVersion"))
    }

    @Test
    fun `load throws on empty file`(@TempDir dir: Path) {
        val target = dir.resolve("empty.json")
        Files.write(target, ByteArray(0))
        assertThrows(VulnBaselineIoException::class.java) {
            VulnBaselineStore.load(target)
        }
    }
}
