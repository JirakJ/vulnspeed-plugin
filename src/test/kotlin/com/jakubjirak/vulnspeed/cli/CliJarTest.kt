/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.cli

import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile

/**
 * Runs the built `vulnspeed-cli-<version>.jar` in a separate JVM with nothing else on
 * the classpath — proves the published jar is self-contained (no IntelliJ classes needed).
 * The jar path comes from the `vulnspeed.cliJar` system property set by Gradle (`test` depends on `cliJar`).
 */
class CliJarTest {

    @TempDir
    lateinit var dir: Path

    private val jar: Path = Paths.get(
        requireNotNull(System.getProperty("vulnspeed.cliJar")) { "vulnspeed.cliJar system property not set" }
    )

    private data class Proc(val code: Int, val out: String, val err: String)

    private fun java(vararg args: String): Proc {
        val javaBin = Paths.get(System.getProperty("java.home"), "bin", "java").toString()
        val outFile = dir.resolve("stdout-${System.nanoTime()}.txt")
        val errFile = dir.resolve("stderr-${System.nanoTime()}.txt")
        val process = ProcessBuilder(listOf(javaBin, "-jar", jar.toString()) + args)
            .redirectOutput(outFile.toFile())
            .redirectError(errFile.toFile())
            .start()
        assertTrue(process.waitFor(2, TimeUnit.MINUTES), "CLI did not finish")
        return Proc(
            process.exitValue(),
            Files.readString(outFile, StandardCharsets.UTF_8),
            Files.readString(errFile, StandardCharsets.UTF_8)
        )
    }

    @Test
    fun `jar contains no IntelliJ-bound classes and has a Main-Class`() {
        ZipFile(jar.toFile()).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            assertTrue("com/jakubjirak/vulnspeed/cli/VulnSpeedCli.class" in names)
            assertTrue("kotlin/Unit.class" in names, "Kotlin stdlib must be bundled")
            assertTrue("com/google/gson/Gson.class" in names, "Gson must be bundled")
            assertFalse(names.any { it.startsWith("com/intellij/") })
            val own = names.filter { it.startsWith("com/jakubjirak/") }
            assertFalse(own.any { it.contains("Action") || it.contains("VulnSpeedEngine") }, own.toString())
            assertFalse(names.any { it == "META-INF/plugin.xml" })
            val manifest = zip.getInputStream(zip.getEntry("META-INF/MANIFEST.MF")).readBytes().toString(Charsets.UTF_8)
            assertTrue(manifest.contains("Main-Class: com.jakubjirak.vulnspeed.cli.VulnSpeedCli"))
        }
    }

    @Test
    fun `java -jar scan writes findings and SARIF and gates with exit code 2`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val json = dir.resolve("out/findings.json")
        val sarif = dir.resolve("out/vulnspeed.sarif")

        val run = java("scan", "--project=$project", "--out-json=$json", "--out-sarif=$sarif", "--fail-on=severity:HIGH")

        assertEquals(2, run.code, run.err)
        assertTrue(run.out.contains("Scanned 4 file(s)"), run.out)
        val findings = JsonParser.parseString(Files.readString(json, StandardCharsets.UTF_8)).asJsonArray
        assertTrue(findings.any { it.asJsonObject["ruleId"].asString == "SQL_001" })
        val sarifDoc = JsonParser.parseString(Files.readString(sarif, StandardCharsets.UTF_8)).asJsonObject
        assertEquals("2.1.0", sarifDoc["version"].asString)
        assertEquals(findings.size(), sarifDoc.getAsJsonArray("runs")[0].asJsonObject.getAsJsonArray("results").size())
    }

    @Test
    fun `java -jar baseline and enrich run over the scan output`() {
        val project = CliFixtures.vulnerableProject(dir.resolve("p"))
        val json = dir.resolve("findings.json")
        val baseline = dir.resolve("baseline.json")
        assertEquals(0, java("scan", "--project=$project", "--out-json=$json").code)

        assertEquals(0, java("baseline", "--create", "--project=$project", "--findings=$json", "--baseline=$baseline").code)
        val compare = java(
            "baseline", "--compare", "--project=$project", "--findings=$json", "--baseline=$baseline",
            "--fail-on=severity:HIGH"
        )
        assertEquals(0, compare.code, compare.err)

        val enrich = java("enrich", "--findings=$json", "--format=md", "--offline", "--cache-dir=${dir.resolve("cache")}")
        assertEquals(0, enrich.code, enrich.err)
    }

    @Test
    fun `java -jar version and clean project`() {
        val version = java("version")
        assertEquals(0, version.code)
        assertTrue(version.out.trim().matches(Regex("vulnspeed-cli \\d{4}\\.\\d+\\.\\d+")), version.out)

        val project = CliFixtures.cleanProject(dir.resolve("clean"))
        assertEquals(0, java("scan", "--project=$project", "--fail-on=severity:LOW").code)
    }
}
