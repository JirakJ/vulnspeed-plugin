/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.cli.CliFixtures
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class ProjectFileWalkerTest {

    @TempDir
    lateinit var dir: Path

    private fun relative(files: List<Path>): List<String> = files.map { dir.relativize(it).toString().replace('\\', '/') }

    @Test
    fun `collects supported files sorted, skipping excluded directories`() {
        CliFixtures.write(dir, "src/b/B.kt", "")
        CliFixtures.write(dir, "src/a/A.java", "")
        CliFixtures.write(dir, "README.md", "")
        CliFixtures.write(dir, "build/Gen.java", "")
        CliFixtures.write(dir, "node_modules/x/index.js", "")
        CliFixtures.write(dir, ".idea/Workspace.java", "")
        CliFixtures.write(dir, "web/app.ts", "")

        assertEquals(listOf("src/a/A.java", "src/b/B.kt", "web/app.ts"), relative(ProjectFileWalker.collect(dir)))
    }

    @Test
    fun `excluded names are only skipped as directories, and nested build dirs too`() {
        CliFixtures.write(dir, "src/build.kt", "")
        CliFixtures.write(dir, "module/build/Out.java", "")

        assertEquals(listOf("src/build.kt"), relative(ProjectFileWalker.collect(dir)))
    }

    @Test
    fun `a hidden project root itself is still walked`() {
        val root = dir.resolve(".hidden-project")
        CliFixtures.write(root, "Main.java", "")

        assertEquals(1, ProjectFileWalker.collect(root).size)
    }

    @Test
    fun `non-directory root yields no files`() {
        val file = CliFixtures.write(dir, "Main.java", "")

        assertTrue(ProjectFileWalker.collect(file).isEmpty())
        assertTrue(ProjectFileWalker.collect(dir.resolve("missing")).isEmpty())
    }

    @Test
    fun `excluded directory policy`() {
        assertTrue(ScanPolicy.isExcludedDirectory(".git"))
        assertTrue(ScanPolicy.isExcludedDirectory("node_modules"))
        assertTrue(ScanPolicy.isExcludedDirectory("build"))
        assertFalse(ScanPolicy.isExcludedDirectory("src"))
        assertFalse(ScanPolicy.isExcludedDirectory("builder"))
    }
}
