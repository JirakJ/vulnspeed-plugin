/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.cli

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/** Builds small on-disk projects for the headless scanner / CLI tests. */
object CliFixtures {

    /** A line SQL_001 (CRITICAL) reports. */
    const val SQL_LINE = "        String q = \"SELECT * FROM users WHERE id = \" + userId;"

    /** Source with no finding at all. */
    const val CLEAN_SOURCE = "class Clean {\n    int answer() { return 42; }\n}\n"

    /**
     * Writes a project with one vulnerable Java file plus files that must not be reported:
     * a suppressed line, an opted-out file, unsupported extensions and excluded directories.
     */
    fun vulnerableProject(root: Path): Path {
        write(root, "src/main/java/App.java", "class App {\n    void find(String userId) {\n$SQL_LINE\n    }\n}\n")
        write(
            root, "src/main/java/Accepted.java",
            "class Accepted {\n    void find(String userId) {\n$SQL_LINE // vulnspeed-ignore: SQL_001\n    }\n}\n"
        )
        write(root, "src/main/java/OptedOut.java", "// vulnspeed-ignore-file\nclass OptedOut {\n$SQL_LINE\n}\n")
        write(root, "src/main/java/Clean.java", CLEAN_SOURCE)
        write(root, "docs/notes.txt", SQL_LINE)
        write(root, "build/generated/Gen.java", "class Gen {\n$SQL_LINE\n}\n")
        write(root, "node_modules/lib/index.js", "el.innerHTML = userInput;\n")
        write(root, ".git/hooks/x.py", "query = \"SELECT * FROM t WHERE a = \" + b\n")
        return root
    }

    /** Writes a project whose only source file has no findings. */
    fun cleanProject(root: Path): Path {
        write(root, "src/Clean.java", CLEAN_SOURCE)
        return root
    }

    fun write(root: Path, relative: String, content: String): Path {
        val file = root.resolve(relative)
        Files.createDirectories(file.parent)
        Files.write(file, content.toByteArray(StandardCharsets.UTF_8))
        return file
    }

    /** Captured result of a CLI run. */
    data class Run(val code: Int, val out: String, val err: String)

    fun capture(block: (PrintStream, PrintStream) -> Int): Run {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = block(PrintStream(out, true, StandardCharsets.UTF_8), PrintStream(err, true, StandardCharsets.UTF_8))
        return Run(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8))
    }
}
