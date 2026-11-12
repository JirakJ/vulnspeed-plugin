/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes

/**
 * Finds the files a project scan covers: every file with a supported extension
 * ([ScanPolicy.isSupportedFile]) below the project root, skipping excluded
 * directories ([ScanPolicy.isExcludedDirectory]: hidden directories such as
 * `.git` / `.idea`, `node_modules` and `build`). Symbolic links are not followed.
 *
 * Used by both the IDE project scan and the headless CLI, so they cover the
 * same set of files.
 */
object ProjectFileWalker {

    /**
     * Returns the scannable files below [root], sorted by path so results are
     * deterministic. Unreadable directories are skipped. Returns an empty list
     * when [root] is not a directory.
     */
    fun collect(root: Path): List<Path> {
        if (!Files.isDirectory(root)) return emptyList()
        val files = mutableListOf<Path>()
        Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
            override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                val name = dir.fileName?.toString() ?: return FileVisitResult.CONTINUE
                return if (dir != root && ScanPolicy.isExcludedDirectory(name)) {
                    FileVisitResult.SKIP_SUBTREE
                } else {
                    FileVisitResult.CONTINUE
                }
            }

            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (attrs.isRegularFile && ScanPolicy.isSupportedFile(file.fileName.toString())) {
                    files.add(file)
                }
                return FileVisitResult.CONTINUE
            }

            override fun visitFileFailed(file: Path, exc: IOException): FileVisitResult = FileVisitResult.CONTINUE
        })
        return files.sorted()
    }
}
