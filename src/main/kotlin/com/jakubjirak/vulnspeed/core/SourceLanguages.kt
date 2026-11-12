/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

/**
 * Language tags used to scope rules ([com.jakubjirak.vulnspeed.model.Rule.languages])
 * and to tag findings, plus the file-name heuristics that derive them.
 */
object SourceLanguages {

    const val JAVA = "java"
    const val KOTLIN = "kotlin"
    const val PYTHON = "python"
    const val JAVASCRIPT = "javascript"
    const val TYPESCRIPT = "typescript"
    const val SWIFT = "swift"
    const val C = "c"
    const val CPP = "cpp"
    const val GO = "go"
    const val RUST = "rust"
    const val DOCKERFILE = "dockerfile"
    const val YAML = "yaml"
    const val PROPERTIES = "properties"
    const val UNKNOWN = "unknown"

    val JVM: Set<String> = setOf(JAVA, KOTLIN)
    val JS: Set<String> = setOf(JAVASCRIPT, TYPESCRIPT)
    val NATIVE: Set<String> = setOf(C, CPP)

    /** Every programming language VulnSpeed scans (configuration formats excluded). */
    val CODE: Set<String> = JVM + JS + NATIVE + setOf(PYTHON, SWIFT, GO, RUST)

    /** Configuration formats VulnSpeed scans. */
    val CONFIG: Set<String> = setOf(DOCKERFILE, YAML, PROPERTIES)

    private val BY_EXTENSION: Map<String, String> = buildMap {
        put("java", JAVA)
        listOf("kt", "kts").forEach { put(it, KOTLIN) }
        put("py", PYTHON)
        listOf("js", "mjs", "cjs", "jsx").forEach { put(it, JAVASCRIPT) }
        listOf("ts", "mts", "cts", "tsx").forEach { put(it, TYPESCRIPT) }
        put("swift", SWIFT)
        listOf("cpp", "cc", "cxx", "hpp", "hh", "hxx").forEach { put(it, CPP) }
        listOf("c", "h").forEach { put(it, C) }
        put("go", GO)
        put("rs", RUST)
        listOf("yml", "yaml").forEach { put(it, YAML) }
        put("properties", PROPERTIES)
        put("dockerfile", DOCKERFILE)
    }

    /** Extensions that map to a language (Dockerfiles are additionally recognised by name). */
    val EXTENSIONS: Set<String> = BY_EXTENSION.keys

    /** Language tag for [fileName] (a bare name or a path), or [UNKNOWN]. */
    fun languageFor(fileName: String): String {
        val name = fileName.substringAfterLast('/').substringAfterLast('\\')
        if (isDockerfileName(name)) return DOCKERFILE
        if (!name.contains('.')) return UNKNOWN
        return BY_EXTENSION[name.substringAfterLast('.').lowercase()] ?: UNKNOWN
    }

    /** `Dockerfile`, `Containerfile`, `Dockerfile.prod`, `prod.Dockerfile`, `api.dockerfile`. */
    fun isDockerfileName(name: String): Boolean {
        val lower = name.lowercase()
        return lower == "dockerfile" || lower == "containerfile" || lower.startsWith("dockerfile.") ||
            lower.endsWith(".dockerfile")
    }

    /** Minified or bundled JavaScript that is never worth scanning line by line. */
    fun isMinifiedName(name: String): Boolean {
        val lower = name.lowercase()
        return MINIFIED_SUFFIXES.any { lower.endsWith(it) }
    }

    private val MINIFIED_SUFFIXES = listOf(".min.js", "-min.js", ".min.mjs", ".bundle.js")

    private val TEST_DIRECTORY = Regex("""(^|/)(test|tests|__tests__|spec|specs|testing|testdata|test-fixtures|fixtures)/""")
    private val TEST_FILE = Regex(
        """(^|/)(test_[^/]*\.py|[^/]*_test\.(py|go)|conftest\.py|[^/]*(Test|Tests|Spec|IT)\.(java|kt|swift)|""" +
            """[^/]*\.(test|spec)\.(js|jsx|ts|tsx|mjs|cjs))$"""
    )

    /** True for test sources: files under a test directory or named like a test (`FooTest.kt`, `test_x.py`, `a.spec.ts`). */
    fun isTestPath(path: String): Boolean {
        val normalized = path.replace('\\', '/')
        return TEST_DIRECTORY.containsMatchIn(normalized) || TEST_FILE.containsMatchIn(normalized)
    }
}
