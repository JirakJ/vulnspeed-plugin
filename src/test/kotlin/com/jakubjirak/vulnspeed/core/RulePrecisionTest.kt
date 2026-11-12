/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/** The engine-level precision guards and the self-scan regression budget. */
class RulePrecisionTest {

    private val scanner = RuleScanner()

    private fun ruleIds(content: String, path: String): List<String> =
        scanner.scanContent(content, path, RuleScanner.languageFor(path), ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB)
            .vulnerabilities.map { it.ruleId }

    // --- language scoping ---

    @Test
    fun `docker rules do not fire on SQL lines in source code`() {
        // 2026.9.x reported DOCKER_004 / SESSION_007 on ordinary SQL in Kotlin sources.
        val sql = "val q = \"FROM users SELECT\"\nval s = \"SELECT id FROM users WHERE role = ?\"\n"
        assertEquals(emptyList<String>(), ruleIds(sql, "/p/src/Repo.kt"))
    }

    @Test
    fun `a rule runs only on its languages`() {
        val line = "data = yaml.load(stream)"
        assertTrue("DESER_002" in ruleIds(line, "/p/app.py"))
        assertFalse("DESER_002" in ruleIds(line, "/p/App.java"))
        assertFalse("DESER_002" in ruleIds(line, "/p/app.js"))
    }

    @Test
    fun `dockerfile rules run on Dockerfiles only`() {
        assertTrue("DOCKER_001" in ruleIds("FROM node:latest\n", "/p/Dockerfile"))
        assertTrue("DOCKER_001" in ruleIds("FROM node:latest\n", "/p/api.dockerfile"))
        assertFalse("DOCKER_001" in ruleIds("FROM node:latest\n", "/p/notes.yaml"))
    }

    // --- comments, long lines, test files ---

    @Test
    fun `commented-out code is not reported but secrets in comments are`() {
        val content = "/*\n * String q = \"SELECT * FROM t WHERE id = \" + id;\n */\n// key AKIAIOSFODNN7EXAMPLE\n"
        val ids = ruleIds(content, "/p/App.java")
        assertFalse("SQL_001" in ids)
        assertTrue("SECRET_AWS_001" in ids)
    }

    @Test
    fun `python docstrings are skipped but multi-line SQL strings are scanned`() {
        val docstring = "def f():\n    \"\"\"\n    yaml.load(stream)\n    \"\"\"\n"
        assertFalse("DESER_002" in ruleIds(docstring, "/p/app.py"))

        val code = "q = \"\"\"\nSELECT 1\n\"\"\"\ndata = yaml.load(stream)\n"
        assertTrue("DESER_002" in ruleIds(code, "/p/app.py"))
    }

    @Test
    fun `minified lines are skipped`() {
        val minified = "var a=1;" + "x".repeat(RuleScanner.MAX_LINE_LENGTH) + ";el.innerHTML=userInput;"
        assertFalse("XSS_001" in ruleIds(minified, "/p/app.js"))
        assertTrue("XSS_001" in ruleIds("el.innerHTML = userInput;", "/p/app.js"))
    }

    @Test
    fun `rules marked skipTestFiles ignore test sources`() {
        val line = "String password = \"Sup3rS3cret!\";"
        assertTrue("AUTH_001" in ruleIds(line, "/p/src/main/java/App.java"))
        assertFalse("AUTH_001" in ruleIds(line, "/p/src/test/java/App.java"))
        assertFalse("AUTH_001" in ruleIds(line, "/p/src/main/java/AppTest.java"))
    }

    // --- file context ---

    @Test
    fun `excludeIfFileContains suppresses a hardened file`() {
        val plain = "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();"
        assertTrue("XXE_001" in ruleIds(plain, "/p/X.java"))
        val hardened = plain + "\nf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"
        assertFalse("XXE_001" in ruleIds(hardened, "/p/X.java"))
    }

    @Test
    fun `requiresInFile gates a rule on file context`() {
        val line = "ctx.search(base, \"(uid=\" + user + \")\", controls);"
        assertFalse("LDAP_001" in ruleIds(line, "/p/X.java"))
        assertTrue("LDAP_001" in ruleIds("import javax.naming.directory.DirContext;\n$line", "/p/X.java"))
    }

    // --- dedupe ---

    @Test
    fun `a rule reports a line once even with several matches`() {
        val line = "a.innerHTML = x; b.innerHTML = y;"
        assertEquals(1, ruleIds(line, "/p/app.js").count { it == "XSS_001" })
    }

    @Test
    fun `same-CWE findings on one line keep only the most severe`() {
        // AUTH_001 (HIGH, CWE-798) and SECRET_AWS_001 (CRITICAL, CWE-798) both match.
        val ids = ruleIds("String secret = \"AKIAIOSFODNN7EXAMPLE\";", "/p/App.java")
        assertEquals(listOf("SECRET_AWS_001"), ids)
    }

    @Test
    fun `excludePattern drops placeholder values`() {
        assertTrue("SECRET_URL_001" in ruleIds("String url = \"postgres://app:Xy9!kq@db/app\";", "/p/App.java"))
        assertFalse("SECRET_URL_001" in ruleIds("String url = \"postgres://user:password@localhost/db\";", "/p/App.java"))
        assertFalse("AUTH_001" in ruleIds("String password = \"<your-password>\";", "/p/App.java"))
    }

    @Test
    fun `custom rules without languages still run everywhere`() {
        val rule = Rule("T_1", "t", "t", Severity.LOW, 1, "x", pattern = "forbidden")
        assertTrue(rule.languages.isEmpty())
        assertFalse(rule.matchAnywhere)
        assertFalse(rule.skipTestFiles)
    }

    // --- languages and file names ---

    @Test
    fun `language detection covers config formats and module extensions`() {
        assertEquals("dockerfile", SourceLanguages.languageFor("Dockerfile"))
        assertEquals("dockerfile", SourceLanguages.languageFor("/x/Dockerfile.prod"))
        assertEquals("dockerfile", SourceLanguages.languageFor("Containerfile"))
        assertEquals("yaml", SourceLanguages.languageFor("docker-compose.yml"))
        assertEquals("properties", SourceLanguages.languageFor("application.properties"))
        assertEquals("javascript", SourceLanguages.languageFor("index.mjs"))
        assertEquals("typescript", SourceLanguages.languageFor("App.tsx"))
        assertEquals("cpp", SourceLanguages.languageFor("a.hpp"))
        assertEquals("unknown", SourceLanguages.languageFor("README.md"))
    }

    @Test
    fun `test paths are recognised`() {
        listOf(
            "/p/src/test/java/A.java", "/p/tests/test_x.py", "/p/pkg/x_test.go", "/p/src/a.spec.ts",
            "/p/__tests__/a.js", "/p/src/main/kotlin/FooTest.kt", "/p/conftest.py",
        ).forEach { assertTrue(SourceLanguages.isTestPath(it), it) }
        listOf("/p/src/main/java/A.java", "/p/app/contest.py", "/p/src/Testing.kt").forEach {
            assertFalse(SourceLanguages.isTestPath(it), it)
        }
    }

    @Test
    fun `minified bundles and dependency folders are not scanned`() {
        assertFalse(ScanPolicy.isSupportedFile("jquery.min.js"))
        assertFalse(ScanPolicy.isSupportedFile("raphael-min.js"))
        assertTrue(ScanPolicy.isSupportedFile("Dockerfile"))
        assertTrue(ScanPolicy.isSupportedFile("deploy.yaml"))
        listOf("vendor", "dist", "target", "__pycache__", "venv").forEach { assertTrue(ScanPolicy.isExcludedDirectory(it), it) }
    }

    // --- comment masks ---

    @Test
    fun `comment masks per language`() {
        assertArrayEquals(
            booleanArrayOf(false, true, true, true, false, true),
            CommentLines.mask(listOf("int a;", "/**", " * doc", " */", "int b; // trailing", "// only"), "java"),
        )
        assertArrayEquals(
            booleanArrayOf(true, false, true),
            CommentLines.mask(listOf("# c", "key: v", "  # nested"), "yaml"),
        )
        assertArrayEquals(
            booleanArrayOf(true, false),
            CommentLines.mask(listOf("! legacy comment", "a=b"), "properties"),
        )
        assertArrayEquals(
            booleanArrayOf(false, true, false, false, false, true),
            CommentLines.mask(listOf("x = 1", "\"\"\"one-line docstring\"\"\"", "s = '''", "body", "'''", "# c"), "python"),
        )
        assertArrayEquals(booleanArrayOf(false), CommentLines.mask(listOf("// not a comment here"), "unknown"))
    }

    // --- self-scan regression ---

    @Test
    fun `self-scan of the plugin's production sources stays within budget`() {
        val main = Path.of("src/main")
        if (!Files.isDirectory(main)) return // only meaningful when run from the project directory (Gradle does)
        val findings = HeadlessProjectScanner().scan(main).result.vulnerabilities
        assertTrue(
            findings.size <= SELF_SCAN_BUDGET,
            "self-scan found ${findings.size} findings (budget $SELF_SCAN_BUDGET):\n" +
                findings.joinToString("\n") { "${it.ruleId} ${it.filePath}:${it.line} ${it.codeSnippet}" },
        )
    }

    companion object {
        /**
         * Maximum findings a scan of VulnSpeed's own `src/main` may report. 2026.9.2 reported
         * 850 here (1,157 for the whole source tree); 2026.10.0 reports 0. A failing budget
         * means a rule regressed into noise — fix the rule, don't raise the budget.
         */
        const val SELF_SCAN_BUDGET = 5
    }
}
