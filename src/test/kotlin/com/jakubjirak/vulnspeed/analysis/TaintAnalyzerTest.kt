/*
 * Copyright (c) 2025 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.VulnerabilityType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class TaintAnalyzerTest {

    private val analyzer = TaintAnalyzer()

    @Test
    fun `analyzeTaintFlow detects SQL injection flow`() {
        // The taint analyzer tracks the variable name from source to sink.
        // The sink line must contain both the variable name and the sink method.
        val code = """
            String userInput = request.getParameter("id");
            stmt.executeQuery("SELECT * FROM users WHERE id = " + userInput);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/Test.java")

        assertTrue(flows.isNotEmpty(), "Expected taint flow to be detected")
        val flow = flows.first()
        assertEquals("request.getParameter", flow.source)
        assertEquals("executeQuery", flow.sink)
        assertEquals(VulnerabilityType.SQL_INJECTION, flow.sinkType)
        assertEquals("userInput", flow.variable)
        assertFalse(flow.isSanitized)
    }

    @Test
    fun `analyzeTaintFlow detects command injection flow`() {
        val code = """
            String cmd = request.getParameter("cmd");
            Runtime.exec(cmd);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/Test.java")

        assertTrue(flows.isNotEmpty())
        assertEquals(VulnerabilityType.COMMAND_INJECTION, flows.first().sinkType)
    }

    @Test
    fun `analyzeTaintFlow detects XSS via innerHTML`() {
        val code = """
            String data = request.getParameter("input");
            element.innerHTML = data;
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/test.js")

        assertTrue(flows.isNotEmpty())
        assertEquals(VulnerabilityType.XSS, flows.first().sinkType)
    }

    @Test
    fun `analyzeTaintFlow returns empty when no tainted flow`() {
        val code = """
            String safe = "constant";
            System.out.println(safe);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/Safe.java")
        assertTrue(flows.isEmpty())
    }

    @Test
    fun `analyzeTaintFlow respects sanitization`() {
        val code = """
            String userInput = request.getParameter("name");
            String clean = sanitize(userInput);
            stmt.executeQuery(clean);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/Test.java")
        // The taint flow should be suppressed because sanitize is between source and sink
        assertTrue(flows.isEmpty())
    }

    @Test
    fun `analyzeTaintFlow detects multiple sources`() {
        val code = """
            String param1 = request.getParameter("a");
            stmt.executeQuery(param1);
            String param2 = request.getHeader("b");
            stmt.executeUpdate(param2);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/Test.java")
        assertTrue(flows.size >= 2)
    }

    @Test
    fun `analyzeTaintFlow records correct line numbers`() {
        val code = """
            String x = request.getParameter("id");
            String q = "SELECT " + x;
            stmt.executeQuery(q);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/Test.java")
        assertTrue(flows.isNotEmpty())
        assertEquals(1, flows.first().sourceLine)
    }

    @Test
    fun `analyzeTaintFlow records file path`() {
        val code = """
            String val = request.getParameter("x");
            stmt.executeQuery(val);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/src/MyServlet.java")
        assertTrue(flows.isNotEmpty())
        assertEquals("/src/MyServlet.java", flows.first().filePath)
    }

    @Test
    fun `TaintFlow data class stores all fields`() {
        val flow = TaintFlow(
            source = "request.getParameter",
            sink = "executeQuery",
            sinkType = VulnerabilityType.SQL_INJECTION,
            variable = "input",
            sourceLine = 5,
            sinkLine = 10,
            filePath = "/test.java",
            isSanitized = false
        )

        assertEquals("request.getParameter", flow.source)
        assertEquals("executeQuery", flow.sink)
        assertEquals(5, flow.sourceLine)
        assertEquals(10, flow.sinkLine)
        assertFalse(flow.isSanitized)
    }

    @Test
    fun `analyzeTaintFlow handles System_getenv as source`() {
        val code = """
            String envVal = System.getenv("SECRET");
            Runtime.exec(envVal);
        """.trimIndent()

        val flows = analyzer.analyzeTaintFlow(code, "/test.java")
        assertTrue(flows.isNotEmpty())
        assertEquals("System.getenv", flows.first().source)
    }
}
