package com.jakubjirak.vulnspeed.analysis

import com.jakubjirak.vulnspeed.model.*

/**
 * Taint analysis for tracking data flow from sources to sinks
 */
class TaintAnalyzer {
    
    private val sources = setOf(
        "request.getParameter", "request.getHeader", "request.getCookie",
        "System.getenv", "System.getProperty", "readLine", "Scanner.next",
        "@RequestParam", "@PathVariable", "@RequestBody", "@RequestHeader"
    )
    
    private val sinks = mapOf(
        "executeQuery" to VulnerabilityType.SQL_INJECTION,
        "executeUpdate" to VulnerabilityType.SQL_INJECTION,
        "Runtime.exec" to VulnerabilityType.COMMAND_INJECTION,
        "ProcessBuilder" to VulnerabilityType.COMMAND_INJECTION,
        "FileOutputStream" to VulnerabilityType.PATH_TRAVERSAL,
        "innerHTML" to VulnerabilityType.XSS,
        "document.write" to VulnerabilityType.XSS,
        "eval(" to VulnerabilityType.XSS
    )
    
    private val sanitizers = setOf(
        "encode", "escape", "sanitize", "validate", "normalize", "filter"
    )
    
    fun analyzeTaintFlow(code: String, filePath: String): List<TaintFlow> {
        val flows = mutableListOf<TaintFlow>()
        val lines = code.lines()
        
        lines.forEachIndexed { lineNum, line ->
            sources.forEach { source ->
                if (line.contains(source)) {
                    val variable = extractVariableName(line, source)
                    if (variable != null) {
                        val sink = findSink(lines, lineNum, variable)
                        if (sink != null && !hasSanitization(lines, lineNum, sink.first, variable)) {
                            flows.add(
                                TaintFlow(
                                    source = source,
                                    sink = sink.second,
                                    sinkType = sinks[sink.second] ?: VulnerabilityType.INFORMATION_DISCLOSURE,
                                    variable = variable,
                                    sourceLine = lineNum + 1,
                                    sinkLine = sink.first + 1,
                                    filePath = filePath,
                                    isSanitized = false
                                )
                            )
                        }
                    }
                }
            }
        }
        
        return flows
    }
    
    private fun extractVariableName(line: String, source: String): String? {
        val assignmentPattern = """(\w+)\s*=.*$source""".toRegex()
        val match = assignmentPattern.find(line)
        return match?.groupValues?.get(1)
    }
    
    private fun findSink(lines: List<String>, startLine: Int, variable: String): Pair<Int, String>? {
        for (i in startLine until lines.size.coerceAtMost(startLine + 50)) {
            val line = lines[i]
            if (line.contains(variable)) {
                sinks.keys.forEach { sink ->
                    if (line.contains(sink)) {
                        return Pair(i, sink)
                    }
                }
            }
        }
        return null
    }
    
    private fun hasSanitization(lines: List<String>, sourceLineNum: Int, sinkLineNum: Int, variable: String): Boolean {
        for (i in sourceLineNum until sinkLineNum) {
            val line = lines[i]
            if (line.contains(variable)) {
                sanitizers.forEach { sanitizer ->
                    if (line.contains(sanitizer)) {
                        return true
                    }
                }
            }
        }
        return false
    }
}

data class TaintFlow(
    val source: String,
    val sink: String,
    val sinkType: VulnerabilityType,
    val variable: String,
    val sourceLine: Int,
    val sinkLine: Int,
    val filePath: String,
    val isSanitized: Boolean
)
