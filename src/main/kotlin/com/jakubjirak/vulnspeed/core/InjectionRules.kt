/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
// vulnspeed-ignore-file: rule names, descriptions and patterns quote the very code they detect.
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.core.RuleCatalog.A03
import com.jakubjirak.vulnspeed.core.RuleCatalog.JS
import com.jakubjirak.vulnspeed.core.RuleCatalog.JVM
import com.jakubjirak.vulnspeed.core.RuleCatalog.NATIVE
import com.jakubjirak.vulnspeed.core.RuleCatalog.SQL_STMT
import com.jakubjirak.vulnspeed.core.SourceLanguages.GO
import com.jakubjirak.vulnspeed.core.SourceLanguages.JAVA
import com.jakubjirak.vulnspeed.core.SourceLanguages.KOTLIN
import com.jakubjirak.vulnspeed.core.SourceLanguages.PYTHON
import com.jakubjirak.vulnspeed.core.SourceLanguages.SWIFT
import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity

/**
 * Injection rules: SQL / NoSQL, OS command, code, template, LDAP, XPath, reflection and ReDoS.
 * Positive / negative samples: `rule-samples.txt` (tests).
 */
internal object InjectionRules {
    val RULES: List<Rule> = listOf(
        Rule(
            id = "SQL_001",
            name = "SQL Injection via String Concatenation",
            description = "A SQL statement is built by concatenating a variable into the query string",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = JVM + JS + setOf(PYTHON, GO, SWIFT),
            pattern = """["'`]\s*$SQL_STMT[^"`]*?["'`]\s*\+\s*[A-Za-z_(]|""" +
                """["'`]\s*(?i:where|and|or)\s+[\w.]+\s*(?:=|<>|!=|<|>|(?i:like)|(?i:in)\s*\()\s*'?\(?["'`]\s*\+\s*[A-Za-z_(]""",
        ),
        Rule(
            id = "SQL_002",
            name = "SQL/HQL Injection in JPA or Hibernate Query",
            description = "A JPA / Hibernate query string is concatenated with a variable",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = JVM,
            pattern = """\b(?:createNativeQuery|createQuery|createSQLQuery)\s*\(\s*(?:"[^"]*"\s*\+|[A-Za-z_]\w*\s*\+)""",
        ),
        Rule(
            id = "SQL_003",
            name = "NoSQL Injection via MongoDB \$where",
            description = "A MongoDB \$where predicate is built from a variable — it executes as JavaScript on the server",
            severity = Severity.HIGH, cwe = 943, owasp = A03,
            languages = JS + PYTHON,
            pattern = """\${'$'}where["']?\s*:\s*(?:["'][^"']*["']\s*\+|`[^`]*\$\{|[fF]["'][^"']*\{)""",
        ),
        Rule(
            id = "SQL_004",
            name = "SQL Injection via Python String Formatting",
            description = "A SQL statement is built with an f-string, % formatting or str.format instead of query parameters",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """\b[fF][rR]?["']\s*$SQL_STMT[^"']*\{[A-Za-z_]|""" +
                """"\s*$SQL_STMT[^"]*"\s*(?:%\s*[\w(]|\.format\()|'\s*$SQL_STMT[^']*'\s*(?:%\s*[\w(]|\.format\()""",
        ),
        Rule(
            id = "SQL_005",
            name = "SQL Injection via String Interpolation",
            description = "A SQL statement interpolates a variable (JS template literal or Kotlin string template)",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = JS + KOTLIN,
            // Tagged templates (sql`…`, prisma.$queryRaw`…`) are parameterized and therefore excluded.
            pattern = """(?<![\w$.])`\s*$SQL_STMT[^`]*\$\{|"\s*$SQL_STMT[^"]*\$\{?[A-Za-z_]""",
        ),
        Rule(
            id = "SQL_006",
            name = "SQL Injection via Format String",
            description = "A SQL statement is built with fmt.Sprintf / String.format instead of query parameters",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = setOf(GO, JAVA, KOTLIN),
            pattern = """\b(?:fmt\.Sprintf|String\.format)\(\s*"\s*$SQL_STMT[^"]*%[sv]""",
        ),
        Rule(
            id = "NODE_002",
            name = "NoSQL Injection via Raw Request Object",
            description = "A MongoDB query receives the raw request object, so clients can inject query operators",
            severity = Severity.HIGH, cwe = 943, owasp = A03,
            languages = JS,
            pattern = """\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|""" +
                """countDocuments)\(\s*req\.(?:body|query|params)\s*[,)]""",
        ),
        Rule(
            id = "PRISMA_001",
            name = "Prisma Unsafe Raw Query",
            description = "\$queryRawUnsafe / \$executeRawUnsafe is called with an interpolated or concatenated query",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = JS,
            pattern = """\${'$'}(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_][\w.]*\s*\+)""",
        ),
        Rule(
            id = "SEQUELIZE_001",
            name = "Sequelize Raw Query Injection",
            description = "sequelize.query is called with an interpolated or concatenated SQL string",
            severity = Severity.CRITICAL, cwe = 89, owasp = A03,
            languages = JS,
            pattern = """\bsequelize\.query\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)""",
        ),
        Rule(
            id = "TYPEORM_001",
            name = "Query Builder Raw Condition Injection",
            description = "A query-builder where/having condition interpolates a variable instead of using parameters",
            severity = Severity.HIGH, cwe = 89, owasp = A03,
            languages = JS,
            requiresInFile = """createQueryBuilder|from ["']typeorm["']|require\(["']knex["']\)|from ["']knex["']""",
            pattern = """\.(?:where|andWhere|orWhere|having|whereRaw)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)""",
        ),
        Rule(
            id = "CMD_001",
            name = "Command Injection - Runtime.exec()",
            description = "Runtime.exec() is called with a command built from a variable",
            severity = Severity.CRITICAL, cwe = 78, owasp = A03,
            languages = JVM,
            pattern = """Runtime\.getRuntime\(\)\.exec\(\s*(?:"[^"]*"\s*\+|[A-Za-z_][\w.]*\s*\+|"[^"]*\$\{?[A-Za-z_])""",
        ),
        Rule(
            id = "CMD_002",
            name = "Command Injection - ProcessBuilder",
            description = "ProcessBuilder runs a shell command or an argument built by concatenation",
            severity = Severity.HIGH, cwe = 78, owasp = A03,
            languages = JVM,
            pattern = """\bProcessBuilder\s*\((?:[^;]*?"[^"]*"\s*\+\s*[A-Za-z_]|""" +
                """\s*(?:listOf\(|Arrays\.asList\(|List\.of\()?\s*"(?:sh|bash|""" +
                """/bin/sh|/bin/bash|cmd|cmd\.exe)"\s*,\s*"[-/][cC]"\s*,\s*[A-Za-z_])""",
        ),
        Rule(
            id = "CMD_003",
            name = "Command Injection - Python Shell Execution",
            description = "os.system / subprocess runs a command built with an f-string, concatenation or formatting",
            severity = Severity.CRITICAL, cwe = 78, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """\b(?:os\.(?:system|popen)|subprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput))""" +
                """\s*\(\s*(?:[fF]["']|["'][^"']*["']\s*(?:\+|%|\.format\()|[A-Za-z_][\w.]*\s*\+)""",
        ),
        Rule(
            id = "CMD_004",
            name = "Subprocess With shell=True",
            description = "subprocess is invoked through the shell; any untrusted part of the command can inject more commands",
            severity = Severity.MEDIUM, cwe = 78, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """\bsubprocess\.\w+\([^)]*\bshell\s*=\s*True""",
        ),
        Rule(
            id = "CMD_005",
            name = "Command Injection - Go exec.Command via Shell",
            description = "exec.Command runs `sh -c` with a command built at runtime",
            severity = Severity.HIGH, cwe = 78, owasp = A03,
            languages = setOf(GO),
            pattern = """exec\.Command(?:Context)?\(\s*(?:\w+\s*,\s*)?"(?:/bin/)?(?:ba)?sh"\s*,\s*"-c"\s*,\s*""" +
                """(?:[^")]*\+|fmt\.Sprintf|[A-Za-z_]\w*\s*\))""",
        ),
        Rule(
            id = "CMD_006",
            name = "Command Injection - system()/popen() With Variable",
            description = "system() or popen() runs a command held in a variable",
            severity = Severity.HIGH, cwe = 78, owasp = A03,
            languages = NATIVE,
            pattern = """(?<![\w.>])(?:std::)?(?:system|popen)\s*\(\s*[A-Za-z_]""",
        ),
        Rule(
            id = "JS_003",
            name = "Command Injection - Node.js child_process",
            description = "child_process.exec runs a shell command built with interpolation or concatenation",
            severity = Severity.CRITICAL, cwe = 78, owasp = A03,
            languages = JS,
            pattern = """(?:\b(?:child_process|childProcess|cp)\.|(?<![\w.$]))(?:exec|execSync)\s*\(\s*""" +
                """(?:`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_]\w*\s*\+)""",
        ),
        Rule(
            id = "PYTHON_002",
            name = "Python Code Injection via eval()/exec()",
            description = "eval() / exec() runs data that comes from the request, input() or the command line",
            severity = Severity.CRITICAL, cwe = 95, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """(?<![\w.])(?:eval|exec)\s*\([^)]*\b(?:request\.|input\s*\(|sys\.argv)""",
        ),
        Rule(
            id = "JS_004",
            name = "JavaScript Code Injection via eval()",
            description = "eval() / new Function() runs data taken from the HTTP request",
            severity = Severity.CRITICAL, cwe = 95, owasp = A03,
            languages = JS,
            pattern = """(?<![\w.$])(?:eval|Function)\s*\([^)]*\breq\.(?:body|query|params|headers|cookies)\b""",
        ),
        Rule(
            id = "SCRIPT_001",
            name = "Script Engine Injection",
            description = "A javax.script ScriptEngine evaluates a script built at runtime",
            severity = Severity.CRITICAL, cwe = 94, owasp = A03,
            languages = JVM,
            requiresInFile = """ScriptEngine""",
            pattern = """\.eval\s*\(\s*(?:"[^"]*"\s*\+|[A-Za-z_][\w.]*\s*\+|request\.getParameter)""",
        ),
        Rule(
            id = "EXPR_001",
            name = "Expression Language Injection",
            description = "A SpEL / OGNL / MVEL expression is built at runtime",
            severity = Severity.CRITICAL, cwe = 917, owasp = A03,
            languages = JVM,
            pattern = """\b(?:parseExpression|Ognl\.getValue|Ognl\.parseExpression|MVEL\.eval)\s*\(\s*""" +
                """(?:"[^"]*"\s*\+|[A-Za-z_][\w.]*\s*\+|request\.getParameter)""",
        ),
        Rule(
            id = "ATTACK_001",
            name = "Server-Side Template Injection (SSTI)",
            description = "A Jinja2 template is rendered from a runtime-built string instead of a template file",
            severity = Severity.HIGH, cwe = 1336, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """\brender_template_string\s*\(\s*(?:[fF]["']|["'][^"']*["']\s*(?:\+|%)|[A-Za-z_]\w*\s*[,)+]|request\.)|""" +
                """\b(?:jinja2\.)?Template\s*\(\s*(?:[fF]["']|["'][^"']*["']\s*(?:\+|%)|request\.)""",
        ),
        Rule(
            id = "LDAP_001",
            name = "LDAP Injection",
            description = "An LDAP search filter is built by concatenating or formatting a variable",
            severity = Severity.HIGH, cwe = 90, owasp = A03,
            languages = JVM + PYTHON,
            requiresInFile = """(?i)ldap|DirContext""",
            pattern = """["']\(\s*[\w-]+\s*=\s*["']\s*\+\s*[A-Za-z_]|\b[fF]["']\(\s*[\w-]+\s*=\s*\{""",
        ),
        Rule(
            id = "XPATH_001",
            name = "XPath Injection",
            description = "An XPath expression is built by concatenating or formatting a variable",
            severity = Severity.HIGH, cwe = 643, owasp = A03,
            languages = JVM + PYTHON,
            requiresInFile = """(?i)xpath""",
            pattern = """\.(?:evaluate|compile|selectNodes|selectSingleNode|xpath)\s*\(\s*(?:"[^"]*"\s*\+|'[^']*'\s*\+|[fF]["'][^"']*\{)""",
        ),
        Rule(
            id = "REFLECT_001",
            name = "Unsafe Reflection From Request Data",
            description = "Class.forName loads a class whose name comes from the HTTP request",
            severity = Severity.HIGH, cwe = 470, owasp = A03,
            languages = JVM,
            pattern = """\bClass\.forName\s*\([^;]*\brequest\.(?:getParameter|getHeader)\b""",
        ),
        Rule(
            id = "REGEX_001",
            name = "Regular Expression Denial of Service (ReDoS)",
            description = "A regular expression nests quantifiers, e.g. (a+)+, which can backtrack exponentially",
            severity = Severity.MEDIUM, cwe = 1333, owasp = A03,
            languages = JVM + JS + setOf(PYTHON, GO),
            pattern = """\b(?:Pattern\.compile|Regex|re\.(?:compile|match|search|fullmatch|findall|finditer|sub|split)|""" +
                """new\s+RegExp|regexp\.(?:MustCompile|Compile))\s*\(\s*[rR]?["'`][^"'`]*\((?:[^()"'`\\]|\\.)*[+*]\)[+*{]""",
        ),
    )
}
