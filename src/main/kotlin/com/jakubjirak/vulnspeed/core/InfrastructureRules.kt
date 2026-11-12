/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
// vulnspeed-ignore-file: rule names, descriptions and patterns quote the very code they detect.
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.core.RuleCatalog.A01
import com.jakubjirak.vulnspeed.core.RuleCatalog.A02
import com.jakubjirak.vulnspeed.core.RuleCatalog.A03
import com.jakubjirak.vulnspeed.core.RuleCatalog.A05
import com.jakubjirak.vulnspeed.core.RuleCatalog.A08
import com.jakubjirak.vulnspeed.core.RuleCatalog.JVM
import com.jakubjirak.vulnspeed.core.RuleCatalog.MANAGED
import com.jakubjirak.vulnspeed.core.RuleCatalog.NATIVE
import com.jakubjirak.vulnspeed.core.RuleCatalog.WEB_BACKENDS
import com.jakubjirak.vulnspeed.core.SourceLanguages.DOCKERFILE
import com.jakubjirak.vulnspeed.core.SourceLanguages.PROPERTIES
import com.jakubjirak.vulnspeed.core.SourceLanguages.PYTHON
import com.jakubjirak.vulnspeed.core.SourceLanguages.SWIFT
import com.jakubjirak.vulnspeed.core.SourceLanguages.YAML
import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity

/**
 * Configuration, container, cloud, file, network and native-code rules.
 * Positive / negative samples: `rule-samples.txt` (tests).
 */
internal object InfrastructureRules {
    val RULES: List<Rule> = listOf(
        Rule(
            id = "SPRING_001",
            name = "Spring Security Permits Every Request",
            description = "anyRequest().permitAll() turns off authorization for every endpoint",
            severity = Severity.HIGH, cwe = 862, owasp = A01,
            languages = JVM,
            pattern = """\banyRequest\(\)\s*\.permitAll\(\)|\bauthorize\(\s*anyRequest\s*,\s*permitAll\s*\)""",
        ),
        Rule(
            id = "SPRING_003",
            name = "All Actuator Endpoints Exposed",
            description = "Every Spring Boot actuator endpoint (env, heapdump, …) is exposed over HTTP",
            severity = Severity.MEDIUM, cwe = 200, owasp = A05,
            languages = setOf(YAML, PROPERTIES),
            requiresInFile = """exposure""",
            pattern = """\bmanagement\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?\*|^\s*include\s*:\s*["']?\*["']?\s*$""",
        ),
        Rule(
            id = "PYTHON_003",
            name = "Python Web App Debug Mode Enabled",
            description = "Flask debug mode / Django DEBUG=True exposes an interactive debugger and stack traces",
            severity = Severity.MEDIUM, cwe = 489, owasp = A05,
            languages = setOf(PYTHON),
            skipTestFiles = true,
            pattern = """\.run\s*\([^)]*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b""",
        ),
        Rule(
            id = "DOCKER_001",
            name = "Docker Base Image Uses :latest",
            description = "FROM …:latest makes builds unreproducible and can silently pull a vulnerable image",
            severity = Severity.LOW, cwe = 1357, owasp = A08,
            languages = setOf(DOCKERFILE),
            pattern = """^\s*FROM\s+(?:--platform=\S+\s+)?[^\s:@]+:latest\b""",
        ),
        Rule(
            id = "DOCKER_005",
            name = "Container Runs as Root",
            description = "USER root makes the container process run with root privileges",
            severity = Severity.MEDIUM, cwe = 250, owasp = A05,
            languages = setOf(DOCKERFILE),
            pattern = """^\s*USER\s+(?:root|0)(?::\S+)?\s*$""",
        ),
        Rule(
            id = "DOCKER_006",
            name = "Remote Script Piped to Shell",
            description = "RUN downloads a script and pipes it straight into a shell without verifying it",
            severity = Severity.MEDIUM, cwe = 494, owasp = A08,
            languages = setOf(DOCKERFILE),
            pattern = """^\s*RUN\b.*\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b""",
        ),
        Rule(
            id = "K8S_005",
            name = "Privileged Container",
            description = "privileged: true gives the container full access to the host",
            severity = Severity.HIGH, cwe = 250, owasp = A05,
            languages = setOf(YAML),
            pattern = """^\s*(?:-\s*)?privileged\s*:\s*true\b""",
        ),
        Rule(
            id = "K8S_006",
            name = "Privilege Escalation Allowed",
            description = "allowPrivilegeEscalation: true lets processes gain more privileges than their parent",
            severity = Severity.MEDIUM, cwe = 250, owasp = A05,
            languages = setOf(YAML),
            pattern = """^\s*(?:-\s*)?allowPrivilegeEscalation\s*:\s*true\b""",
        ),
        Rule(
            id = "K8S_007",
            name = "Host Namespace Shared With Container",
            description = "The container shares the host network / PID / IPC namespace",
            severity = Severity.MEDIUM, cwe = 668, owasp = A05,
            languages = setOf(YAML),
            pattern = """^\s*(?:-\s*)?(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b|^\s*(?:network_mode|pid)\s*:\s*["']?host\b""",
        ),
        Rule(
            id = "CONTAINER_001",
            name = "Docker Socket Mounted Into Container",
            description = "Mounting /var/run/docker.sock gives the container root-equivalent control of the host",
            severity = Severity.HIGH, cwe = 250, owasp = A05,
            languages = setOf(YAML),
            pattern = """/var/run/docker\.sock""",
        ),
        Rule(
            id = "ISTIO_001",
            name = "Istio mTLS in Permissive Mode",
            description = "PERMISSIVE mode accepts plaintext traffic alongside mTLS",
            severity = Severity.MEDIUM, cwe = 319, owasp = A02,
            languages = setOf(YAML),
            requiresInFile = """PeerAuthentication|MeshPolicy""",
            pattern = """^\s*mode\s*:\s*["']?PERMISSIVE\b""",
        ),
        Rule(
            id = "LAMBDA_003",
            name = "IAM Policy Allows All Actions",
            description = "An Allow statement grants Action \"*\" (or service:*)",
            severity = Severity.MEDIUM, cwe = 269, owasp = A01,
            languages = setOf(YAML),
            requiresInFile = """(?i)Effect["']?\s*:\s*["']?Allow""",
            pattern = """^\s*(?:-\s*)?["']?Action["']?\s*:\s*(?:\[\s*)?["']?(?:[a-z0-9-]+:)?\*["']?\s*\]?\s*$""",
        ),
        Rule(
            id = "CLOUD_002",
            name = "Public S3 Bucket or Object ACL",
            description = "An S3 bucket or object is made publicly readable or writable",
            severity = Severity.HIGH, cwe = 732, owasp = A01,
            languages = MANAGED + YAML,
            pattern = """\bCannedAccessControlList\.PublicRead(?:Write)?\b|\bObjectCannedACL\.(?:PUBLIC_READ|PUBLIC_READ_WRITE)\b|""" +
                """(?i:\bacl)["']?\s*[=:]\s*["']public-read(?:-write)?["']|\bAccessControl\s*:\s*PublicRead(?:Write)?\b""",
        ),
        Rule(
            id = "PATH_001",
            name = "Path Traversal",
            description = "A file path is built from request data without validation",
            severity = Severity.HIGH, cwe = 22, owasp = A01,
            languages = WEB_BACKENDS,
            pattern = """\bnew\s+File(?:InputStream|OutputStream|Reader|Writer)?\s*\([^;]*\brequest\.getParameter\b|""" +
                """\bPaths?\.(?:get|of)\s*\([^;]*\brequest\.getParameter\b|""" +
                """(?<![\w.])open\s*\([^)]*\brequest\.(?:args|form|values|GET|POST)\b|""" +
                """\bsend_file\s*\([^)]*\brequest\.(?:args|form|values)\b|\bos\.path\.join\s*\([^)]*\brequest\.(?:args|form|values)\b|""" +
                """\bres\.(?:sendFile|download)\s*\([^)]*\breq\.(?:query|params|body)\b|""" +
                """\b(?:fs|path)\.\w+\s*\([^)]*\breq\.(?:query|params|body)\b""",
        ),
        Rule(
            id = "PATH_002",
            name = "Zip Slip",
            description = "An archive entry name is used as a file path without checking it stays inside the target directory",
            severity = Severity.HIGH, cwe = 22, owasp = A01,
            languages = JVM,
            excludeIfFileContains = """getCanonicalPath|toRealPath|\.normalize\(\)\s*\.startsWith|startsWith\(\s*\w*(?:dest|target|base)""",
            pattern = """\bnew\s+File\s*\([^;]*\b\w*[eE]ntry\.(?:getName\(\)|name\b)|""" +
                """\.resolve\s*\(\s*\w*[eE]ntry\.(?:getName\(\)|name)\s*\)""",
        ),
        Rule(
            id = "PATH_003",
            name = "Tar Slip - tarfile.extractall Without Filter",
            description = "tarfile.extractall without a filter can write outside the target directory (CVE-2007-4559 class)",
            severity = Severity.MEDIUM, cwe = 22, owasp = A01,
            languages = setOf(PYTHON),
            requiresInFile = """\btarfile\b""",
            pattern = """\.extractall\s*\((?![^)]*\bfilter\s*=)""",
        ),
        Rule(
            id = "TEMP_001",
            name = "Insecure Temporary File",
            description = "tempfile.mktemp / os.tempnam return a name that another process can create first",
            severity = Severity.MEDIUM, cwe = 377, owasp = A01,
            languages = setOf(PYTHON),
            pattern = """\btempfile\.mktemp\s*\(|\bos\.(?:tempnam|tmpnam)\s*\(""",
        ),
        Rule(
            id = "NET_001",
            name = "Cleartext FTP / Telnet Client",
            description = "FTP and Telnet send credentials and data unencrypted",
            severity = Severity.MEDIUM, cwe = 319, owasp = A02,
            languages = JVM + PYTHON,
            pattern = """\bftplib\.FTP\s*\(|\bnew\s+FTPClient\s*\(|\btelnetlib\.Telnet\s*\(""",
        ),
        Rule(
            id = "NET_006",
            name = "Unencrypted WebSocket (ws://)",
            description = "A ws:// URL to a non-local host sends traffic unencrypted",
            severity = Severity.MEDIUM, cwe = 319, owasp = A02,
            languages = MANAGED,
            skipTestFiles = true,
            pattern = """["'`]ws://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\])""",
        ),
        Rule(
            id = "GRPC_001",
            name = "gRPC Without TLS",
            description = "A gRPC channel or server is created without transport security",
            severity = Severity.MEDIUM, cwe = 319, owasp = A02,
            languages = MANAGED,
            skipTestFiles = true,
            pattern = """\bgrpc\.WithInsecure\s*\(|\binsecure\.NewCredentials\s*\(|\.usePlaintext\s*\(|\bgrpc\.insecure_channel\s*\(|""" +
                """\bcredentials\.createInsecure\s*\(|\bServerCredentials\.createInsecure\s*\(|\badd_insecure_port\s*\(""",
        ),
        Rule(
            id = "MOBILE_002",
            name = "Credential in Unencrypted Mobile Storage",
            description = "A password / token is written to SharedPreferences or UserDefaults, which are stored unencrypted",
            severity = Severity.MEDIUM, cwe = 312, owasp = A02,
            languages = JVM + SWIFT,
            requiresInFile = """SharedPreferences|UserDefaults""",
            pattern = """\.put(?:String|StringSet)\s*\(\s*["'][^"']*(?i:passw|token|secret|api_?key)|""" +
                """\.set\([^)]*forKey:\s*"[^"]*(?i:passw|token|secret|api_?key)""",
        ),
        Rule(
            id = "BUFFER_001",
            name = "Unbounded C String Function",
            description = "strcpy / strcat / sprintf / gets write without a length bound and can overflow the buffer",
            severity = Severity.HIGH, cwe = 120, owasp = A03,
            languages = NATIVE,
            pattern = """(?<![\w.>])(?:std::)?(?:strcpy|strcat|sprintf|vsprintf|gets|wcscpy|wcscat)\s*\(""",
        ),
        Rule(
            id = "FORMAT_001",
            name = "Format String Vulnerability",
            description = "A printf-family function receives a variable as its format string",
            severity = Severity.HIGH, cwe = 134, owasp = A03,
            languages = NATIVE,
            pattern = """(?<![\w.>])(?:printf|vprintf)\s*\(\s*[A-Za-z_][\w.\->\[\]]*\s*\)|""" +
                """(?<![\w.>])(?:fprintf|sprintf|snprintf|dprintf|syslog)\s*\(\s*[^,"]+,\s*(?:[^,"]+,\s*)?[A-Za-z_][\w.\->\[\]]*\s*\)""",
        ),
    )
}
