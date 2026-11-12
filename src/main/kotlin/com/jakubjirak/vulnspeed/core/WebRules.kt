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
import com.jakubjirak.vulnspeed.core.RuleCatalog.A07
import com.jakubjirak.vulnspeed.core.RuleCatalog.A10
import com.jakubjirak.vulnspeed.core.RuleCatalog.JS
import com.jakubjirak.vulnspeed.core.RuleCatalog.JVM
import com.jakubjirak.vulnspeed.core.RuleCatalog.MANAGED
import com.jakubjirak.vulnspeed.core.RuleCatalog.REQUEST_DATA
import com.jakubjirak.vulnspeed.core.RuleCatalog.WEB_BACKENDS
import com.jakubjirak.vulnspeed.core.SourceLanguages.PROPERTIES
import com.jakubjirak.vulnspeed.core.SourceLanguages.PYTHON
import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity

/**
 * Web application rules: XSS, redirects, SSRF, CORS, CSRF, cookies, tokens.
 * Positive / negative samples: `rule-samples.txt` (tests).
 */
internal object WebRules {
    val RULES: List<Rule> = listOf(
        Rule(
            id = "XSS_001",
            name = "Cross-Site Scripting via innerHTML",
            description = "Dynamic content is assigned to innerHTML / outerHTML without sanitization",
            severity = Severity.HIGH, cwe = 79, owasp = A03,
            languages = JS,
            skipTestFiles = true,
            pattern = """\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!["'][^"']*["']\s*[;,)]?\s*$)(?!`[^`$]*`\s*;?\s*$)""" +
                """(?!(?:DOMPurify|sanitize|purify)\w*[.(])[^\s;]""",
        ),
        Rule(
            id = "XSS_002",
            name = "DOM-based XSS - document.write",
            description = "document.write receives data from the URL, referrer, cookies or window.name",
            severity = Severity.HIGH, cwe = 79, owasp = A03,
            languages = JS,
            skipTestFiles = true,
            pattern = """\bdocument\.write(?:ln)?\s*\([^)]*\b(?:location|document\.URL|""" +
                """document\.referrer|document\.cookie|window\.name)\b""",
        ),
        Rule(
            id = "XSS_003",
            name = "React XSS - dangerouslySetInnerHTML",
            description = "dangerouslySetInnerHTML renders unsanitized HTML",
            severity = Severity.MEDIUM, cwe = 79, owasp = A03,
            languages = JS,
            skipTestFiles = true,
            pattern = """dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!\s*(?:DOMPurify|sanitize|purify)\w*[.(])[^}\s]""",
        ),
        Rule(
            id = "XSS_004",
            name = "XSS via Markup / mark_safe",
            description = "A string built from variables is marked as safe HTML, bypassing auto-escaping",
            severity = Severity.HIGH, cwe = 79, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """\b(?:Markup|mark_safe|SafeString)\s*\(\s*(?:[fF]["']|["'][^"']*["']\s*(?:%|\+|\.format\()|[^)]*\brequest\.)""",
        ),
        Rule(
            id = "XSS_005",
            name = "Reflected XSS in Servlet Response",
            description = "A request parameter is written to the servlet response without encoding",
            severity = Severity.HIGH, cwe = 79, owasp = A03,
            languages = JVM,
            pattern = """\.getWriter\(\)\s*\.(?:print|println|write|append)\s*\([^;]*\brequest\.getParameter\b""",
        ),
        Rule(
            id = "XSS_006",
            name = "Jinja2 Autoescape Disabled",
            description = "Templates are rendered with autoescape=False, so variables are inserted as raw HTML",
            severity = Severity.MEDIUM, cwe = 79, owasp = A03,
            languages = setOf(PYTHON),
            pattern = """\bautoescape\s*=\s*False\b""",
        ),
        Rule(
            id = "ANGULAR_001",
            name = "Angular Sanitizer Bypass",
            description = "bypassSecurityTrust* marks a dynamic value as trusted HTML / script / URL",
            severity = Severity.MEDIUM, cwe = 79, owasp = A03,
            languages = JS,
            pattern = """\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*(?!["'`])""",
        ),
        Rule(
            id = "REDIRECT_001",
            name = "Open Redirect",
            description = "The redirect target is taken directly from the request",
            severity = Severity.MEDIUM, cwe = 601, owasp = A01,
            languages = WEB_BACKENDS,
            pattern = """\b(?:res\.redirect|response\.sendRedirect|redirect|HttpResponseRedirect)\s*\(\s*(?:\d{3}\s*,\s*)?$REQUEST_DATA""",
        ),
        Rule(
            id = "SSRF_001",
            name = "Server-Side Request Forgery",
            description = "An outgoing HTTP request uses a URL taken directly from the incoming request",
            severity = Severity.HIGH, cwe = 918, owasp = A10,
            languages = WEB_BACKENDS,
            pattern = """\b(?:requests\.(?:get|post|put|delete|head|patch|request)|""" +
                """httpx\.(?:get|post|request)|urllib\.request\.urlopen|""" +
                """urlopen|axios(?:\.(?:get|post|put|delete|request))?|fetch|needle(?:\.(?:get|post))?|got|https?\.get|""" +
                """restTemplate\.(?:getForObject|getForEntity|exchange)|new\s+URL)\s*\(\s*$REQUEST_DATA""",
        ),
        Rule(
            id = "CORS_001",
            name = "Overly Permissive CORS",
            description = "CORS allows any origin (*)",
            severity = Severity.MEDIUM, cwe = 942, owasp = A05,
            languages = MANAGED,
            pattern = """["']Access-Control-Allow-Origin["']\s*[,:]\s*["']\*["']|""" +
                """@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?\{?\s*["']\*["']|""" +
                """\.allowedOrigins\(\s*["']\*["']|\bCORS_(?:ORIGIN_ALLOW_ALL|""" +
                """ALLOW_ALL_ORIGINS)\s*=\s*True|\bAllowAllOrigins\s*:\s*true|""" +
                """\borigins?\s*[=:]\s*["']\*["']""",
        ),
        Rule(
            id = "CSRF_001",
            name = "CSRF Protection Disabled",
            description = "Cross-site request forgery protection is switched off",
            severity = Severity.MEDIUM, cwe = 352, owasp = A01,
            languages = JVM + PYTHON,
            skipTestFiles = true,
            pattern = """\.csrf\(\)\s*\.disable\(\)|\bcsrf\s*\(\s*(?:\w+\s*->\s*\w+\.disable\(\)|AbstractHttpConfigurer::disable|""" +
                """CsrfConfigurer<\w+>::disable)\s*\)|\bcsrf\s*\{\s*disable\(\)\s*\}|""" +
                """\bWTF_CSRF_ENABLED\b["']?\]?\s*=\s*False|@csrf_exempt\b""",
        ),
        Rule(
            id = "COOKIE_001",
            name = "Insecure Cookie Flags",
            description = "A cookie is explicitly configured without the Secure or HttpOnly flag",
            severity = Severity.MEDIUM, cwe = 614, owasp = A05,
            languages = WEB_BACKENDS,
            requiresInFile = """(?i)cookie|session""",
            skipTestFiles = true,
            pattern = """\bset(?:Secure|HttpOnly)\s*\(\s*false\s*\)|\b(?:httpOnly|secure)\s*:\s*false\b|""" +
                """\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\b["']?\]?\s*=\s*False|\bset_cookie\([^)]*\b(?:secure|httponly)\s*=\s*False""",
        ),
        Rule(
            id = "API_010",
            name = "Sensitive Token in Web Storage",
            description = "A token or secret is stored in localStorage / sessionStorage, readable by any injected script",
            severity = Severity.MEDIUM, cwe = 922, owasp = A02,
            languages = JS,
            pattern = """\b(?:localStorage|sessionStorage)\.setItem\(\s*["'`][^"'`]*(?i:token|jwt|secret|passw|api_?key|credential)""",
        ),
        Rule(
            id = "OAUTH_003",
            name = "OAuth Implicit Flow",
            description = "response_type=token (implicit flow) returns tokens in the URL; use authorization code + PKCE",
            severity = Severity.MEDIUM, cwe = 598, owasp = A07,
            languages = SourceLanguages.CODE,
            pattern = """response_type=token\b|\bresponseType\s*:\s*["']token["']|\bresponse_type\s*[=:]\s*["']token["']""",
        ),
        Rule(
            id = "GRAPHQL_002",
            name = "GraphQL Introspection Enabled",
            description = "Introspection is explicitly enabled, exposing the full schema to clients",
            severity = Severity.LOW, cwe = 200, owasp = A05,
            languages = JS + PROPERTIES,
            requiresInFile = """(?i)graphql|apollo""",
            pattern = """\bintrospection\s*:\s*true\b|\bintrospection\.enabled\s*=\s*true\b""",
        ),
    )
}
