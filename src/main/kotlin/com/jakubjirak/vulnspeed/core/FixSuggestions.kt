/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.FixSuggestion
import com.jakubjirak.vulnspeed.model.VulnerabilityType

/**
 * Remediation guidance and vulnerability category for each built-in rule family,
 * keyed by rule-id prefix (`SQL_004` → `SQL`). Unknown prefixes get no fix
 * suggestion and the [VulnerabilityType.INFORMATION_DISCLOSURE] category.
 */
object FixSuggestions {

    private const val OWASP_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"

    private val SECRET = FixSuggestion(
        title = "Remove Hardcoded Secret",
        description = "Revoke and rotate the leaked credential, then load it from the environment or a secret manager",
        code = "// Load from environment:\nString apiKey = System.getenv(\"API_KEY\");",
        references = listOf("${OWASP_CS}Secrets_Management_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/798.html"),
    )

    private val SQL = FixSuggestion(
        title = "Use Parameterized Queries",
        description = "Use prepared statements or parameterized queries to prevent SQL injection",
        code = "PreparedStatement stmt = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setInt(1, userId);",
        references = listOf("https://owasp.org/www-community/attacks/SQL_Injection", "${OWASP_CS}Query_Parameterization_Cheat_Sheet.html"),
    )

    private val NOSQL = FixSuggestion(
        title = "Avoid Query Operators Built From Input",
        description = "Never build \$where / JavaScript predicates from input; cast input to the expected type before querying",
        code = "const userId = parseInt(req.params.id, 10);\ndb.collection('users').find({ userId });",
        references = listOf("${OWASP_CS}Injection_Prevention_Cheat_Sheet.html"),
    )

    private val CMD = FixSuggestion(
        title = "Avoid Command Injection",
        description = "Pass arguments as a list without a shell, and validate input against an allow-list",
        code = "new ProcessBuilder(\"convert\", inputFile, outputFile).start();\n" +
            "# Python:\nsubprocess.run([\"convert\", src, dst], check=True)",
        references = listOf("https://owasp.org/www-community/attacks/Command_Injection"),
    )

    private val CODE = FixSuggestion(
        title = "Avoid Dynamic Code Execution",
        description = "Never evaluate user-controlled code, templates, expressions or class names; parse data with a safe parser",
        code = "# Python:\nvalue = ast.literal_eval(user_input)\n// JavaScript:\nconst value = Number.parseInt(req.body.amount, 10);",
        references = listOf("https://owasp.org/www-community/attacks/Code_Injection"),
    )

    private val QUERY_LANG = FixSuggestion(
        title = "Escape or Parameterize the Query",
        description = "Escape LDAP filter / XPath values or use parameterized APIs (XPathVariableResolver, LDAP filter encoders)",
        code = "String filter = \"(uid=\" + LdapEncoder.filterEncode(user) + \")\";",
        references = listOf("${OWASP_CS}LDAP_Injection_Prevention_Cheat_Sheet.html"),
    )

    private val REGEX = FixSuggestion(
        title = "Remove Nested Quantifiers",
        description = "Nested quantifiers such as (a+)+ backtrack exponentially; rewrite the pattern or use a linear-time engine",
        code = "// (\\\\w+)+@  →  \\\\w+@",
        references = listOf("https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"),
    )

    private val DESER = FixSuggestion(
        title = "Validate Before Deserialization",
        description = "Use data-only formats (JSON) or safe loaders; never deserialize untrusted native objects",
        code = "# Python:\ndata = yaml.safe_load(stream)\n// Java:\nMyClass obj = new ObjectMapper().readValue(json, MyClass.class);",
        references = listOf("${OWASP_CS}Deserialization_Cheat_Sheet.html"),
    )

    private val XXE = FixSuggestion(
        title = "Disable XXE in XML Parser",
        description = "Disable DOCTYPE declarations and external entity processing in XML parsers",
        code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
        references = listOf("${OWASP_CS}XML_External_Entity_Prevention_Cheat_Sheet.html"),
    )

    private val CRYPTO = FixSuggestion(
        title = "Use Strong Cryptographic Algorithms",
        description = "Use SHA-256+, AES-GCM, TLS 1.2+, SecureRandom / secrets, and keep certificate validation on",
        code = "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\nCipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
        references = listOf("${OWASP_CS}Cryptographic_Storage_Cheat_Sheet.html"),
    )

    private val JWT = FixSuggestion(
        title = "Verify JWT Signatures",
        description = "Always verify the signature and pin the accepted algorithms; never accept alg=none",
        code = "jwt.decode(token, key, algorithms=[\"HS256\"])",
        references = listOf("${OWASP_CS}JSON_Web_Token_for_Java_Cheat_Sheet.html"),
    )

    private val XSS = FixSuggestion(
        title = "Sanitize User Input",
        description = "Use textContent, framework auto-escaping, or sanitize with DOMPurify before inserting HTML",
        code = "element.textContent = userInput; // Safe\n// OR\nelement.innerHTML = DOMPurify.sanitize(userInput);",
        references = listOf("https://owasp.org/www-community/attacks/xss/"),
    )

    private val REDIRECT = FixSuggestion(
        title = "Validate Redirect Targets",
        description = "Redirect only to relative paths or to an allow-list of hosts",
        code = "if (!ALLOWED_REDIRECTS.contains(target)) target = \"/\";\nres.redirect(target);",
        references = listOf("${OWASP_CS}Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    )

    private val SSRF = FixSuggestion(
        title = "Validate URLs Against an Allow-List",
        description = "Never fetch a URL taken from the request; restrict scheme and host to trusted values",
        code = "URI uri = new URI(userUrl);\nif (!ALLOWED_HOSTS.contains(uri.getHost())) throw new SecurityException();",
        references = listOf("${OWASP_CS}Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
    )

    private val WEB_CONFIG = FixSuggestion(
        title = "Harden Web Security Configuration",
        description = "Keep CSRF protection on, restrict CORS origins, set Secure/HttpOnly cookies, keep tokens out of web storage",
        code = "@CrossOrigin(origins = \"https://trusted.example.com\")\ncookie.setSecure(true);\ncookie.setHttpOnly(true);",
        references = listOf(
            "${OWASP_CS}Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "${OWASP_CS}HTML5_Security_Cheat_Sheet.html",
        ),
    )

    private val APP_CONFIG = FixSuggestion(
        title = "Disable Debug and Restrict Exposure",
        description = "Turn debug mode off in production and expose only the endpoints you need",
        code = "management.endpoints.web.exposure.include=health,info\napp.run(debug=False)",
        references = listOf("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    )

    private val CONTAINER = FixSuggestion(
        title = "Harden the Container",
        description = "Pin base images, run as a non-root user, never bake secrets into images, avoid privileged mode",
        code = "FROM eclipse-temurin:21.0.5_11-jre\nUSER 10001\n# Kubernetes:\nsecurityContext:\n  privileged: false\n  " +
            "allowPrivilegeEscalation: false\n  runAsNonRoot: true",
        references = listOf(
            "${OWASP_CS}Docker_Security_Cheat_Sheet.html",
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ),
    )

    private val CLOUD = FixSuggestion(
        title = "Apply Least Privilege",
        description = "Grant only the actions a workload needs and keep storage private",
        code = "Action:\n  - s3:GetObject\nResource: arn:aws:s3:::my-bucket/*",
        references = listOf("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"),
    )

    private val PATH = FixSuggestion(
        title = "Validate and Canonicalize Paths",
        description = "Resolve the path against a base directory and reject anything that escapes it",
        code = "Path base = Paths.get(\"/safe/dir\").toRealPath();\nPath p = base.resolve(name).normalize();\n" +
            "if (!p.startsWith(base)) throw new SecurityException();",
        references = listOf("https://owasp.org/www-community/attacks/Path_Traversal"),
    )

    private val TRANSPORT = FixSuggestion(
        title = "Use Encrypted Transport",
        description = "Use SFTP/FTPS, wss:// and TLS-protected gRPC channels instead of cleartext protocols",
        code = "const ws = new WebSocket('wss://example.com/ws');\nManagedChannelBuilder.forAddress(host, 443).useTransportSecurity();",
        references = listOf("${OWASP_CS}Transport_Layer_Protection_Cheat_Sheet.html"),
    )

    private val MOBILE = FixSuggestion(
        title = "Use the Platform Keystore",
        description = "Store credentials in the Android Keystore / EncryptedSharedPreferences or the iOS Keychain",
        code = "val prefs = EncryptedSharedPreferences.create(context, \"secure\", masterKey, AES256_SIV, AES256_GCM)",
        references = listOf("https://mas.owasp.org/MASTG/"),
    )

    private val NATIVE = FixSuggestion(
        title = "Use Bounded String Functions",
        description = "Replace strcpy/strcat/sprintf/gets with bounded variants and never pass input as a format string",
        code = "snprintf(buf, sizeof buf, \"%s\", input);\nprintf(\"%s\", input);",
        references = listOf("https://cwe.mitre.org/data/definitions/120.html", "https://cwe.mitre.org/data/definitions/134.html"),
    )

    private val LOGGING = FixSuggestion(
        title = "Keep Secrets Out of Logs",
        description = "Never log passwords; log an identifier or a redacted value instead",
        code = "log.info(\"Login attempt for user {}\", username);",
        references = listOf("${OWASP_CS}Logging_Cheat_Sheet.html"),
    )

    private class Family(val prefixes: List<String>, val type: VulnerabilityType, val fix: FixSuggestion?)

    private val FAMILIES: List<Family> = listOf(
        Family(listOf("SECRET", "CONFIG", "PCI", "DOCKER_002"), VulnerabilityType.HARDCODED_CREDENTIALS, SECRET),
        Family(listOf("AUTH"), VulnerabilityType.AUTHENTICATION, SECRET),
        Family(listOf("SQL", "PRISMA", "SEQUELIZE", "TYPEORM"), VulnerabilityType.SQL_INJECTION, SQL),
        Family(listOf("NODE"), VulnerabilityType.SQL_INJECTION, NOSQL),
        Family(listOf("CMD", "JS_003"), VulnerabilityType.COMMAND_INJECTION, CMD),
        Family(listOf("PYTHON_002", "JS_004", "SCRIPT", "EXPR", "REFLECT", "ATTACK"), VulnerabilityType.CODE_INJECTION, CODE),
        Family(listOf("LDAP", "XPATH"), VulnerabilityType.SQL_INJECTION, QUERY_LANG),
        Family(listOf("REGEX"), VulnerabilityType.MISCONFIG, REGEX),
        Family(listOf("DESER", "SERIAL", "PYTHON_001"), VulnerabilityType.INSECURE_DESERIALIZATION, DESER),
        Family(listOf("XXE"), VulnerabilityType.XXE, XXE),
        Family(listOf("CRYPTO_BASIC"), VulnerabilityType.INSECURE_RANDOMNESS, CRYPTO),
        Family(listOf("CRYPTO"), VulnerabilityType.WEAK_CRYPTO, CRYPTO),
        Family(listOf("JWT", "OAUTH"), VulnerabilityType.AUTHENTICATION, JWT),
        Family(listOf("XSS", "ANGULAR"), VulnerabilityType.XSS, XSS),
        Family(listOf("REDIRECT"), VulnerabilityType.ACCESS_CONTROL, REDIRECT),
        Family(listOf("SSRF"), VulnerabilityType.MISCONFIG, SSRF),
        Family(listOf("CSRF"), VulnerabilityType.CSRF, WEB_CONFIG),
        Family(listOf("CORS", "COOKIE", "API", "GRAPHQL"), VulnerabilityType.MISCONFIG, WEB_CONFIG),
        Family(listOf("SPRING", "PYTHON_003"), VulnerabilityType.SECURITY_MISCONFIGURATION, APP_CONFIG),
        Family(listOf("DOCKER", "K8S", "CONTAINER", "ISTIO"), VulnerabilityType.IAC_VULNERABILITY, CONTAINER),
        Family(listOf("LAMBDA", "CLOUD"), VulnerabilityType.IAC_VULNERABILITY, CLOUD),
        Family(listOf("PATH", "TEMP"), VulnerabilityType.PATH_TRAVERSAL, PATH),
        Family(listOf("NET", "GRPC"), VulnerabilityType.SENSITIVE_DATA_EXPOSURE, TRANSPORT),
        Family(listOf("MOBILE"), VulnerabilityType.SENSITIVE_DATA_EXPOSURE, MOBILE),
        Family(listOf("BUFFER", "FORMAT"), VulnerabilityType.BUFFER_OVERFLOW, NATIVE),
        Family(listOf("GDPR"), VulnerabilityType.INSUFFICIENT_LOGGING, LOGGING),
    )

    private fun familyOf(ruleId: String): Family? {
        val id = ruleId.uppercase()
        return FAMILIES.firstOrNull { family -> family.prefixes.any { id.startsWith(it) } }
    }

    /** Fix suggestion for [ruleId], or null when the rule family is unknown. */
    fun forRule(ruleId: String): FixSuggestion? = familyOf(ruleId)?.fix

    /** Vulnerability category for [ruleId]. */
    fun typeOf(ruleId: String): VulnerabilityType = familyOf(ruleId)?.type ?: VulnerabilityType.INFORMATION_DISCLOSURE
}
