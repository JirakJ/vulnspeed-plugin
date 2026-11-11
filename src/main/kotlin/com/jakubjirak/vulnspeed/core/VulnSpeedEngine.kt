package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.*
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiManager
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.util.Computable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ForkJoinPool
import java.util.UUID
import kotlin.math.min

@Service
class VulnSpeedEngine : AutoCloseable {
    private val scanResults = ConcurrentHashMap<String, ScanResult>()
    private val executorService = ForkJoinPool.commonPool()
    private val patternRules = loadDefaultRules()
    
    fun scanFile(file: VirtualFile, project: Project): ScanResult {
        val scanId = UUID.randomUUID().toString()
        val startTime = System.currentTimeMillis()
        
        val content = ApplicationManager.getApplication().runReadAction(Computable {
            FileDocumentManager.getInstance().getDocument(file)?.text
        }) ?: run {
            return ScanResult(
                scanId = scanId,
                timestamp = System.currentTimeMillis(),
                durationMs = System.currentTimeMillis() - startTime,
                vulnerabilities = emptyList(),
                stats = ScanStats(0, 0, 0, 0, 0, 0, 0)
            )
        }
        
        val linesOfCode = content.lines().size.toLong()
        
        val vulnerabilities = mutableListOf<Vulnerability>()
        val language = detectLanguage(file)
        
        // Run pattern matching
        for (rule in patternRules.filter { it.enabled }) {
            vulnerabilities.addAll(
                scanWithRule(content, file.path, rule, language)
            )
        }
        
        // Sort by severity and line number
        vulnerabilities.sortWith(compareBy({ it.severity.ordinal }, { it.line }))
        
        val endTime = System.currentTimeMillis()
        val result = ScanResult(
            scanId = scanId,
            timestamp = endTime,
            durationMs = endTime - startTime,
            vulnerabilities = vulnerabilities,
            stats = ScanStats(
                totalVulns = vulnerabilities.size,
                criticalCount = vulnerabilities.count { it.severity == Severity.CRITICAL },
                highCount = vulnerabilities.count { it.severity == Severity.HIGH },
                mediumCount = vulnerabilities.count { it.severity == Severity.MEDIUM },
                lowCount = vulnerabilities.count { it.severity == Severity.LOW },
                filesScanned = 1,
                linesOfCode = linesOfCode
            )
        )
        
        scanResults[scanId] = result
        return result
    }
    
    fun scanProject(project: Project): ScanResult {
        val scanId = UUID.randomUUID().toString()
        val startTime = System.currentTimeMillis()
        val allVulnerabilities = mutableListOf<Vulnerability>()
        var totalLoc = 0L
        var filesScanned = 0
        
        // Collect all source files
        val files = collectProjectFiles(project).take(1000) // Limit to 1000 files per scan
        
        // Parallel scanning
        files.parallelStream().forEach { file ->
            try {
                val result = scanFile(file, project)
                synchronized(allVulnerabilities) {
                    allVulnerabilities.addAll(result.vulnerabilities)
                    totalLoc += result.stats.linesOfCode
                    filesScanned++
                }
            } catch (e: Exception) {
                LOG.warn("VulnSpeed failed to scan ${file.path}: ${e.message}")
            }
        }
        
        allVulnerabilities.sortWith(compareBy({ it.severity.ordinal }, { it.line }))
        
        val endTime = System.currentTimeMillis()
        val result = ScanResult(
            scanId = scanId,
            timestamp = endTime,
            durationMs = endTime - startTime,
            vulnerabilities = allVulnerabilities,
            stats = ScanStats(
                totalVulns = allVulnerabilities.size,
                criticalCount = allVulnerabilities.count { it.severity == Severity.CRITICAL },
                highCount = allVulnerabilities.count { it.severity == Severity.HIGH },
                mediumCount = allVulnerabilities.count { it.severity == Severity.MEDIUM },
                lowCount = allVulnerabilities.count { it.severity == Severity.LOW },
                filesScanned = filesScanned,
                linesOfCode = totalLoc
            ),
        )
        
        scanResults[scanId] = result
        return result
    }
    
    fun getScanResult(scanId: String): ScanResult? = scanResults[scanId]
    
    private fun scanWithRule(content: String, filePath: String, rule: Rule, language: String): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()

        try {
            val regex = Regex(rule.pattern, RegexOption.MULTILINE)
            val lines = content.lines()

            if (SuppressionDirectives.isFileSuppressed(lines)) return emptyList()

            lines.forEachIndexed { lineNum, line ->
                regex.findAll(line).forEach { match ->
                    if (SuppressionDirectives.isSuppressed(lines, lineNum, rule.id)) return@forEach
                    vulns.add(
                        Vulnerability(
                            id = UUID.randomUUID().toString(),
                            ruleId = rule.id,
                            ruleName = rule.name,
                            type = parseVulnType(rule.id),
                            severity = rule.severity,
                            cwe = rule.cwe,
                            filePath = filePath,
                            line = lineNum + 1,
                            column = match.range.first + 1,
                            message = rule.description,
                            codeSnippet = line.substring(
                                maxOf(0, match.range.first - 10),
                                minOf(line.length, match.range.last + 11)
                            ),
                            confidence = 0.85f,
                            owasp = rule.owasp,
                            fixSuggestion = generateFixSuggestion(rule),
                            tags = listOf(language, rule.id)
                        )
                    )
                }
            }
        } catch (e: Exception) {
            LOG.warn("VulnSpeed rule ${rule.id} failed: ${e.message}")
        }

        return vulns
    }
    
    private fun generateFixSuggestion(rule: Rule): FixSuggestion? {
        return when {
            rule.id.startsWith("SECRET") -> FixSuggestion(
                title = "Remove Hardcoded Secret",
                description = "Revoke and rotate the leaked credential, then load it from the environment or a secret manager",
                code = "// Load from environment:\nString apiKey = System.getenv(\"API_KEY\");\n\n// Or from a secret manager (AWS " +
                    "example):\nGetSecretValueRequest request = new GetSecretValueRequest().withSecretId(\"my-secret\");",
                references = listOf(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/798.html"
                )
            )
            rule.id.startsWith("SQL") -> FixSuggestion(
                title = "Use Parameterized Queries",
                description = "Use prepared statements or parameterized queries to prevent SQL injection",
                code = "PreparedStatement stmt = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setInt(1, " +
                    "userId);",
                references = listOf("https://owasp.org/www-community/attacks/SQL_Injection")
            )
            rule.id.startsWith("XSS") -> FixSuggestion(
                title = "Sanitize User Input",
                description = "Use textContent or sanitize with DOMPurify library",
                code = "element.textContent = userInput; // Safe\n// OR\nelement.innerHTML = DOMPurify.sanitize(userInput);",
                references = listOf("https://owasp.org/www-community/attacks/xss/")
            )
            rule.id.startsWith("CRYPTO") -> FixSuggestion(
                title = "Use Strong Cryptographic Algorithms",
                description = "Use SHA-256, SHA-384, SHA-512 or AES-GCM for encryption",
                code = "// For hashing:\nMessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n\n// For encryption:\nCipher " +
                    "cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html")
            )
            rule.id.startsWith("CMD") -> FixSuggestion(
                title = "Avoid Command Injection",
                description = "Use safe APIs, whitelist input, or use parameterized commands",
                code = "// Use ProcessBuilder with separate arguments:\nProcessBuilder pb = new ProcessBuilder(\"command\", \"arg1\", " +
                    "sanitizedInput);\n\n// Or validate against whitelist:\nif (!ALLOWED_COMMANDS.contains(command)) throw new " +
                    "SecurityException();",
                references = listOf("https://owasp.org/www-community/attacks/Command_Injection")
            )
            rule.id.startsWith("PATH") -> FixSuggestion(
                title = "Validate and Canonicalize Paths",
                description = "Use Path.normalize() and validate against base directory",
                code = "Path basePath = Paths.get(\"/safe/directory\").toRealPath();\nPath userPath = " +
                    "basePath.resolve(userInput).normalize();\nif (!userPath.startsWith(basePath)) {\n    throw new " +
                    "SecurityException(\"Path traversal detected\");\n}",
                references = listOf("https://owasp.org/www-community/attacks/Path_Traversal")
            )
            rule.id.startsWith("DESER") -> FixSuggestion(
                title = "Validate Before Deserialization",
                description = "Use safe serialization formats (JSON) or implement ObjectInputFilter",
                code = "// Use JSON instead:\nGson gson = new Gson();\nMyClass obj = gson.fromJson(jsonString, MyClass.class);\n\n// Or " +
                    "use ObjectInputFilter (Java 9+):\nObjectInputFilter filter = " +
                    "ObjectInputFilter.Config.createFilter(\"com.myapp.**;!*\");",
                references = listOf("https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data")
            )
            rule.id.startsWith("XXE") -> FixSuggestion(
                title = "Disable XXE in XML Parser",
                description = "Disable external entity processing in XML parsers",
                code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
                    "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
                    "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
                    "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html")
            )
            rule.id.startsWith("SSRF") -> FixSuggestion(
                title = "Validate URLs Against Whitelist",
                description = "Validate and restrict URLs to trusted domains only",
                code = "URI uri = new URI(userUrl);\nString host = uri.getHost();\nif (!ALLOWED_HOSTS.contains(host)) {\n    throw new " +
                    "SecurityException(\"Untrusted host: \" + host);\n}",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.ht" +
                    "ml")
            )
            rule.id.startsWith("CSRF") -> FixSuggestion(
                title = "Enable CSRF Protection",
                description = "Use CSRF tokens for state-changing operations",
                code = "// Spring Security:\n@EnableWebSecurity\npublic class SecurityConfig {\n    @Bean\n    public " +
                    "SecurityFilterChain filterChain(HttpSecurity http) {\n        " +
                    "http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());\n    }\n}",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html")
            )
            rule.id.startsWith("JWT") -> FixSuggestion(
                title = "Use Strong JWT Signature",
                description = "Use HS256, RS256, or ES256 with strong keys",
                code = "// Use strong signing algorithm:\nString token = Jwts.builder()\n    .setSubject(username)\n    " +
                    ".signWith(SignatureAlgorithm.HS256, secretKey) // Use strong key\n    .compact();",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html")
            )
            rule.id.startsWith("COOKIE") -> FixSuggestion(
                title = "Set Secure Cookie Flags",
                description = "Always set Secure and HttpOnly flags on sensitive cookies",
                code = "Cookie cookie = new Cookie(\"session\", sessionId);\ncookie.setSecure(true); // HTTPS only\n" +
                    "cookie.setHttpOnly(true); // No JavaScript access\ncookie.setSameSite(\"Strict\"); // CSRF protection",
                references = listOf("https://owasp.org/www-community/controls/SecureCookieAttribute")
            )
            rule.id.startsWith("CORS") -> FixSuggestion(
                title = "Restrict CORS Origins",
                description = "Use specific allowed origins instead of wildcard",
                code = "@CrossOrigin(origins = \"https://trusted-domain.com\")\n// OR\n" +
                    "response.setHeader(\"Access-Control-Allow-Origin\", \"https://trusted-domain.com\");",
                references = listOf("https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")
            )
            rule.id.startsWith("REFLECT") || rule.id.startsWith("SCRIPT") || rule.id.startsWith("EXPR") -> FixSuggestion(
                title = "Avoid Dynamic Code Execution",
                description = "Never execute user-controlled code. Use whitelist approach.",
                code = "// Use whitelist:\nif (!ALLOWED_CLASSES.contains(className)) {\n    throw new SecurityException();\n}\n// Or " +
                    "avoid reflection entirely and use dependency injection",
                references = listOf("https://owasp.org/www-community/attacks/Code_Injection")
            )
            rule.id.startsWith("AUTH") -> FixSuggestion(
                title = "Implement Strong Authentication",
                description = "Use industry-standard authentication with proper password hashing",
                code = "// BCrypt for password hashing:\nBCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\nString " +
                    "hashedPassword = encoder.encode(plainPassword);\n\n// Spring Security annotation:\n" +
                    "@PreAuthorize(\"hasRole('ADMIN')\")",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html")
            )
            rule.id.startsWith("API") -> FixSuggestion(
                title = "Secure API Design",
                description = "Use POST for sensitive data, validate content types, sanitize errors",
                code = "@PostMapping(value = \"/api/endpoint\", consumes = \"application/json\")\npublic Response handle(@Valid " +
                    "@RequestBody Request req) {\n    try {\n        // business logic\n    } catch (Exception e) {\n        " +
                    "log.error(\"Error\", e);\n        return Response.error(\"An error occurred\"); // Generic message\n    }\n}",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html")
            )
            rule.id.startsWith("DB") -> FixSuggestion(
                title = "Secure Database Operations",
                description = "Use parameterized queries, connection pooling, and proper ORM configuration",
                code = "// Use DataSource with pooling:\n@Bean\npublic DataSource dataSource() {\n    HikariConfig config = new " +
                    "HikariConfig();\n    config.setMaximumPoolSize(10);\n    return new HikariDataSource(config);\n}\n\n// For " +
                    "dynamic tables, use whitelist:\nif (!ALLOWED_TABLES.contains(tableName)) throw new SecurityException();",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html")
            )
            rule.id.startsWith("CLOUD") -> FixSuggestion(
                title = "Secure Cloud Configuration",
                description = "Never hardcode credentials. Use environment variables or secret managers.",
                code = "// Use AWS SDK with IAM roles or environment:\nAWSCredentialsProvider provider = " +
                    "DefaultAWSCredentialsProviderChain.getInstance();\n\n// Or use AWS Secrets Manager:\nGetSecretValueRequest " +
                    "request = new GetSecretValueRequest()\n    .withSecretId(\"my-secret\");",
                references = listOf("https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/credentials.html")
            )
            rule.id.startsWith("RESOURCE") || rule.id.startsWith("BUFFER") -> FixSuggestion(
                title = "Proper Resource Management",
                description = "Always close resources using try-with-resources (Java 7+)",
                code = "// Automatically closes resources:\ntry (FileInputStream fis = new FileInputStream(file);\n     BufferedReader " +
                    "br = new BufferedReader(new InputStreamReader(fis))) {\n    // use resources\n} // auto-closed here",
                references = listOf("https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html")
            )
            rule.id.startsWith("INPUT") || rule.id.startsWith("SIZE") -> FixSuggestion(
                title = "Validate All Input",
                description = "Use Bean Validation annotations and size limits",
                code = "public Response handle(\n    @Valid @Size(min=1, max=100) @Pattern(regexp=\"^[a-zA-Z0-9]+$\") String input,\n   " +
                    " @RequestParam @Max(10485760) MultipartFile file) {\n    // validated input\n}",
                references = listOf("https://beanvalidation.org/")
            )
            rule.id.startsWith("RECORD") || rule.id.startsWith("KOTLIN") -> FixSuggestion(
                title = "Immutable Data Structures",
                description = "Use immutable collections in records and data classes",
                code = "// Java Record with immutable list:\npublic record User(String name, List<String> roles) {\n    public User {\n " +
                    "       roles = List.copyOf(roles); // Defensive copy\n    }\n}\n\n// Kotlin data class:\ndata class User(val " +
                    "name: String, val roles: List<String>) // Use List, not MutableList",
                references = listOf("https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/Record.html")
            )
            rule.id.startsWith("VIRTUAL") -> FixSuggestion(
                title = "Virtual Thread Best Practices",
                description = "Avoid synchronized blocks in virtual threads. Use ReentrantLock instead.",
                code = "// Instead of synchronized:\nprivate final ReentrantLock lock = new ReentrantLock();\n\n" +
                    "Thread.ofVirtual().start(() -> {\n    lock.lock();\n    try {\n        // critical section\n    } finally {\n   " +
                    "     lock.unlock();\n    }\n});",
                references = listOf("https://openjdk.org/jeps/444")
            )
            rule.id.startsWith("SPRING") -> FixSuggestion(
                title = "Secure Spring Configuration",
                description = "Use Spring Security best practices with proper authentication",
                code = "@Configuration\n@EnableWebSecurity\npublic class SecurityConfig {\n    @Bean\n    public SecurityFilterChain " +
                    "filterChain(HttpSecurity http) {\n        return http\n            .authorizeRequests(auth -> auth\n            " +
                    "    .anyRequest().authenticated())\n            " +
                    ".csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())\n            .build();\n    }\n}",
                references = listOf("https://spring.io/guides/topicals/spring-security-architecture")
            )
            rule.id.startsWith("REST") || rule.id.startsWith("GRAPHQL") || rule.id.startsWith("WEBSOCKET") -> FixSuggestion(
                title = "Secure API Endpoints",
                description = "Implement pagination, versioning, authentication, and rate limiting",
                code = "@GetMapping(\"/api/v1/users\")\n@PreAuthorize(\"hasRole('USER')\")\n@RateLimit(value = 100, duration = 1, unit " +
                    "= TimeUnit.MINUTES)\npublic Page<User> getUsers(@PageableDefault(size = 20) Pageable page) {\n    return " +
                    "userService.findAll(page);\n}",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html")
            )
            rule.id.startsWith("MICRO") || rule.id.startsWith("KAFKA") || rule.id.startsWith("REDIS") ||
                rule.id.startsWith("RABBIT") -> FixSuggestion(
                title = "Secure Microservices Communication",
                description = "Use mutual TLS, circuit breakers, and proper authentication",
                code = "@FeignClient(name = \"user-service\", configuration = SecureClientConfig.class)\npublic interface UserClient {\n" +
                    "    @CircuitBreaker(name = \"userService\", fallbackMethod = \"getUserFallback\")\n    User " +
                    "getUser(@PathVariable Long id);\n}\n\n// Enable SSL/TLS:\nspring.kafka.security.protocol=SASL_SSL\n" +
                    "spring.kafka.properties.sasl.mechanism=PLAIN",
                references = listOf("https://microservices.io/patterns/security/access-token.html")
            )
            rule.id.startsWith("MOBILE") || rule.id.startsWith("WEB") -> FixSuggestion(
                title = "Secure Frontend & Mobile Apps",
                description = "Implement CSP, SRI, certificate pinning, and secure storage",
                code = "// Content Security Policy:\n<meta http-equiv=\"Content-Security-Policy\" \n      content=\"default-src 'self'; " +
                    "script-src 'self' https://trusted.cdn.com\">\n\n// Subresource Integrity:\n<script " +
                    "src=\"https://cdn.example.com/lib.js\" \n        " +
                    "integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n        " +
                    "crossorigin=\"anonymous\"></script>\n\n// iOS Certificate Pinning:\nlet serverTrustPolicy = " +
                    "ServerTrustPolicy.pinCertificates(\n    certificates: ServerTrustPolicy.certificates(),\n    " +
                    "validateCertificateChain: true,\n    validateHost: true\n)",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html")
            )
            rule.id.startsWith("CICD") || rule.id.startsWith("K8S") -> FixSuggestion(
                title = "Secure CI/CD & Kubernetes",
                description = "Use secrets management, security contexts, and minimal privileges",
                code = "# Kubernetes Security Context:\napiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    runAsNonRoot: true\n  " +
                    "  runAsUser: 1000\n  containers:\n  - name: app\n    securityContext:\n      allowPrivilegeEscalation: false\n  " +
                    "    readOnlyRootFilesystem: true\n\n# Use secrets properly:\nkind: Secret\napiVersion: v1\nmetadata:\n  name: " +
                    "db-credentials\ntype: Opaque\nstringData:\n  password: \${DB_PASSWORD}  # From environment/vault",
                references = listOf("https://kubernetes.io/docs/concepts/security/pod-security-standards/")
            )
            rule.id.startsWith("PYTHON") -> FixSuggestion(
                title = "Secure Python Code",
                description = "Avoid pickle, eval, use parameterized queries and environment variables",
                code = "# Instead of pickle:\nimport json\ndata = json.loads(user_input)\n\n# Instead of eval:\nimport ast\ndata = " +
                    "ast.literal_eval(user_input)  # Safe for literals only\n\n# SQLAlchemy parameterized:\nfrom sqlalchemy import " +
                    "text\nstmt = text(\"SELECT * FROM users WHERE id = :id\")\nresult = session.execute(stmt, {\"id\": user_id})\n\n" +
                    "# Environment variables:\nimport os\nSECRET_KEY = os.environ.get('SECRET_KEY')",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html")
            )
            rule.id.startsWith("JS") || rule.id.startsWith("TS") || rule.id.startsWith("NODE") -> FixSuggestion(
                title = "Secure JavaScript/TypeScript",
                description = "Use crypto.randomBytes, avoid prototype pollution, sanitize inputs",
                code = "// Secure random:\nconst crypto = require('crypto');\nconst token = crypto.randomBytes(32).toString('hex');\n\n" +
                    "// Avoid prototype pollution:\nconst obj = Object.create(null);  // No prototype\n// OR validate keys:\nif " +
                    "(Object.hasOwn(obj, key) && key !== '__proto__') {\n    obj[key] = value;\n}\n\n// Express with Helmet:\nconst " +
                    "helmet = require('helmet');\napp.use(helmet());\n\n// MongoDB safe query:\nconst query = { _id: " +
                    "ObjectId(req.params.id) };  // Typed",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html")
            )
            rule.id.startsWith("ATTACK") -> FixSuggestion(
                title = "Prevent Advanced Attack Vectors",
                description = "Validate all inputs, limit resource consumption, check file types",
                code = "// SSTI Prevention:\nString template = \"static/template.ftl\";  // Use constant templates\n\n// File Upload " +
                    "Security:\nMultipartFile file = ...\nif (!ALLOWED_TYPES.contains(file.getContentType())) {\n    throw new " +
                    "SecurityException();\n}\nif (file.getSize() > MAX_FILE_SIZE) {\n    throw new SecurityException();\n}\n\n// XML " +
                    "Entity Expansion:\nDocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
                    "dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\ndbf.setExpandEntityReferences(false);",
                references = listOf("https://owasp.org/www-community/attacks/")
            )
            rule.id.startsWith("GDPR") || rule.id.startsWith("PCI") || rule.id.startsWith("HIPAA") ||
                rule.id.startsWith("PRIVACY") -> FixSuggestion(
                title = "Compliance & Data Privacy",
                description = "Encrypt sensitive data, implement audit logs, mask PII in logs",
                code = "// Encrypt sensitive data:\n@Convert(converter = EncryptedStringConverter.class)\nprivate String " +
                    "socialSecurityNumber;\n\n// Audit logging:\n@PostUpdate\nprivate void auditUpdate() {\n    auditLog.log(\"User " +
                    "updated\", userId, LocalDateTime.now());\n}\n\n// Mask PII in logs:\nlog.info(\"Processing user: {}\" + " +
                    "maskEmail(user.getEmail()));\n\n// Data retention:\n@PrePersist\nprivate void setExpiry() {\n    this.expiresAt " +
                    "= LocalDateTime.now().plusDays(RETENTION_DAYS);\n}",
                references = listOf("https://gdpr.eu/", "https://www.pcisecuritystandards.org/")
            )
            rule.id.startsWith("QUALITY") -> FixSuggestion(
                title = "Code Quality & Security Best Practices",
                description = "Use proper logging, avoid magic numbers, handle exceptions",
                code = "// Proper logging:\nprivate static final Logger log = LoggerFactory.getLogger(MyClass.class);\n" +
                    "log.error(\"Error processing request\", exception);\n\n// Constants:\nprivate static final int " +
                    "PBKDF2_ITERATIONS = 100000;\nprivate static final int AES_KEY_SIZE = 256;\n\n// Exception handling:\ntry {\n    " +
                    "// risky operation\n} catch (SpecificException e) {\n    log.error(\"Failed\", e);\n    throw new " +
                    "BusinessException(\"Operation failed\", e);\n}",
                references = listOf("https://rules.sonarsource.com/java/")
            )
            rule.id.startsWith("CRYPTO_0") || rule.id.startsWith("ENCODING") || rule.id.startsWith("HASH") -> FixSuggestion(
                title = "Strong Cryptography",
                description = "Use proper key sizes, unique IVs, salted password hashing",
                code = "// RSA Key Generation (2048+ bits):\nKeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n" +
                    "kpg.initialize(2048);\n\n// AES with random IV:\nSecureRandom sr = new SecureRandom();\nbyte[] iv = new " +
                    "byte[16];\nsr.nextBytes(iv);\nIvParameterSpec ivSpec = new IvParameterSpec(iv);\n\n// PBKDF2 with salt:\n" +
                    "SecureRandom random = new SecureRandom();\nbyte[] salt = new byte[16];\nrandom.nextBytes(salt);\nPBEKeySpec " +
                    "spec = new PBEKeySpec(password, salt, 100000, 256);\nSecretKeyFactory factory = " +
                    "SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");\nbyte[] hash = " +
                    "factory.generateSecret(spec).getEncoded();",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html")
            )
            rule.id.startsWith("NET") -> FixSuggestion(
                title = "Secure Network Communication",
                description = "Use encrypted protocols, verify hostnames, set timeouts",
                code = "// SFTP instead of FTP:\nJSch jsch = new JSch();\nSession session = jsch.getSession(user, host, 22);\n" +
                    "session.setConfig(\"StrictHostKeyChecking\", \"yes\");\n\n// SMTP with TLS:\n" +
                    "props.put(\"mail.smtp.starttls.enable\", \"true\");\nprops.put(\"mail.smtp.ssl.enable\", \"true\");\n\n// " +
                    "Socket timeout:\nSocket socket = new Socket();\nsocket.connect(new InetSocketAddress(host, port), 5000);\n" +
                    "socket.setSoTimeout(10000);\n\n// WebSocket secure:\nURI uri = new URI(\"wss://secure.example.com/ws\");",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html")
            )
            rule.id.startsWith("AUTHZ") || rule.id.startsWith("BUSINESS") -> FixSuggestion(
                title = "Authorization & Business Logic Security",
                description = "Implement row-level security, validate ownership, atomic operations",
                code = "// Row-level security:\n@Where(clause = \"tenant_id = :currentTenantId\")\n@Entity\npublic class Document {\n   " +
                    " // ...\n}\n\n// Ownership validation:\npublic Document getDocument(Long id) {\n    Document doc = " +
                    "repository.findById(id).orElseThrow();\n    if (!doc.getOwnerId().equals(currentUser.getId())) {\n        throw " +
                    "new AccessDeniedException();\n    }\n    return doc;\n}\n\n// Atomic financial transaction:\n" +
                    "@Transactional(isolation = Isolation.SERIALIZABLE)\npublic void transfer(Account from, Account to, BigDecimal " +
                    "amount) {\n    from.setBalance(from.getBalance().subtract(amount));\n    " +
                    "to.setBalance(to.getBalance().add(amount));\n}",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html")
            )
            rule.id.startsWith("REACT") || rule.id.startsWith("ANGULAR") || rule.id.startsWith("VUE") ||
                rule.id.startsWith("NEXTJS") -> FixSuggestion(
                title = "Modern Framework Security",
                description = "Proper state management, input validation, sanitization",
                code = "// React safe state:\nthis.setState({ value: newValue });\n\n// React with DOMPurify:\nimport DOMPurify from " +
                    "'dompurify';\nconst clean = DOMPurify.sanitize(userInput);\n<div dangerouslySetInnerHTML={{ __html: clean }} " +
                    "/>\n\n// Angular sanitizer:\nconstructor(private sanitizer: DomSanitizer) {}\nthis.safeHtml = " +
                    "this.sanitizer.sanitize(SecurityContext.HTML, userHtml);\n\n// Next.js API auth:\nexport default async function " +
                    "handler(req, res) {\n  const session = await getSession({ req });\n  if (!session) return " +
                    "res.status(401).json({ error: 'Unauthorized' });\n  // ...\n}",
                references = listOf("https://react.dev/learn/keeping-components-pure")
            )
            rule.id.startsWith("LAMBDA") || rule.id.startsWith("SERVERLESS") || rule.id.startsWith("SAM") ||
                rule.id.startsWith("APIGATEWAY") -> FixSuggestion(
                title = "Serverless Security Best Practices",
                description = "Use secrets manager, proper IAM, VPC configuration",
                code = "// Lambda with Secrets Manager:\nconst AWS = require('aws-sdk');\nconst secretsManager = new " +
                    "AWS.SecretsManager();\nlet cachedSecret;\n\nexports.handler = async (event) => {\n  if (!cachedSecret) {\n    " +
                    "const data = await secretsManager.getSecretValue({ SecretId: 'mySecret' }).promise();\n    cachedSecret = " +
                    "JSON.parse(data.SecretString);\n  }\n  // Use cachedSecret\n};\n\n// Least privilege IAM:\nPolicies:\n  - " +
                    "PolicyName: MinimalAccess\n    PolicyDocument:\n      Statement:\n        - Effect: Allow\n          Action: " +
                    "'dynamodb:GetItem'\n          Resource: 'arn:aws:dynamodb:region:account:table/MyTable'",
                references = listOf("https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html")
            )
            rule.id.startsWith("DOCKER") || rule.id.startsWith("K8S") || rule.id.startsWith("HELM") ||
                rule.id.startsWith("ISTIO") -> FixSuggestion(
                title = "Container & Kubernetes Security",
                description = "Non-root containers, resource limits, network policies",
                code = "# Dockerfile best practices:\nFROM alpine:3.18\nRUN addgroup -g 1001 appuser && adduser -D -u 1001 -G appuser " +
                    "appuser\nUSER appuser\nCOPY --chown=appuser:appuser . /app\nHEALTHCHECK --interval=30s CMD wget -qO- " +
                    "http://localhost:8080/health\n\n# Kubernetes security:\napiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n  " +
                    "  runAsNonRoot: true\n    runAsUser: 1000\n  containers:\n  - name: app\n    resources:\n      limits:\n        " +
                    "memory: \"256Mi\"\n        cpu: \"500m\"",
                references = listOf("https://kubernetes.io/docs/concepts/security/")
            )
            rule.id.startsWith("PRISMA") || rule.id.startsWith("SEQUELIZE") || rule.id.startsWith("TYPEORM") ||
                rule.id.startsWith("MONGODB") || rule.id.startsWith("ELASTICSEARCH") -> FixSuggestion(
                title = "Modern ORM/Database Security",
                description = "Use parameterized queries, avoid raw SQL with user input",
                code = "// Prisma safe query:\nconst users = await prisma.queryRaw`SELECT * FROM User WHERE email = \${email}`;\n\n// " +
                    "Sequelize with replacements:\nawait sequelize.query('SELECT * FROM users WHERE email = :email', { replacements: " +
                    "{ email: userEmail }, type: QueryTypes.SELECT });\n\n// TypeORM parameterized:\nconst users = await " +
                    "repository.createQueryBuilder('user').where('user.email = :email', { email: userEmail }).getMany();\n\n// " +
                    "MongoDB safe:\ndb.collection('users').find({ email: userEmail });",
                references = listOf("https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access")
            )
            rule.id.startsWith("TEST") || rule.id.startsWith("GITHUB") || rule.id.startsWith("GITLAB") || rule.id.startsWith("JENKINS") ||
                rule.id.startsWith("SONAR") -> FixSuggestion(
                title = "CI/CD & Testing Security",
                description = "Use secrets management, mask sensitive data in logs",
                code = "# GitHub Actions secrets:\n- name: Deploy\n  env:\n    API_KEY: \${{ secrets.API_KEY }}\n  run: |\n    # Never " +
                    "echo secrets\n    deploy.sh\n\n# GitHub Actions PR validation:\non:\n  pull_request_target:\njobs:\n  " +
                    "validate:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: " +
                    "ubuntu-latest\n\n# Jenkins credentials:\nwithCredentials([string(credentialsId: 'api-key', variable: " +
                    "'API_KEY')]) {\n  sh 'deploy.sh'\n}",
                references = listOf("https://docs.github.com/en/actions/security-guides/encrypted-secrets")
            )
            rule.id.startsWith("DATADOG") || rule.id.startsWith("NEWRELIC") || rule.id.startsWith("SENTRY") ||
                rule.id.startsWith("PROMETHEUS") || rule.id.startsWith("GRAFANA") || rule.id.startsWith("ELASTIC") -> FixSuggestion(
                title = "Monitoring & Observability Security",
                description = "Protect API keys, secure metrics endpoints, authentication",
                code = "// Environment-based config:\nconst apiKey = process.env.DATADOG_API_KEY;\n\n// Prometheus with auth:\n- " +
                    "job_name: 'app'\n  static_configs:\n    - targets: ['localhost:9090']\n  basic_auth:\n    username: " +
                    "'prometheus'\n    password_file: '/etc/prometheus/password'\n\n// Grafana auth:\n[auth.anonymous]\nenabled = " +
                    "false\n\n[auth.basic]\nenabled = true\n\n// Sentry scrubbing:\nSentry.init({\n  beforeSend(event) {\n    if " +
                    "(event.request?.headers?.authorization) {\n      delete event.request.headers.authorization;\n    }\n    return " +
                    "event;\n  }\n});",
                references = listOf("https://docs.datadoghq.com/account_management/api-app-keys/")
            )
            rule.id.startsWith("CLOUDFORMATION") || rule.id.startsWith("TERRAFORM") -> FixSuggestion(
                title = "Infrastructure as Code Security",
                description = "Use AWS Secrets Manager, encrypted state, sensitive variables",
                code = "# Terraform with secrets:\nvariable \"db_password\" {\n  type      = string\n  sensitive = true\n}\n\n# " +
                    "Terraform backend encryption:\nterraform {\n  backend \"s3\" {\n    bucket         = \"terraform-state\"\n    " +
                    "key            = \"state\"\n    region         = \"us-east-1\"\n    encrypt        = true\n    kms_key_id     = " +
                    "\"arn:aws:kms:...\"\n    dynamodb_table = \"terraform-lock\"\n  }\n}\n\n# CloudFormation with Secrets Manager:\n" +
                    "MasterUserPassword: !Sub '{{resolve:secretsmanager:DBPassword:SecretString:password}}'",
                references = listOf("https://www.terraform.io/docs/language/values/variables.html#suppressing-values-in-cli-output")
            )
            rule.id.startsWith("API") -> FixSuggestion(
                title = "API Security Best Practices",
                description = "Rate limiting, pagination, input validation, secure tokens",
                code = "// Rate limiting with Pageable:\n@GetMapping(\"/api/v1/users\")\npublic Page<User> " +
                    "getUsers(@PageableDefault(size = 20) Pageable pageable) {\n  return userService.findAll(pageable);\n}\n\n// " +
                    "Secure CORS:\n@CrossOrigin(origins = {\"https://trusted-domain.com\"})\n\n// DTO instead of Entity:\npublic " +
                    "User updateUser(@RequestBody UserDTO dto) {\n  return userService.update(dto);\n}\n\n// API token in HTTP-only " +
                    "cookie (not localStorage):\nCookie apiCookie = new Cookie(\"apiToken\", apiToken);\n" +
                    "apiCookie.setHttpOnly(true);\napiCookie.setSecure(true);",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html")
            )
            rule.id.startsWith("SESSION") -> FixSuggestion(
                title = "Secure Session Management",
                description = "Regenerate session ID, secure cookies, proper timeout",
                code = "// Session regeneration:\n@PostMapping(\"/login\")\npublic String login(HttpServletRequest request) {\n  " +
                    "request.getSession().invalidate();\n  HttpSession newSession = request.getSession(true);\n  // ...\n}\n\n// " +
                    "Secure cookie:\nCookie cookie = new Cookie(\"JSESSIONID\", sessionId);\ncookie.setSecure(true);\n" +
                    "cookie.setHttpOnly(true);\ncookie.setSameSite(\"Strict\");\ncookie.setMaxAge(1800); // 30 minutes\n\n// " +
                    "Logout:\n@PostMapping(\"/logout\")\npublic void logout(HttpSession session) {\n  session.invalidate();\n}",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html")
            )
            rule.id.startsWith("INPUT") -> FixSuggestion(
                title = "Input Validation & Sanitization",
                description = "Validate all inputs, prevent injection, bounds checking",
                code = "// Regex DoS prevention:\nPattern.compile(regex, Pattern.DOTALL).matcher(input).matches();\n\n// Safe " +
                    "reflection:\nif (ALLOWED_CLASSES.contains(className)) {\n  Class.forName(className);\n}\n\n// Integer " +
                    "overflow:\nint result = Math.addExact(a, b); // Throws on overflow\n\n// Array bounds:\nif (index >= 0 && index " +
                    "< array.length) {\n  value = array[index];\n}\n\n// URL validation:\nif " +
                    "(url.startsWith(\"https://trusted.com/\")) {\n  new URL(url);\n}\n\n// Filename sanitization:\nString safe = " +
                    "Paths.get(filename).getFileName().toString();",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html")
            )
            rule.id.startsWith("PERF") -> FixSuggestion(
                title = "Performance & Resource Management",
                description = "Connection pooling, proper cleanup, bounded resources",
                code = "// N+1 prevention:\n@EntityGraph(attributePaths = {\"items\"})\nList<Order> findAll();\n\n// StringBuilder in " +
                    "loop:\nStringBuilder sb = new StringBuilder();\nfor (String s : list) {\n  sb.append(s);\n}\n\n// Bounded " +
                    "thread pool:\nExecutorService executor = Executors.newFixedThreadPool(10);\n\n// Try-with-resources:\ntry " +
                    "(BufferedReader br = Files.newBufferedReader(path)) {\n  // ...\n}\n\n// Connection pooling:\nHikariConfig " +
                    "config = new HikariConfig();\nconfig.setMaximumPoolSize(10);\nDataSource ds = new HikariDataSource(config);",
                references = listOf("https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html")
            )
            rule.id.startsWith("GRAPHQL") -> FixSuggestion(
                title = "GraphQL Security",
                description = "Query depth limiting, complexity analysis, authorization",
                code = "// Query depth limit:\n@Bean\npublic GraphQLSchema schema() {\n  return GraphQLSchema.newSchema()\n    " +
                    ".query(queryType)\n    .fieldVisibility(MaxQueryDepthInstrumentation.build(15))\n    .build();\n}\n\n// " +
                    "Complexity limit:\n@Bean\npublic Instrumentation complexityInstrumentation() {\n  return new " +
                    "MaxQueryComplexityInstrumentation(1000);\n}\n\n// Field authorization:\n@PreAuthorize(\"hasRole('ADMIN')\")\n" +
                    "@GraphQLQuery\npublic User getUser(Long id) { ... }",
                references = listOf("https://www.graphql-java.com/documentation/instrumentation/")
            )
            rule.id.startsWith("OAUTH") || rule.id.startsWith("JWT") -> FixSuggestion(
                title = "OAuth & JWT Security",
                description = "State parameter, redirect URI validation, JWT verification",
                code = "// OAuth with state:\nString state = generateRandomState();\nsession.setAttribute(\"oauth_state\", state);\n" +
                    "String authUrl = baseUrl + \"?state=\" + state;\n\n// Redirect URI validation:\nif " +
                    "(!ALLOWED_REDIRECTS.contains(redirectUri)) {\n  throw new SecurityException(\"Invalid redirect URI\");\n}\n\n// " +
                    "JWT verification:\nDecodedJWT jwt = JWT.require(Algorithm.HMAC256(secret))\n  .withIssuer(\"auth0\")\n  " +
                    ".build()\n  .verify(token);\n\n// PKCE for mobile:\nString verifier = generateCodeVerifier();\nString challenge " +
                    "= generateCodeChallenge(verifier);",
                references = listOf("https://oauth.net/2/pkce/")
            )
            rule.id.startsWith("GRPC") -> FixSuggestion(
                title = "gRPC Security",
                description = "TLS encryption, authentication, message size limits",
                code = "// gRPC with TLS:\nNettyServerBuilder.forPort(8443)\n  .useTransportSecurity(certChainFile, privateKeyFile)\n  " +
                    ".addService(myService)\n  .build();\n\n// Authentication interceptor:\npublic class AuthInterceptor implements " +
                    "ServerInterceptor {\n  @Override\n  public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(...) {\n    " +
                    "String token = headers.get(AUTH_HEADER);\n    validateToken(token);\n    return next.startCall(call, headers);\n" +
                    "  }\n}\n\n// Message size limit:\nServerBuilder.forPort(8080)\n  .maxInboundMessageSize(1024 * 1024) // 1MB\n  " +
                    ".build();",
                references = listOf("https://grpc.io/docs/guides/auth/")
            )
            rule.id.startsWith("WS") -> FixSuggestion(
                title = "WebSocket Security",
                description = "Origin validation, authentication, rate limiting",
                code = "// Origin validation:\n@Configuration\npublic class WebSocketConfig implements WebSocketConfigurer {\n  " +
                    "@Override\n  public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {\n    " +
                    "registry.addHandler(handler, \"/ws\")\n      .setAllowedOrigins(\"https://trusted.com\");\n  }\n}\n\n// " +
                    "Authentication:\n@OnOpen\npublic void onOpen(Session session, @PathParam(\"token\") String token) {\n  if " +
                    "(!validateToken(token)) {\n    session.close(new CloseReason(POLICY_VIOLATION, \"Unauthorized\"));\n  }\n}\n\n" +
                    "// Use WSS:\nconst ws = new WebSocket('wss://example.com/ws');",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets")
            )
            rule.id.startsWith("SERIAL") -> FixSuggestion(
                title = "Safe Serialization",
                description = "Avoid deserializing untrusted data, use safe parsers",
                code = "// Safe XML parsing:\nDocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
                    "dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n" +
                    "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n\n// Safe YAML:\nYaml yaml = " +
                    "new Yaml(new SafeConstructor());\n\n// Safe Jackson:\nObjectMapper mapper = new ObjectMapper();\n" +
                    "mapper.disableDefaultTyping();\nmapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL, " +
                    "JsonTypeInfo.As.WRAPPER_ARRAY);\n\n// Avoid ObjectInputStream - use JSON:\nObjectMapper mapper = new " +
                    "ObjectMapper();\nMyClass obj = mapper.readValue(jsonString, MyClass.class);",
                references = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html")
            )
            else -> null
        }
    }
    
    private fun parseVulnType(ruleId: String): VulnerabilityType {
        return when {
            ruleId.startsWith("SECRET", ignoreCase = true) -> VulnerabilityType.HARDCODED_CREDENTIALS
            ruleId.contains("SQL", ignoreCase = true) || ruleId.contains("DB", ignoreCase = true) -> VulnerabilityType.SQL_INJECTION
            ruleId.contains("XSS", ignoreCase = true) -> VulnerabilityType.XSS
            ruleId.contains("CRYPTO", ignoreCase = true) || ruleId.contains("JWT", ignoreCase = true) ||
                ruleId.contains("TOKEN", ignoreCase = true) -> VulnerabilityType.WEAK_CRYPTO
            ruleId.contains("AUTH", ignoreCase = true) || ruleId.contains("SESSION", ignoreCase = true) -> VulnerabilityType.AUTHENTICATION
            ruleId.contains("CMD", ignoreCase = true) || ruleId.contains("SCRIPT", ignoreCase = true) ||
                ruleId.contains("EXPR", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            ruleId.contains("PATH", ignoreCase = true) || ruleId.contains("FILE", ignoreCase = true) -> VulnerabilityType.PATH_TRAVERSAL
            ruleId.contains("XXE", ignoreCase = true) -> VulnerabilityType.XXE
            ruleId.contains("DESER", ignoreCase = true) ||
                ruleId.contains("PICKLE", ignoreCase = true) -> VulnerabilityType.INSECURE_DESERIALIZATION
            ruleId.contains("SSRF", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("IDOR", ignoreCase = true) || ruleId.contains("ACCESS", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("CSRF", ignoreCase = true) -> VulnerabilityType.CSRF
            ruleId.contains("LOG", ignoreCase = true) -> VulnerabilityType.INSUFFICIENT_LOGGING
            ruleId.contains("REDIRECT", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("COOKIE", ignoreCase = true) || ruleId.contains("CORS", ignoreCase = true) ||
                ruleId.contains("API", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("LDAP", ignoreCase = true) || ruleId.contains("XPATH", ignoreCase = true) -> VulnerabilityType.SQL_INJECTION
            ruleId.contains("REFLECT", ignoreCase = true) ||
                ruleId.contains("CLASSLOAD", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            ruleId.contains("BUFFER", ignoreCase = true) -> VulnerabilityType.BUFFER_OVERFLOW
            ruleId.contains("CLOUD", ignoreCase = true) || ruleId.contains("DOCKER", ignoreCase = true) ||
                ruleId.contains("MOBILE", ignoreCase = true) ||
                ruleId.contains("CICD", ignoreCase = true) -> VulnerabilityType.HARDCODED_CREDENTIALS
            ruleId.contains("INPUT", ignoreCase = true) || ruleId.contains("SIZE", ignoreCase = true) ||
                ruleId.contains("RATE", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("NULL", ignoreCase = true) ||
                ruleId.contains("RESOURCE", ignoreCase = true) -> VulnerabilityType.INSECURE_DEPENDENCY
            ruleId.contains("RACE", ignoreCase = true) || ruleId.contains("SYNC", ignoreCase = true) ||
                ruleId.contains("THREAD", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("KOTLIN", ignoreCase = true) || ruleId.contains("RECORD", ignoreCase = true) ||
                ruleId.contains("PATTERN", ignoreCase = true) ||
                ruleId.contains("VIRTUAL", ignoreCase = true) -> VulnerabilityType.INSECURE_DEPENDENCY
            ruleId.contains("SPRING", ignoreCase = true) || ruleId.contains("REST", ignoreCase = true) ||
                ruleId.contains("GRAPHQL", ignoreCase = true) ||
                ruleId.contains("WEBSOCKET", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("MICRO", ignoreCase = true) || ruleId.contains("KAFKA", ignoreCase = true) ||
                ruleId.contains("REDIS", ignoreCase = true) ||
                ruleId.contains("RABBIT", ignoreCase = true) -> VulnerabilityType.AUTHENTICATION
            ruleId.contains("WEB", ignoreCase = true) || ruleId.contains("K8S", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("PYTHON", ignoreCase = true) && ruleId.contains("001") -> VulnerabilityType.INSECURE_DESERIALIZATION
            ruleId.contains("JS", ignoreCase = true) || ruleId.contains("TS", ignoreCase = true) ||
                ruleId.contains("NODE", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            ruleId.contains("ATTACK", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            ruleId.contains("GDPR", ignoreCase = true) || ruleId.contains("PCI", ignoreCase = true) ||
                ruleId.contains("HIPAA", ignoreCase = true) ||
                ruleId.contains("PRIVACY", ignoreCase = true) -> VulnerabilityType.INFORMATION_DISCLOSURE
            ruleId.contains("QUALITY", ignoreCase = true) -> VulnerabilityType.INSECURE_DEPENDENCY
            ruleId.contains("ENCODING", ignoreCase = true) || ruleId.contains("HASH", ignoreCase = true) -> VulnerabilityType.WEAK_CRYPTO
            ruleId.contains("NET", ignoreCase = true) -> VulnerabilityType.WEAK_CRYPTO
            ruleId.contains("AUTHZ", ignoreCase = true) ||
                ruleId.contains("BUSINESS", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("REACT", ignoreCase = true) || ruleId.contains("ANGULAR", ignoreCase = true) ||
                ruleId.contains("VUE", ignoreCase = true) || ruleId.contains("NEXTJS", ignoreCase = true) -> VulnerabilityType.XSS
            ruleId.contains("LAMBDA", ignoreCase = true) || ruleId.contains("SERVERLESS", ignoreCase = true) ||
                ruleId.contains("SAM", ignoreCase = true) ||
                ruleId.contains("APIGATEWAY", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("CLOUDFORMATION", ignoreCase = true) ||
                ruleId.contains("TERRAFORM", ignoreCase = true) -> VulnerabilityType.HARDCODED_CREDENTIALS
            ruleId.contains("HELM", ignoreCase = true) || ruleId.contains("ISTIO", ignoreCase = true) -> VulnerabilityType.MISCONFIG
            ruleId.contains("PRISMA", ignoreCase = true) || ruleId.contains("SEQUELIZE", ignoreCase = true) ||
                ruleId.contains("TYPEORM", ignoreCase = true) ||
                ruleId.contains("CASSANDRA", ignoreCase = true) -> VulnerabilityType.SQL_INJECTION
            ruleId.contains("MONGODB", ignoreCase = true) || ruleId.contains("ELASTICSEARCH", ignoreCase = true) ||
                ruleId.contains("FIRESTORE", ignoreCase = true) -> VulnerabilityType.SQL_INJECTION
            ruleId.contains("DYNAMODB", ignoreCase = true) -> VulnerabilityType.WEAK_CRYPTO
            ruleId.contains("TEST", ignoreCase = true) || ruleId.contains("GITHUB", ignoreCase = true) ||
                ruleId.contains("GITLAB", ignoreCase = true) || ruleId.contains("JENKINS", ignoreCase = true) ||
                ruleId.contains("SONAR", ignoreCase = true) -> VulnerabilityType.HARDCODED_CREDENTIALS
            ruleId.contains("DATADOG", ignoreCase = true) || ruleId.contains("NEWRELIC", ignoreCase = true) ||
                ruleId.contains("SENTRY", ignoreCase = true) || ruleId.contains("PROMETHEUS", ignoreCase = true) ||
                ruleId.contains("GRAFANA", ignoreCase = true) ||
                ruleId.contains("ELASTIC", ignoreCase = true) -> VulnerabilityType.HARDCODED_CREDENTIALS
            ruleId.contains("API", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("SESSION", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("INPUT", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            ruleId.contains("PERF", ignoreCase = true) -> VulnerabilityType.INSECURE_DEPENDENCY
            ruleId.contains("GRAPHQL", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            ruleId.contains("OAUTH", ignoreCase = true) || ruleId.contains("JWT", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("GRPC", ignoreCase = true) -> VulnerabilityType.WEAK_CRYPTO
            ruleId.contains("WS", ignoreCase = true) -> VulnerabilityType.ACCESS_CONTROL
            ruleId.contains("SERIAL", ignoreCase = true) -> VulnerabilityType.COMMAND_INJECTION
            else -> VulnerabilityType.INFORMATION_DISCLOSURE
        }
    }
    
    private fun detectLanguage(file: VirtualFile): String {
        return when (file.extension?.lowercase()) {
            "java" -> "java"
            "kt", "kts" -> "kotlin"
            "py" -> "python"
            "js" -> "javascript"
            "ts" -> "typescript"
            "swift" -> "swift"
            "cpp", "cc", "cxx" -> "cpp"
            "c", "h" -> "c"
            else -> "unknown"
        }
    }
    
    private fun collectProjectFiles(project: Project): List<VirtualFile> {
        val files = mutableListOf<VirtualFile>()

        // Walk project root
        project.basePath?.let { basePath ->
            walkDirectory(java.io.File(basePath), files)
        }
        
        return files
    }
    
    private fun walkDirectory(dir: java.io.File, files: MutableList<VirtualFile>) {
        if (!dir.isDirectory || dir.name.startsWith(".")) return
        
        dir.listFiles()?.forEach { file ->
            if (file.isFile && isSupportedFile(file.name)) {
                val vFile = com.intellij.openapi.vfs.LocalFileSystem.getInstance().findFileByIoFile(file)
                if (vFile != null) files.add(vFile)
            } else if (file.isDirectory && !file.name.startsWith(".") && file.name != "node_modules" && file.name != "build") {
                walkDirectory(file, files)
            }
        }
    }
    
    private fun isSupportedFile(filename: String): Boolean {
        val ext = filename.substringAfterLast('.')
        return ext in listOf("java", "kt", "py", "js", "ts", "swift", "cpp", "c", "h", "go", "rs")
    }
    
    
    private fun loadDefaultRules(): List<Rule> {
        return SecretsRules.RULES + listOf(
            Rule(
                id = "SQL_001",
                name = "SQL Injection via String Concatenation",
                description = "User input is directly concatenated into SQL queries",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """(SELECT|INSERT|UPDATE|DELETE).*['"\s]+\+\s*\w+""",
            ),
            Rule(
                id = "XSS_001",
                name = "Cross-Site Scripting via innerHTML",
                description = "User-controlled data is assigned to innerHTML without sanitization",
                severity = Severity.HIGH,
                cwe = 79,
                owasp = "A03:2021 - Injection",
                pattern = """\.innerHTML\s*=\s*[\w\s]+""",
            ),
            Rule(
                id = "AUTH_001",
                name = "Hardcoded Credentials",
                description = "Hardcoded passwords or API keys detected",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(password|api_key|secret|token)\s*=\s*['"]\S+['"]\s*""",
            ),
            Rule(
                id = "CRYPTO_BASIC_001",
                name = "Insecure Random Number Generation",
                description = "Using Math.random() or java.util.Random for security-sensitive operations",
                severity = Severity.MEDIUM,
                cwe = 330,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(Math\.random|new Random)\(""",
            ),
            
            Rule(
                id = "CRYPTO_001",
                name = "Weak Cryptographic Algorithm - MD5/SHA1",
                description = "Using weak hash algorithms like MD5 or SHA1",
                severity = Severity.HIGH,
                cwe = 327,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(MessageDigest\.getInstance\(["'](MD5|SHA-?1)["']\)|hashlib\.(md5|sha1)\()""",
            ),
            Rule(
                id = "CRYPTO_002",
                name = "Weak Encryption - DES/3DES/RC4",
                description = "Using deprecated encryption algorithms (DES, 3DES, RC4)",
                severity = Severity.HIGH,
                cwe = 327,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(Cipher\.getInstance\(["'](DES|3DES|DESede|RC4|ARC4))|AES/ECB""",
            ),
            Rule(
                id = "CRYPTO_003",
                name = "Hardcoded Cryptographic Key",
                description = "Cryptographic key or IV hardcoded in source code",
                severity = Severity.CRITICAL,
                cwe = 321,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(SecretKeySpec|IvParameterSpec)\(.*['"]\w{16,}['"]""",
            ),
            Rule(
                id = "CRYPTO_004",
                name = "Insecure TLS Configuration",
                description = "Using insecure SSL/TLS protocols (SSLv3, TLS 1.0, TLS 1.1)",
                severity = Severity.HIGH,
                cwe = 326,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(SSLv3|TLSv1\.0|TLSv1\.1|PROTOCOL_TLS|PROTOCOL_SSLv3)""",
            ),
            Rule(
                id = "CRYPTO_005",
                name = "Certificate Validation Disabled",
                description = "SSL/TLS certificate validation is disabled",
                severity = Severity.CRITICAL,
                cwe = 295,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(setHostnameVerifier.*ALLOW_ALL|X509TrustManager.*checkServerTrusted.*\{\s*\})""",
            ),
            Rule(
                id = "PATH_001",
                name = "Path Traversal Vulnerability",
                description = "Unsanitized file path construction from user input",
                severity = Severity.HIGH,
                cwe = 22,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(File|Path|Paths\.get)\([^)]*[\+&]\s*\w+""",
            ),
            Rule(
                id = "PATH_002",
                name = "Zip Slip Vulnerability",
                description = "Extracting zip entries without validating paths",
                severity = Severity.HIGH,
                cwe = 22,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """ZipEntry.*getName\(\).*File\(""",
            ),
            Rule(
                id = "CMD_001",
                name = "Command Injection - Runtime.exec()",
                description = "User input flows into system command execution",
                severity = Severity.CRITICAL,
                cwe = 78,
                owasp = "A03:2021 - Injection",
                pattern = """Runtime\.getRuntime\(\)\.exec\(\s*[\w\s]+\+""",
            ),
            Rule(
                id = "CMD_002",
                name = "Command Injection - ProcessBuilder",
                description = "Unsanitized input in ProcessBuilder command",
                severity = Severity.CRITICAL,
                cwe = 78,
                owasp = "A03:2021 - Injection",
                pattern = """ProcessBuilder.*\+\s*\w+""",
            ),
            Rule(
                id = "CMD_003",
                name = "Command Injection - Shell Execution",
                description = "Direct shell command execution with user input",
                severity = Severity.CRITICAL,
                cwe = 78,
                owasp = "A03:2021 - Injection",
                pattern = """(subprocess\.(call|run|Popen)|os\.(system|popen)).*\+\s*\w+""",
            ),
            Rule(
                id = "DESER_001",
                name = "Insecure Deserialization - ObjectInputStream",
                description = "Deserializing untrusted data without validation",
                severity = Severity.CRITICAL,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """ObjectInputStream.*readObject\(\)""",
            ),
            Rule(
                id = "DESER_002",
                name = "Insecure Deserialization - YAML",
                description = "Using unsafe YAML deserialization (yaml.load instead of yaml.safe_load)",
                severity = Severity.HIGH,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """yaml\.load\([^,)]*\)""",
            ),
            Rule(
                id = "XXE_001",
                name = "XXE - XML External Entity",
                description = "XML parser configured without XXE protection",
                severity = Severity.HIGH,
                cwe = 611,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """(DocumentBuilderFactory|SAXParserFactory)\.newInstance\(\)(?!.*setFeature)""",
            ),
            Rule(
                id = "LDAP_001",
                name = "LDAP Injection",
                description = "User input concatenated into LDAP queries",
                severity = Severity.HIGH,
                cwe = 90,
                owasp = "A03:2021 - Injection",
                pattern = """(search|lookup)\(.*\+\s*\w+""",
            ),
            Rule(
                id = "XPATH_001",
                name = "XPath Injection",
                description = "User input in XPath expression without sanitization",
                severity = Severity.HIGH,
                cwe = 643,
                owasp = "A03:2021 - Injection",
                pattern = """(XPath|compile).*evaluate\(.*\+\s*\w+""",
            ),
            Rule(
                id = "SSRF_001",
                name = "Server-Side Request Forgery",
                description = "User-controlled URL in HTTP request",
                severity = Severity.HIGH,
                cwe = 918,
                owasp = "A10:2021 - Server-Side Request Forgery",
                pattern = """(URL|URI|HttpClient|requests\.get)\(.*\+\s*\w+""",
            ),
            Rule(
                id = "IDOR_001",
                name = "Insecure Direct Object Reference",
                description = "Direct database access with user-controlled ID without authorization",
                severity = Severity.HIGH,
                cwe = 639,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(findById|getById|getUserById)\(\s*request\.getParameter""",
            ),
            Rule(
                id = "CSRF_001",
                name = "Missing CSRF Protection",
                description = "State-changing operation without CSRF token validation",
                severity = Severity.MEDIUM,
                cwe = 352,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """@(PostMapping|RequestMapping).*method\s*=\s*RequestMethod\.POST(?!.*csrf)""",
            ),
            Rule(
                id = "LOG_001",
                name = "Log Injection",
                description = "User input logged without sanitization",
                severity = Severity.MEDIUM,
                cwe = 117,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """(log\.(info|debug|warn|error)|logger\.(info|debug|warn|error))\(.*\+\s*\w+""",
            ),
            Rule(
                id = "REDIRECT_001",
                name = "Unvalidated Redirect",
                description = "Redirecting to user-controlled URL",
                severity = Severity.MEDIUM,
                cwe = 601,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(redirect|sendRedirect|location\.href)\s*=\s*[\w\s]+\+""",
            ),
            Rule(
                id = "REGEX_001",
                name = "Regular Expression Denial of Service (ReDoS)",
                description = "Potentially catastrophic backtracking in regex",
                severity = Severity.MEDIUM,
                cwe = 1333,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """\(.*\+.*\)\+|\(.*\*.*\)\*""",
            ),
            Rule(
                id = "RACE_001",
                name = "Time-of-Check Time-of-Use (TOCTOU)",
                description = "Race condition in file operations",
                severity = Severity.MEDIUM,
                cwe = 367,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(File\.exists|isFile|isDirectory)\(\).*\n.*new FileOutputStream""",
            ),
            Rule(
                id = "TEMP_001",
                name = "Insecure Temporary File",
                description = "Creating temporary files with predictable names",
                severity = Severity.MEDIUM,
                cwe = 377,
                owasp = "A04:2021 - Insecure Design",
                pattern = """File\.createTempFile\(['"]\w+['"],\s*null\)""",
            ),
            Rule(
                id = "SQL_002",
                name = "SQL Injection - JPA Native Query",
                description = "Native SQL query with string concatenation in JPA",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """createNativeQuery\(.*\+\s*\w+""",
            ),
            Rule(
                id = "SQL_003",
                name = "NoSQL Injection - MongoDB",
                description = "MongoDB query with unsanitized user input",
                severity = Severity.HIGH,
                cwe = 943,
                owasp = "A03:2021 - Injection",
                pattern = """(find|findOne)\(.*\${'$'}where.*\+""",
            ),
            Rule(
                id = "XSS_002",
                name = "DOM-based XSS - document.write",
                description = "Using document.write with user-controlled data",
                severity = Severity.HIGH,
                cwe = 79,
                owasp = "A03:2021 - Injection",
                pattern = """document\.write\(.*(?:location|window\.location|document\.URL)""",
            ),
            Rule(
                id = "XSS_003",
                name = "React XSS - dangerouslySetInnerHTML",
                description = "Using dangerouslySetInnerHTML without sanitization",
                severity = Severity.HIGH,
                cwe = 79,
                owasp = "A03:2021 - Injection",
                pattern = """dangerouslySetInnerHTML=\{\{__html:\s*\w+""",
            ),
            Rule(
                id = "JWT_001",
                name = "Weak JWT Algorithm",
                description = "JWT signed with 'none' algorithm or weak signature",
                severity = Severity.CRITICAL,
                cwe = 347,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(algorithm.*["']none["']|\.setSigningKey\(["']\w{1,16}["']\))""",
            ),
            Rule(
                id = "COOKIE_001",
                name = "Insecure Cookie Configuration",
                description = "Cookie without Secure or HttpOnly flag",
                severity = Severity.MEDIUM,
                cwe = 614,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """Cookie\(.*\)(?!.*setSecure|.*setHttpOnly)""",
            ),
            Rule(
                id = "CORS_001",
                name = "Overly Permissive CORS",
                description = "CORS configured to allow all origins",
                severity = Severity.HIGH,
                cwe = 942,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """Access-Control-Allow-Origin.*\*""",
            ),
            Rule(
                id = "MASS_ASSIGN_001",
                name = "Mass Assignment Vulnerability",
                description = "Binding all request parameters without whitelist",
                severity = Severity.MEDIUM,
                cwe = 915,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@RequestBody.*(?!@Valid|@Validated).*User""",
            ),
            
            // ADDITIONAL RULES - Java/Kotlin Specific
            Rule(
                id = "REFLECT_001",
                name = "Unsafe Reflection Usage",
                description = "Using reflection with user-controlled class names",
                severity = Severity.HIGH,
                cwe = 470,
                owasp = "A03:2021 - Injection",
                pattern = """(Class\.forName|\.newInstance|\.invoke)\(.*\+\s*\w+""",
            ),
            Rule(
                id = "SCRIPT_001",
                name = "Script Engine Injection",
                description = "JavaScript/Script engine execution with user input",
                severity = Severity.CRITICAL,
                cwe = 94,
                owasp = "A03:2021 - Injection",
                pattern = """(ScriptEngine|eval|ScriptEngineManager).*\.eval\(.*\+""",
            ),
            Rule(
                id = "EXPR_001",
                name = "Expression Language Injection",
                description = "SpEL or OGNL expression with unsanitized input",
                severity = Severity.CRITICAL,
                cwe = 917,
                owasp = "A03:2021 - Injection",
                pattern = """(ExpressionParser|OgnlContext|getValue)\(.*\+\s*\w+""",
            ),
            Rule(
                id = "THREAD_001",
                name = "Insecure Thread Creation",
                description = "Creating threads with user-controlled Runnable",
                severity = Severity.HIGH,
                cwe = 572,
                owasp = "A04:2021 - Insecure Design",
                pattern = """new Thread\(.*\+\s*\w+""",
            ),
            Rule(
                id = "CLASSLOAD_001",
                name = "Insecure ClassLoader Usage",
                description = "Loading classes from user-controlled paths",
                severity = Severity.CRITICAL,
                cwe = 470,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """(URLClassLoader|ClassLoader\.loadClass)\(.*\+\s*\w+""",
            ),
            
            // Memory & Resource Management
            Rule(
                id = "RESOURCE_001",
                name = "Resource Leak - Unclosed Stream",
                description = "Stream or connection not closed in finally or try-with-resources",
                severity = Severity.MEDIUM,
                cwe = 404,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(FileInputStream|FileOutputStream|Connection|Statement|ResultSet)\s+\w+\s*=.*(?!try-with-resources)""",
            ),
            Rule(
                id = "NULL_001",
                name = "Null Pointer Dereference",
                description = "Potential null pointer access without null check",
                severity = Severity.MEDIUM,
                cwe = 476,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(\.get\(\w+\)|\.orElse|Optional)\s*\.\w+(?!\.isPresent|\.isEmpty)""",
            ),
            Rule(
                id = "BUFFER_001",
                name = "Buffer Overflow Risk",
                description = "Fixed-size buffer with unbounded input",
                severity = Severity.HIGH,
                cwe = 120,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(byte\[\d+\]|char\[\d+\]).*\.read\(""",
            ),
            
            // Input Validation
            Rule(
                id = "INPUT_001",
                name = "Missing Input Validation",
                description = "User input used without validation",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """@(RequestParam|PathVariable).*String\s+\w+\)(?!.*@Valid|.*@Pattern)""",
            ),
            Rule(
                id = "SIZE_001",
                name = "Missing Size Validation",
                description = "File upload or input without size limit",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(MultipartFile|InputStream).*(?!@Size|@Max|maxFileSize)""",
            ),
            Rule(
                id = "RATE_001",
                name = "Missing Rate Limiting",
                description = "API endpoint without rate limiting",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@(PostMapping|PutMapping|DeleteMapping)(?!.*@RateLimit|.*@Throttle)""",
            ),
            
            // Authentication & Authorization
            Rule(
                id = "AUTH_002",
                name = "Weak Password Storage",
                description = "Passwords stored without proper hashing",
                severity = Severity.CRITICAL,
                cwe = 256,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(setPassword|savePassword)\(.*(?!BCrypt|Argon2|PBKDF2|SCrypt)""",
            ),
            Rule(
                id = "AUTH_003",
                name = "Missing Authentication Check",
                description = "Sensitive endpoint without authentication annotation",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """@(PostMapping|PutMapping|DeleteMapping).*(?!@PreAuthorize|@Secured|@RolesAllowed)""",
            ),
            Rule(
                id = "SESSION_001",
                name = "Insecure Session Management",
                description = "Session ID exposed in URL or logs",
                severity = Severity.HIGH,
                cwe = 598,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(session|sessionId|JSESSIONID).*\+\s*(url|redirect|log)""",
            ),
            Rule(
                id = "TOKEN_001",
                name = "Insecure Token Generation",
                description = "Using weak random for security tokens",
                severity = Severity.HIGH,
                cwe = 330,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(token|sessionId|nonce)\s*=.*(Math\.random|Random\(\)|UUID\.randomUUID)""",
            ),
            
            // API Security
            Rule(
                id = "API_001",
                name = "Sensitive Data in GET Request",
                description = "Sensitive data transmitted via GET method",
                severity = Severity.MEDIUM,
                cwe = 598,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@GetMapping.*@RequestParam.*(password|secret|token|key)""",
            ),
            Rule(
                id = "API_002",
                name = "Missing Content-Type Validation",
                description = "Endpoint accepts any content type",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """@(PostMapping|PutMapping)(?!.*consumes\s*=)""",
            ),
            Rule(
                id = "API_003",
                name = "Verbose Error Messages",
                description = "Exposing stack traces or internal details in responses",
                severity = Severity.LOW,
                cwe = 209,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(printStackTrace|\.getMessage|\.toString)\(\).*response""",
            ),
            
            // Database Security
            Rule(
                id = "DB_001",
                name = "SQL Query with Dynamic Table Name",
                description = "Table or column name from user input",
                severity = Severity.HIGH,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """(SELECT|FROM|UPDATE|DELETE).*\+\s*(tableName|columnName)""",
            ),
            Rule(
                id = "DB_002",
                name = "ORM N+1 Query Problem",
                description = "Potential N+1 query performance issue",
                severity = Severity.LOW,
                cwe = 1050,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@OneToMany.*fetch\s*=\s*FetchType\.LAZY(?!.*@BatchSize)""",
            ),
            Rule(
                id = "DB_003",
                name = "Missing Database Connection Pool",
                description = "Opening connections without pooling",
                severity = Severity.MEDIUM,
                cwe = 404,
                owasp = "A04:2021 - Insecure Design",
                pattern = """DriverManager\.getConnection.*(?!DataSource|HikariCP|c3p0)""",
            ),
            
            // Cloud & Container Security
            Rule(
                id = "CLOUD_001",
                name = "Exposed AWS Credentials",
                description = "AWS access keys hardcoded in source",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(AKIA[0-9A-Z]{16}|aws_access_key_id|AWS_SECRET_ACCESS_KEY)""",
            ),
            Rule(
                id = "CLOUD_002",
                name = "Insecure S3 Bucket Access",
                description = "S3 bucket with public access or weak ACL",
                severity = Severity.HIGH,
                cwe = 732,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(\.withCannedAcl\(CannedAccessControlList\.PublicRead|s3:.*\*)""",
            ),
            Rule(
                id = "DOCKER_001",
                name = "Dockerfile Security Issue",
                description = "Running container as root or exposing sensitive ports",
                severity = Severity.MEDIUM,
                cwe = 250,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(FROM.*:latest|USER root|EXPOSE (22|23|3389))""",
            ),
            
            // Concurrency Issues
            Rule(
                id = "RACE_002",
                name = "Double-Checked Locking",
                description = "Broken double-checked locking pattern",
                severity = Severity.MEDIUM,
                cwe = 609,
                owasp = "A04:2021 - Insecure Design",
                pattern = """if\s*\(\s*\w+\s*==\s*null\s*\).*synchronized.*if\s*\(\s*\w+\s*==\s*null""",
            ),
            Rule(
                id = "SYNC_001",
                name = "Synchronization on Non-Final Field",
                description = "Synchronizing on mutable object",
                severity = Severity.MEDIUM,
                cwe = 662,
                owasp = "A04:2021 - Insecure Design",
                pattern = """synchronized\s*\(\s*this\.\w+(?!.*final)""",
            ),
            
            // Modern Java Features (Java 21+)
            Rule(
                id = "RECORD_001",
                name = "Mutable Record Field",
                description = "Record with mutable field exposing internal state",
                severity = Severity.MEDIUM,
                cwe = 374,
                owasp = "A04:2021 - Insecure Design",
                pattern = """record\s+\w+\([^)]*(?:List|Map|Set|Array)(?!.*unmodifiable)""",
            ),
            Rule(
                id = "VIRTUAL_001",
                name = "Virtual Thread Pinning Risk",
                description = "Blocking operation in virtual thread",
                severity = Severity.LOW,
                cwe = 821,
                owasp = "A04:2021 - Insecure Design",
                pattern = """Thread\.ofVirtual.*synchronized\s*\(""",
            ),
            Rule(
                id = "PATTERN_001",
                name = "Pattern Matching Type Confusion",
                description = "Pattern matching without proper type guards",
                severity = Severity.MEDIUM,
                cwe = 843,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(instanceof\s+\w+\s+\w+).*(?!if|&&|\|\|)""",
            ),
            
            // Kotlin Specific
            Rule(
                id = "KOTLIN_001",
                name = "Platform Type Null Safety Bypass",
                description = "Using platform types without null checks",
                severity = Severity.MEDIUM,
                cwe = 476,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(fun|val)\s+\w+.*=.*\.let\s*\{.*!!\s*\}""",
            ),
            Rule(
                id = "KOTLIN_002",
                name = "Unsafe lateinit Usage",
                description = "lateinit var accessed without initialization check",
                severity = Severity.MEDIUM,
                cwe = 665,
                owasp = "A04:2021 - Insecure Design",
                pattern = """lateinit\s+var\s+\w+.*(?!::.*\.isInitialized)""",
            ),
            Rule(
                id = "KOTLIN_003",
                name = "Data Class with Mutable Collections",
                description = "Data class exposing mutable collections",
                severity = Severity.MEDIUM,
                cwe = 374,
                owasp = "A04:2021 - Insecure Design",
                pattern = """data class.*\((.*Mutable(List|Set|Map)|var\s+(list|set|map))""",
            ),
            
            // Spring Security & Framework Specific (10 rules)
            Rule(
                id = "SPRING_001",
                name = "Overly Permissive Spring Security",
                description = "Spring Security configured to permit all requests",
                severity = Severity.CRITICAL,
                cwe = 306,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(permitAll\(\)|authorizeRequests.*anyRequest.*permitAll)""",
            ),
            Rule(
                id = "SPRING_002",
                name = "Disabled CSRF in Spring",
                description = "CSRF protection explicitly disabled",
                severity = Severity.HIGH,
                cwe = 352,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """csrf\(\)\.disable\(\)""",
            ),
            Rule(
                id = "SPRING_003",
                name = "Actuator Endpoints Exposed",
                description = "Spring Boot Actuator endpoints without authentication",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """management\.endpoints\.web\.exposure\.include=\*""",
            ),
            Rule(
                id = "SPRING_004",
                name = "SQL Injection in Spring JdbcTemplate",
                description = "String concatenation in JdbcTemplate query",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """jdbcTemplate\.(query|update)\(.*\+\s*\w+""",
            ),
            Rule(
                id = "SPRING_005",
                name = "Hardcoded Spring Profile Credentials",
                description = "Credentials in application.properties/yml",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(spring\.datasource\.(password|username)|spring\.security\.user\.password)\s*=\s*\S+""",
            ),
            Rule(
                id = "SPRING_006",
                name = "Missing @Transactional on Write Operations",
                description = "Database write without transaction management",
                severity = Severity.MEDIUM,
                cwe = 662,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(save|update|delete)\(.*\)(?!.*@Transactional)""",
            ),
            Rule(
                id = "SPRING_007",
                name = "Insecure OAuth2 Configuration",
                description = "OAuth2 without proper scope validation",
                severity = Severity.HIGH,
                cwe = 285,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """@EnableOAuth2Client(?!.*hasAuthority|.*hasRole)""",
            ),
            Rule(
                id = "SPRING_008",
                name = "Bean Validation Disabled",
                description = "Spring MVC without validation annotations",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """@RequestBody(?!.*@Valid|.*@Validated)""",
            ),
            Rule(
                id = "SPRING_009",
                name = "Debug Mode in Production",
                description = "Spring Boot debug/trace logging enabled",
                severity = Severity.MEDIUM,
                cwe = 215,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(logging\.level\.root|debug)\s*=\s*(DEBUG|TRACE)""",
            ),
            Rule(
                id = "SPRING_010",
                name = "Unsafe SpEL Expression",
                description = "Spring Expression Language with user input",
                severity = Severity.CRITICAL,
                cwe = 917,
                owasp = "A03:2021 - Injection",
                pattern = """@Value\(.*\$\{.*\+""",
            ),
            
            // REST API & GraphQL Security (8 rules)
            Rule(
                id = "REST_001",
                name = "Missing Pagination on List Endpoints",
                description = "API endpoint returning unbounded lists",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@GetMapping.*findAll\(\)(?!.*Pageable)""",
            ),
            Rule(
                id = "REST_002",
                name = "HTTP Method Override Vulnerability",
                description = "Accepting X-HTTP-Method-Override header",
                severity = Severity.MEDIUM,
                cwe = 352,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """X-HTTP-Method-Override""",
            ),
            Rule(
                id = "REST_003",
                name = "Missing API Versioning",
                description = "API endpoint without version control",
                severity = Severity.LOW,
                cwe = 1059,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@RequestMapping\((?!.*version|.*/v\d+)""",
            ),
            Rule(
                id = "REST_004",
                name = "Sensitive Data in URL Path",
                description = "Using sensitive data in @PathVariable",
                severity = Severity.MEDIUM,
                cwe = 598,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@PathVariable.*(password|secret|token|ssn|credit)""",
            ),
            Rule(
                id = "GRAPHQL_001",
                name = "GraphQL Query Depth Limit Missing",
                description = "No query depth limiting in GraphQL",
                severity = Severity.HIGH,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@GraphQL(?!.*maxQueryDepth|.*complexity)""",
            ),
            Rule(
                id = "GRAPHQL_002",
                name = "GraphQL Introspection Enabled",
                description = "GraphQL introspection in production",
                severity = Severity.MEDIUM,
                cwe = 215,
                owasp = "A04:2021 - Insecure Design",
                pattern = """graphql\.introspection\.enabled\s*=\s*true""",
            ),
            Rule(
                id = "GRAPHQL_003",
                name = "GraphQL Batch Query DoS",
                description = "No batching limit on GraphQL mutations",
                severity = Severity.HIGH,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@Mutation(?!.*@Throttle|.*maxBatchSize)""",
            ),
            Rule(
                id = "WEBSOCKET_001",
                name = "Insecure WebSocket Configuration",
                description = "WebSocket endpoint without authentication",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """@MessageMapping(?!.*@PreAuthorize|.*Principal)""",
            ),
            
            // Microservices & Distributed Systems (7 rules)
            Rule(
                id = "MICRO_001",
                name = "Missing Circuit Breaker",
                description = "External service call without circuit breaker",
                severity = Severity.MEDIUM,
                cwe = 755,
                owasp = "A04:2021 - Insecure Design",
                pattern = """RestTemplate\.(get|post|put|delete)(?!.*@CircuitBreaker|.*@HystrixCommand)""",
            ),
            Rule(
                id = "MICRO_002",
                name = "Service-to-Service Authentication Missing",
                description = "Microservice call without mutual TLS",
                severity = Severity.HIGH,
                cwe = 287,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """@FeignClient(?!.*configuration.*ssl)""",
            ),
            Rule(
                id = "MICRO_003",
                name = "Sensitive Data in Service Logs",
                description = "Logging request/response in microservices",
                severity = Severity.MEDIUM,
                cwe = 532,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """log\.(info|debug).*request\.getBody|response\.getBody""",
            ),
            Rule(
                id = "MICRO_004",
                name = "Missing Request Timeout",
                description = "HTTP client without timeout configuration",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(RestTemplate|WebClient|HttpClient).*(?!timeout|connectTimeout)""",
            ),
            Rule(
                id = "KAFKA_001",
                name = "Kafka Without Authentication",
                description = "Kafka consumer/producer without SASL",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """@KafkaListener(?!.*sasl|.*security\.protocol)""",
            ),
            Rule(
                id = "REDIS_001",
                name = "Redis Without Password",
                description = "Redis connection without authentication",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(spring\.redis\.host|jedis\.host)(?!.*password)""",
            ),
            Rule(
                id = "RABBIT_001",
                name = "RabbitMQ Insecure Configuration",
                description = "RabbitMQ without SSL/TLS",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """spring\.rabbitmq\.host(?!.*ssl|.*port=5671)""",
            ),
            
            // Mobile & Frontend Security (6 rules)
            Rule(
                id = "MOBILE_001",
                name = "Hardcoded API Key in Mobile Code",
                description = "API keys embedded in mobile application",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(apiKey|api_key|API_KEY)\s*=\s*["']\w{20,}["']""",
            ),
            Rule(
                id = "MOBILE_002",
                name = "Insecure Data Storage on Mobile",
                description = "Sensitive data in SharedPreferences/UserDefaults",
                severity = Severity.HIGH,
                cwe = 312,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(SharedPreferences|UserDefaults)\.(set|put).*(password|token|secret)""",
            ),
            Rule(
                id = "MOBILE_003",
                name = "Certificate Pinning Not Implemented",
                description = "Mobile app without SSL pinning",
                severity = Severity.MEDIUM,
                cwe = 295,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """URLSession(?!.*pinnedCertificates|.*publicKeys)""",
            ),
            Rule(
                id = "WEB_001",
                name = "Missing Content Security Policy",
                description = "Web application without CSP header",
                severity = Severity.HIGH,
                cwe = 693,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """<head>(?!.*Content-Security-Policy)""",
            ),
            Rule(
                id = "WEB_002",
                name = "Missing Subresource Integrity",
                description = "External scripts without SRI",
                severity = Severity.MEDIUM,
                cwe = 353,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """<script.*src=["']https?://(?!.*integrity=)""",
            ),
            Rule(
                id = "WEB_003",
                name = "Autocomplete Enabled on Sensitive Fields",
                description = "Password/credit card fields with autocomplete",
                severity = Severity.MEDIUM,
                cwe = 522,
                owasp = "A04:2021 - Insecure Design",
                pattern = """<input.*(password|credit|cvv)(?!.*autocomplete=["']off["'])""",
            ),
            
            // DevOps & CI/CD Security (5 rules)
            Rule(
                id = "CICD_001",
                name = "Secrets in Version Control",
                description = "Potential secrets in Git repository",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----|password.*=.*['"]\w+['"])""",
            ),
            Rule(
                id = "CICD_002",
                name = "Insecure Docker Base Image",
                description = "Using outdated or vulnerable base images",
                severity = Severity.HIGH,
                cwe = 1104,
                owasp = "A06:2021 - Vulnerable and Outdated Components",
                pattern = """FROM (debian:7|ubuntu:14|centos:6|alpine:3.[0-5])""",
            ),
            Rule(
                id = "CICD_003",
                name = "Privileged Docker Container",
                description = "Container running with --privileged flag",
                severity = Severity.HIGH,
                cwe = 250,
                owasp = "A04:2021 - Insecure Design",
                pattern = """--privileged|privileged:\s*true""",
            ),
            Rule(
                id = "K8S_001",
                name = "Kubernetes Pod Without Security Context",
                description = "K8s pod running as root",
                severity = Severity.HIGH,
                cwe = 250,
                owasp = "A04:2021 - Insecure Design",
                pattern = """kind:\s*Pod(?!.*securityContext|.*runAsNonRoot)""",
            ),
            Rule(
                id = "K8S_002",
                name = "Kubernetes Secrets in ConfigMap",
                description = "Sensitive data in ConfigMap instead of Secret",
                severity = Severity.HIGH,
                cwe = 312,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """kind:\s*ConfigMap.*data:.*password""",
            ),
            
            // Python Specific (5 rules)
            Rule(
                id = "PYTHON_001",
                name = "Python Pickle Deserialization",
                description = "Unsafe pickle.loads() on untrusted data",
                severity = Severity.CRITICAL,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """pickle\.(loads|load)\(""",
            ),
            Rule(
                id = "PYTHON_002",
                name = "Python Code Injection via eval()",
                description = "Using eval() with user input",
                severity = Severity.CRITICAL,
                cwe = 94,
                owasp = "A03:2021 - Injection",
                pattern = """eval\(.*input|eval\(.*request""",
            ),
            Rule(
                id = "PYTHON_003",
                name = "Flask Debug Mode in Production",
                description = "Flask app running with debug=True",
                severity = Severity.HIGH,
                cwe = 215,
                owasp = "A04:2021 - Insecure Design",
                pattern = """app\.run\(.*debug\s*=\s*True""",
            ),
            Rule(
                id = "PYTHON_004",
                name = "Django SECRET_KEY in Code",
                description = "Hardcoded Django SECRET_KEY",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """SECRET_KEY\s*=\s*['"][^'"]{20,}['"]""",
            ),
            Rule(
                id = "PYTHON_005",
                name = "SQLAlchemy SQL Injection",
                description = "Raw SQL in SQLAlchemy with string formatting",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """(session\.execute|text)\(.*[%f]\s*%""",
            ),
            
            // JavaScript/TypeScript Advanced (6 rules)
            Rule(
                id = "JS_001",
                name = "Prototype Pollution Vulnerability",
                description = "Unsafe object property assignment",
                severity = Severity.HIGH,
                cwe = 1321,
                owasp = "A03:2021 - Injection",
                pattern = """(Object\.assign|.*__proto__|.*constructor\.prototype)""",
            ),
            Rule(
                id = "JS_002",
                name = "Insecure Random for Crypto",
                description = "Using Math.random() for cryptographic purposes",
                severity = Severity.HIGH,
                cwe = 330,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(token|key|nonce|salt).*Math\.random\(\)""",
            ),
            Rule(
                id = "JS_003",
                name = "Node.js Child Process Injection",
                description = "Unsanitized input in child_process.exec",
                severity = Severity.CRITICAL,
                cwe = 78,
                owasp = "A03:2021 - Injection",
                pattern = """(exec|spawn)\(.*\+.*\)""",
            ),
            Rule(
                id = "TS_001",
                name = "TypeScript 'any' Type Overuse",
                description = "Using 'any' defeats type safety",
                severity = Severity.LOW,
                cwe = 843,
                owasp = "A04:2021 - Insecure Design",
                pattern = """:\s*any(?!.*@ts-expect-error)""",
            ),
            Rule(
                id = "NODE_001",
                name = "Express.js Without Helmet",
                description = "Express app without security headers middleware",
                severity = Severity.MEDIUM,
                cwe = 693,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """express\(\)(?!.*helmet\(\))""",
            ),
            Rule(
                id = "NODE_002",
                name = "MongoDB NoSQL Injection",
                description = "Direct object in MongoDB query",
                severity = Severity.HIGH,
                cwe = 943,
                owasp = "A03:2021 - Injection",
                pattern = """find\(req\.(body|query|params)\)""",
            ),
            
            // Advanced Attack Vectors (10 rules)
            Rule(
                id = "ATTACK_001",
                name = "Server-Side Template Injection (SSTI)",
                description = "User input in template rendering",
                severity = Severity.CRITICAL,
                cwe = 94,
                owasp = "A03:2021 - Injection",
                pattern = """(render|renderTemplate|compile)\(.*\+\s*\w+|Template.*\+""",
            ),
            Rule(
                id = "ATTACK_002",
                name = "HTTP Response Splitting",
                description = "Unvalidated user input in HTTP headers",
                severity = Severity.HIGH,
                cwe = 113,
                owasp = "A03:2021 - Injection",
                pattern = """(setHeader|addHeader)\(.*\+\s*\w+.*\\r\\n""",
            ),
            Rule(
                id = "ATTACK_003",
                name = "Open Redirect via Header Injection",
                description = "User-controlled Location header",
                severity = Severity.MEDIUM,
                cwe = 601,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(setHeader\(["']Location["']|\.location)\s*.*\+\s*\w+""",
            ),
            Rule(
                id = "ATTACK_004",
                name = "XML Bomb (Billion Laughs Attack)",
                description = "XML parser without entity expansion limit",
                severity = Severity.HIGH,
                cwe = 776,
                owasp = "A04:2021 - Insecure Design",
                pattern = """DocumentBuilder(?!.*FEATURE_SECURE_PROCESSING|.*setEntityExpansionLimit)""",
            ),
            Rule(
                id = "ATTACK_005",
                name = "Zip Bomb Detection",
                description = "No compression ratio validation for archives",
                severity = Severity.MEDIUM,
                cwe = 409,
                owasp = "A04:2021 - Insecure Design",
                pattern = """ZipInputStream.*(?!.*getCompressedSize|.*ratio)""",
            ),
            Rule(
                id = "ATTACK_006",
                name = "LDAP Filter Injection",
                description = "Building LDAP filters with string concatenation",
                severity = Severity.HIGH,
                cwe = 90,
                owasp = "A03:2021 - Injection",
                pattern = """(\\(.*\+.*\\)|LdapName.*\+)""",
            ),
            Rule(
                id = "ATTACK_007",
                name = "CSV Injection (Formula Injection)",
                description = "Untrusted data in CSV without escaping formulas",
                severity = Severity.MEDIUM,
                cwe = 1236,
                owasp = "A03:2021 - Injection",
                pattern = """(csvWriter|writeNext|addCell).*(?!.*startsWith\(["'][=+@-])""",
            ),
            Rule(
                id = "ATTACK_008",
                name = "File Upload Without Type Validation",
                description = "Accepting files without proper MIME type check",
                severity = Severity.HIGH,
                cwe = 434,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(MultipartFile|@RequestParam.*file)(?!.*getContentType|.*getMimeType)""",
            ),
            Rule(
                id = "ATTACK_009",
                name = "Insecure File Download",
                description = "File download without access control",
                severity = Severity.HIGH,
                cwe = 22,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(sendFile|writeFile|download).*\+\s*\w+(?!.*checkAccess|.*authorize)""",
            ),
            Rule(
                id = "ATTACK_010",
                name = "Memory Exhaustion via Unbounded Collection",
                description = "Adding to collection without size limit",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """while.*\.(add|put)\((?!.*size\(\)\s*[<>]|.*MAX_SIZE)""",
            ),
            
            // Data Privacy & Compliance (8 rules)
            Rule(
                id = "GDPR_001",
                name = "Missing Data Encryption at Rest",
                description = "Sensitive data stored without encryption",
                severity = Severity.HIGH,
                cwe = 311,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(email|ssn|credit|passport).*save\((?!.*encrypt|.*cipher)""",
            ),
            Rule(
                id = "GDPR_002",
                name = "Missing Audit Logging",
                description = "No audit trail for sensitive operations",
                severity = Severity.MEDIUM,
                cwe = 778,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """(delete|update).*User(?!.*log\.|.*audit)""",
            ),
            Rule(
                id = "GDPR_003",
                name = "PII in Logs",
                description = "Personally Identifiable Information in log statements",
                severity = Severity.HIGH,
                cwe = 532,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """log\.(info|debug|warn).*(email|ssn|password|credit)""",
            ),
            Rule(
                id = "PCI_001",
                name = "Credit Card Number in Code",
                description = "Hardcoded or unmasked credit card data",
                severity = Severity.CRITICAL,
                cwe = 311,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(creditCard|cardNumber)\s*=\s*["']\d{13,19}["']""",
            ),
            Rule(
                id = "PCI_002",
                name = "CVV/CVC Stored After Authorization",
                description = "Card verification code stored permanently",
                severity = Severity.CRITICAL,
                cwe = 359,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(cvv|cvc|securityCode).*\.(save|persist|store)""",
            ),
            Rule(
                id = "HIPAA_001",
                name = "PHI Without Encryption",
                description = "Protected Health Information unencrypted",
                severity = Severity.CRITICAL,
                cwe = 311,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(medicalRecord|diagnosis|prescription).*save\((?!.*encrypt)""",
            ),
            Rule(
                id = "PRIVACY_001",
                name = "Missing Data Retention Policy",
                description = "No automatic data deletion after retention period",
                severity = Severity.MEDIUM,
                cwe = 1188,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@Entity(?!.*@TTL|.*deleteAfter|.*expiresAt)""",
            ),
            Rule(
                id = "PRIVACY_002",
                name = "Third-Party Data Sharing Without Consent",
                description = "Sending user data to external services",
                severity = Severity.HIGH,
                cwe = 359,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(analytics|tracking|sendToThirdParty).*userData(?!.*consent|.*hasAgreed)""",
            ),
            
            // Code Quality & Security Best Practices (10 rules)
            Rule(
                id = "QUALITY_001",
                name = "Empty Catch Block",
                description = "Exception caught but not handled",
                severity = Severity.LOW,
                cwe = 391,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """catch\s*\([^)]+\)\s*\{\s*\}""",
            ),
            Rule(
                id = "QUALITY_002",
                name = "Hardcoded Sensitive URLs",
                description = "Production URLs hardcoded in source",
                severity = Severity.MEDIUM,
                cwe = 547,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """(https?://)(api|admin|internal)\.(production|live)\..*["']""",
            ),
            Rule(
                id = "QUALITY_003",
                name = "TODO/FIXME in Security Code",
                description = "Incomplete security implementation",
                severity = Severity.MEDIUM,
                cwe = 1188,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(TODO|FIXME|HACK).*(auth|security|crypto|password|token)""",
            ),
            Rule(
                id = "QUALITY_004",
                name = "Deprecated Security API",
                description = "Using deprecated security functions",
                severity = Severity.MEDIUM,
                cwe = 477,
                owasp = "A06:2021 - Vulnerable and Outdated Components",
                pattern = """(@Deprecated|deprecated).*(encrypt|hash|sign|authenticate)""",
            ),
            Rule(
                id = "QUALITY_005",
                name = "System.out Instead of Logger",
                description = "Using System.out for logging",
                severity = Severity.LOW,
                cwe = 778,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """System\.(out|err)\.print""",
            ),
            Rule(
                id = "QUALITY_006",
                name = "Missing Input Length Validation",
                description = "No maximum length check on string input",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """@RequestParam\s+String\s+\w+(?!.*@Size|.*@Length|.*@Max)""",
            ),
            Rule(
                id = "QUALITY_007",
                name = "Magic Numbers in Security Code",
                description = "Hardcoded security-related constants",
                severity = Severity.LOW,
                cwe = 547,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(iterations|keySize|saltLength)\s*=\s*\d+(?!.*final|.*const)""",
            ),
            Rule(
                id = "QUALITY_008",
                name = "Broad Exception Catching",
                description = "Catching generic Exception/Throwable",
                severity = Severity.LOW,
                cwe = 396,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """catch\s*\(\s*(Exception|Throwable)\s+""",
            ),
            Rule(
                id = "QUALITY_009",
                name = "Finalizer/Cleaner Security Issue",
                description = "Insecure finalize() method implementation",
                severity = Severity.MEDIUM,
                cwe = 586,
                owasp = "A04:2021 - Insecure Design",
                pattern = """protected\s+void\s+finalize\(\)(?!.*final)""",
            ),
            Rule(
                id = "QUALITY_010",
                name = "Clone Method Security",
                description = "Insecure clone() implementation",
                severity = Severity.MEDIUM,
                cwe = 498,
                owasp = "A04:2021 - Insecure Design",
                pattern = """public\s+Object\s+clone\(\)(?!.*CloneNotSupportedException)""",
            ),
            
            // Advanced Crypto & Encoding (8 rules)
            Rule(
                id = "CRYPTO_006",
                name = "Weak Key Generation",
                description = "Cryptographic key with insufficient entropy",
                severity = Severity.HIGH,
                cwe = 326,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """KeyGenerator.*init\((128|512)(?!.*2048|.*4096)""",
            ),
            Rule(
                id = "CRYPTO_007",
                name = "Static IV for Encryption",
                description = "Initialization vector (IV) is hardcoded or reused",
                severity = Severity.HIGH,
                cwe = 329,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """IvParameterSpec\(.*["']\w+["']|iv\s*=\s*new byte\[\]""",
            ),
            Rule(
                id = "CRYPTO_008",
                name = "Insufficient PBKDF2 Iterations",
                description = "Password-based key derivation with weak iteration count",
                severity = Severity.HIGH,
                cwe = 916,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(PBKDF2|PBEKeySpec).*iterations?\s*=\s*([1-9]\d{0,3}|[1-9]\d{4})(?!.*[1-9]\d{5,})""",
            ),
            Rule(
                id = "CRYPTO_009",
                name = "Weak RSA Key Size",
                description = "RSA key smaller than 2048 bits",
                severity = Severity.HIGH,
                cwe = 326,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """KeyPairGenerator.*RSA.*initialize\((512|1024)""",
            ),
            Rule(
                id = "CRYPTO_010",
                name = "Missing Cipher Padding",
                description = "Block cipher without proper padding",
                severity = Severity.MEDIUM,
                cwe = 327,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """Cipher\.getInstance\(["']AES/(?!.*PKCS[57]Padding)""",
            ),
            Rule(
                id = "ENCODING_001",
                name = "Base64 for Encryption",
                description = "Using Base64 encoding as encryption",
                severity = Severity.HIGH,
                cwe = 327,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(password|secret|token).*Base64\.encode""",
            ),
            Rule(
                id = "ENCODING_002",
                name = "URL Encoding for Security",
                description = "Relying on URL encoding for input sanitization",
                severity = Severity.MEDIUM,
                cwe = 116,
                owasp = "A03:2021 - Injection",
                pattern = """URLEncoder\.encode.*(?!.*HTMLEscape|.*sanitize)""",
            ),
            Rule(
                id = "HASH_001",
                name = "Password Hashing Without Salt",
                description = "Hashing passwords without unique salt",
                severity = Severity.CRITICAL,
                cwe = 759,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """(hashPassword|passwordHash).*digest\((?!.*salt)""",
            ),
            
            // Network & Protocol Security (7 rules)
            Rule(
                id = "NET_001",
                name = "Insecure FTP Usage",
                description = "Using FTP instead of SFTP/FTPS",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """FTPClient|ftp://(?!.*sftp|.*ftps)""",
            ),
            Rule(
                id = "NET_002",
                name = "Cleartext SMTP",
                description = "Sending email without TLS/SSL",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """mail\.smtp(?!.*starttls|.*ssl)""",
            ),
            Rule(
                id = "NET_003",
                name = "DNS Rebinding Vulnerability",
                description = "No hostname validation for HTTP requests",
                severity = Severity.MEDIUM,
                cwe = 350,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """HttpClient(?!.*HostnameVerifier|.*checkHostname)""",
            ),
            Rule(
                id = "NET_004",
                name = "HTTP Proxy Without Authentication",
                description = "Using proxy without credentials",
                severity = Severity.MEDIUM,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """Proxy\((?!.*Authenticator|.*credentials)""",
            ),
            Rule(
                id = "NET_005",
                name = "Server Hostname Not Verified",
                description = "TLS connection without hostname verification",
                severity = Severity.HIGH,
                cwe = 297,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """setHostnameVerifier.*ALLOW_ALL_HOSTNAME_VERIFIER""",
            ),
            Rule(
                id = "NET_006",
                name = "Insecure WebSocket Connection",
                description = "Using ws:// instead of wss://",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """ws://(?!wss://)""",
            ),
            Rule(
                id = "NET_007",
                name = "Socket Without Timeout",
                description = "Network socket without read/connect timeout",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(Socket|ServerSocket)\((?!.*setSoTimeout)""",
            ),
            
            // Business Logic & Authorization (5 rules)
            Rule(
                id = "AUTHZ_001",
                name = "Missing Row-Level Security",
                description = "Database query without tenant/user filtering",
                severity = Severity.HIGH,
                cwe = 639,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """findAll\(\)(?!.*currentUser|.*tenantId|.*@Filter)""",
            ),
            Rule(
                id = "AUTHZ_002",
                name = "Privilege Escalation Risk",
                description = "User can modify their own role/permissions",
                severity = Severity.CRITICAL,
                cwe = 269,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(setRole|setPermissions|grantAuthority).*currentUser""",
            ),
            Rule(
                id = "AUTHZ_003",
                name = "Horizontal Authorization Bypass",
                description = "No ownership check before resource access",
                severity = Severity.HIGH,
                cwe = 639,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(findById|getById).*@PathVariable(?!.*userId|.*ownerId)""",
            ),
            Rule(
                id = "BUSINESS_001",
                name = "Price Manipulation Risk",
                description = "Price/amount from client without validation",
                severity = Severity.CRITICAL,
                cwe = 472,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(price|amount|total).*@RequestBody(?!.*validatePrice|.*@Min)""",
            ),
            Rule(
                id = "BUSINESS_002",
                name = "Race Condition in Financial Transaction",
                description = "Non-atomic balance update",
                severity = Severity.HIGH,
                cwe = 362,
                owasp = "A04:2021 - Insecure Design",
                pattern = """balance.*=.*balance\s*[+-](?!.*synchronized|.*@Lock)""",
            ),
            
            // Modern Framework Security (React, Angular, Vue) (8 rules)
            Rule(
                id = "REACT_001",
                name = "React State Mutation",
                description = "Direct state mutation bypassing setState",
                severity = Severity.MEDIUM,
                cwe = 662,
                owasp = "A04:2021 - Insecure Design",
                pattern = """this\.state\.\w+\s*=(?!.*setState)""",
            ),
            Rule(
                id = "REACT_002",
                name = "Unvalidated Props in React",
                description = "Props used without PropTypes or TypeScript validation",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """props\.\w+.*(?!PropTypes|interface.*Props)""",
            ),
            Rule(
                id = "REACT_003",
                name = "React Hook Dependency Missing",
                description = "useEffect with missing dependency causing stale closure",
                severity = Severity.LOW,
                cwe = 1188,
                owasp = "A04:2021 - Insecure Design",
                pattern = """useEffect\(.*\[\](?!.*exhaustive-deps)""",
            ),
            Rule(
                id = "ANGULAR_001",
                name = "Angular Template Injection",
                description = "User input bound without sanitization in Angular template",
                severity = Severity.HIGH,
                cwe = 79,
                owasp = "A03:2021 - Injection",
                pattern = """\[innerHTML\]=["'].*\{\{(?!.*DomSanitizer)""",
            ),
            Rule(
                id = "ANGULAR_002",
                name = "Angular HTTP Without Interceptor",
                description = "HTTP requests without authentication interceptor",
                severity = Severity.MEDIUM,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """HttpClient(?!.*HttpInterceptor|.*interceptor)""",
            ),
            Rule(
                id = "VUE_001",
                name = "Vue v-html XSS Risk",
                description = "Using v-html with unsanitized user input",
                severity = Severity.HIGH,
                cwe = 79,
                owasp = "A03:2021 - Injection",
                pattern = """v-html=["'].*\{\{(?!.*sanitize|.*DOMPurify)""",
            ),
            Rule(
                id = "VUE_002",
                name = "Vue Prop Validation Missing",
                description = "Component prop without type validation",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """props:\s*\[\s*['"](?!.*type:|.*validator:)""",
            ),
            Rule(
                id = "NEXTJS_001",
                name = "Next.js Insecure API Route",
                description = "API route without authentication check",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """export\s+default.*handler.*req.*res(?!.*auth|.*session)""",
            ),
            
            // Serverless & Cloud Native (10 rules)
            Rule(
                id = "LAMBDA_001",
                name = "AWS Lambda Timeout Too High",
                description = "Lambda function with excessive timeout",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """timeout:\s*([6-9]\d{2}|[1-9]\d{3,})""",
            ),
            Rule(
                id = "LAMBDA_002",
                name = "Lambda Cold Start Credentials",
                description = "Fetching credentials on every invocation",
                severity = Severity.MEDIUM,
                cwe = 405,
                owasp = "A04:2021 - Insecure Design",
                pattern = """handler.*getSecret|getParameter(?!.*global|.*cache)""",
            ),
            Rule(
                id = "LAMBDA_003",
                name = "Lambda Overprivileged IAM Role",
                description = "Lambda with * permissions",
                severity = Severity.HIGH,
                cwe = 269,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """Action:\s*\*|Resource:\s*\*(?!.*Condition)""",
            ),
            Rule(
                id = "LAMBDA_004",
                name = "Lambda Environment Variable Secrets",
                description = "Secrets in Lambda environment variables",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """Environment:.*Variables:.*API_KEY|PASSWORD|SECRET""",
            ),
            Rule(
                id = "SERVERLESS_001",
                name = "Serverless Function Without VPC",
                description = "Function accessing private resources without VPC",
                severity = Severity.MEDIUM,
                cwe = 923,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """functions:(?!.*vpc:|.*vpcConfig:).*rds|elasticache""",
            ),
            Rule(
                id = "CLOUDFORMATION_001",
                name = "CloudFormation Hardcoded Secrets",
                description = "Secrets directly in CloudFormation template",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(MasterUserPassword|Password|SecretString):\s*['"]\w{8,}['"]""",
            ),
            Rule(
                id = "TERRAFORM_001",
                name = "Terraform State Contains Secrets",
                description = "Sensitive data in Terraform state file",
                severity = Severity.CRITICAL,
                cwe = 312,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """sensitive\s*=\s*false.*password|secret|key""",
            ),
            Rule(
                id = "TERRAFORM_002",
                name = "Terraform S3 Backend Without Encryption",
                description = "S3 backend for state without encryption",
                severity = Severity.HIGH,
                cwe = 311,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """backend\s+"s3"(?!.*encrypt\s*=\s*true)""",
            ),
            Rule(
                id = "SAM_001",
                name = "AWS SAM Missing Tracing",
                description = "SAM function without X-Ray tracing",
                severity = Severity.LOW,
                cwe = 778,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """AWS::Serverless::Function(?!.*Tracing:|.*Active)""",
            ),
            Rule(
                id = "APIGATEWAY_001",
                name = "API Gateway Without Throttling",
                description = "API Gateway without rate limiting",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """AWS::ApiGateway::RestApi(?!.*throttle|.*rateLimit)""",
            ),
            
            // Container & Orchestration Advanced (8 rules)
            Rule(
                id = "DOCKER_002",
                name = "Dockerfile Secrets in ENV",
                description = "Secrets passed as ENV variables",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """ENV\s+(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+""",
            ),
            Rule(
                id = "DOCKER_003",
                name = "Dockerfile COPY Without Chown",
                description = "Files copied with root ownership",
                severity = Severity.MEDIUM,
                cwe = 732,
                owasp = "A04:2021 - Insecure Design",
                pattern = """COPY(?!.*--chown).*\s+/""",
            ),
            Rule(
                id = "DOCKER_004",
                name = "Dockerfile Health Check Missing",
                description = "Container without health check",
                severity = Severity.LOW,
                cwe = 1188,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """FROM\s+\w+(?!.*HEALTHCHECK)""",
            ),
            Rule(
                id = "K8S_003",
                name = "Kubernetes NetworkPolicy Missing",
                description = "Namespace without network policy",
                severity = Severity.MEDIUM,
                cwe = 923,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """kind:\s*Namespace(?!.*NetworkPolicy)""",
            ),
            Rule(
                id = "K8S_004",
                name = "Kubernetes Resource Limits Missing",
                description = "Pod without CPU/memory limits",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """kind:\s*Pod(?!.*resources:.*limits:)""",
            ),
            Rule(
                id = "K8S_005",
                name = "Kubernetes Privileged Container",
                description = "Container running with privileged flag",
                severity = Severity.CRITICAL,
                cwe = 250,
                owasp = "A04:2021 - Insecure Design",
                pattern = """privileged:\s*true""",
            ),
            Rule(
                id = "HELM_001",
                name = "Helm Chart Default Values Secrets",
                description = "Hardcoded secrets in values.yaml",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(password|secret|key):\s*['"]\w{8,}['"]""",
            ),
            Rule(
                id = "ISTIO_001",
                name = "Istio mTLS Permissive Mode",
                description = "Service mesh in permissive mode allowing plaintext",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """mode:\s*PERMISSIVE""",
            ),
            
            // Database & ORM Advanced (8 rules)
            Rule(
                id = "PRISMA_001",
                name = "Prisma Raw Query Injection",
                description = "Prisma raw query with string interpolation",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """prisma\.queryRaw.*\+\s*\w+""",
            ),
            Rule(
                id = "SEQUELIZE_001",
                name = "Sequelize Raw Query Injection",
                description = "Sequelize query with unsafe replacements",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """sequelize\.query.*\+\s*\w+(?!.*replacements)""",
            ),
            Rule(
                id = "TYPEORM_001",
                name = "TypeORM Query Builder Injection",
                description = "TypeORM using string concatenation in where clause",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """\.where\(.*\+\s*\w+(?!.*parameters)""",
            ),
            Rule(
                id = "MONGODB_001",
                name = "MongoDB Injection via where",
                description = "MongoDB where operator with user input",
                severity = Severity.HIGH,
                cwe = 943,
                owasp = "A03:2021 - Injection",
                pattern = """where:.*\+\s*\w+""",
            ),
            Rule(
                id = "ELASTICSEARCH_001",
                name = "Elasticsearch Query Injection",
                description = "Elasticsearch query with unsanitized input",
                severity = Severity.HIGH,
                cwe = 943,
                owasp = "A03:2021 - Injection",
                pattern = """query.*query_string.*query:.*\+""",
            ),
            Rule(
                id = "CASSANDRA_001",
                name = "Cassandra CQL Injection",
                description = "Cassandra query with string concatenation",
                severity = Severity.CRITICAL,
                cwe = 89,
                owasp = "A03:2021 - Injection",
                pattern = """session\.execute\(.*\+\s*\w+""",
            ),
            Rule(
                id = "DYNAMODB_001",
                name = "DynamoDB Missing Encryption",
                description = "DynamoDB table without encryption at rest",
                severity = Severity.HIGH,
                cwe = 311,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """AWS::DynamoDB::Table(?!.*SSESpecification|.*Enabled.*true)""",
            ),
            Rule(
                id = "FIRESTORE_001",
                name = "Firestore Insecure Rules",
                description = "Firestore rules allowing unrestricted access",
                severity = Severity.CRITICAL,
                cwe = 306,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """allow\s+(read|write):\s*if\s+true""",
            ),
            
            // Testing & CI/CD Advanced (6 rules)
            Rule(
                id = "TEST_001",
                name = "Hardcoded Test Credentials",
                description = "Real credentials in test files",
                severity = Severity.HIGH,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """(test|spec).*password\s*=\s*['"]\w{8,}['"]""",
            ),
            Rule(
                id = "GITHUB_001",
                name = "GitHub Actions Secrets Exposure",
                description = "Secrets logged or echoed in workflow",
                severity = Severity.CRITICAL,
                cwe = 532,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """echo.*\$\{\{\s*secrets\.""",
            ),
            Rule(
                id = "GITHUB_002",
                name = "GitHub Actions Pull Request Target",
                description = "Dangerous pull_request_target trigger",
                severity = Severity.HIGH,
                cwe = 94,
                owasp = "A03:2021 - Injection",
                pattern = """on:.*pull_request_target(?!.*if:.*github\.event\.pull_request\.head\.repo\.full_name)""",
            ),
            Rule(
                id = "GITLAB_001",
                name = "GitLab CI Unmasked Variables",
                description = "Sensitive variables not marked as masked",
                severity = Severity.HIGH,
                cwe = 532,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """variables:.*PASSWORD|SECRET(?!.*masked:\s*true)""",
            ),
            Rule(
                id = "JENKINS_001",
                name = "Jenkins Plaintext Credentials",
                description = "Credentials stored in plaintext",
                severity = Severity.CRITICAL,
                cwe = 522,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """credentials\(.*password.*\)(?!.*withCredentials)""",
            ),
            Rule(
                id = "SONAR_001",
                name = "SonarQube Disabled Rule",
                description = "Security rule disabled without justification",
                severity = Severity.MEDIUM,
                cwe = 1188,
                owasp = "A04:2021 - Insecure Design",
                pattern = """NOSONAR|squid:S\d+.*off(?!.*justification)""",
            ),
            
            // Monitoring & Observability (6 rules)
            Rule(
                id = "DATADOG_001",
                name = "Datadog API Key Exposed",
                description = "Datadog API key in source code",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """DD_API_KEY.*=.*['"]\w{32}['"]""",
            ),
            Rule(
                id = "NEWRELIC_001",
                name = "New Relic License Key Exposed",
                description = "New Relic license key in code",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """NEW_RELIC_LICENSE_KEY.*=.*['"]\w{40}['"]""",
            ),
            Rule(
                id = "SENTRY_001",
                name = "Sentry DSN in Public Code",
                description = "Sentry DSN exposed in frontend code",
                severity = Severity.MEDIUM,
                cwe = 200,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """https://\w+@\w+\.ingest\.sentry\.io""",
            ),
            Rule(
                id = "PROMETHEUS_001",
                name = "Prometheus Metrics Exposure",
                description = "Sensitive business metrics exposed",
                severity = Severity.MEDIUM,
                cwe = 200,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """/metrics(?!.*BasicAuth|.*BearerToken)""",
            ),
            Rule(
                id = "GRAFANA_001",
                name = "Grafana Anonymous Access",
                description = "Grafana dashboard with anonymous access",
                severity = Severity.MEDIUM,
                cwe = 306,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """anonymous:\s*enabled:\s*true""",
            ),
            Rule(
                id = "ELASTIC_001",
                name = "Elasticsearch Open to Internet",
                description = "Elasticsearch without authentication on public IP",
                severity = Severity.CRITICAL,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """http\.host:\s*0\.0\.0\.0(?!.*xpack\.security\.enabled)""",
            ),
            
            // API Security Advanced (12 rules)
            Rule(
                id = "API_ADV_001",
                name = "API Key in Query Parameter",
                description = "Sensitive API key passed in URL query string",
                severity = Severity.HIGH,
                cwe = 598,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """(api_key|apiKey|api-key)=.*\?""",
            ),
            Rule(
                id = "API_ADV_002",
                name = "No API Rate Limiting",
                description = "API endpoint without rate limiting",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@(Get|Post|Put|Delete)Mapping(?!.*@RateLimit|.*RateLimiter)""",
            ),
            Rule(
                id = "API_ADV_003",
                name = "Missing API Versioning",
                description = "API endpoint without version prefix",
                severity = Severity.LOW,
                cwe = 1188,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@RequestMapping\(['"]/(?!api/v\d+)""",
            ),
            Rule(
                id = "API_004",
                name = "Unbounded API Response",
                description = "API returns all records without pagination",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """findAll\(\)(?!.*Pageable|.*PageRequest)""",
            ),
            Rule(
                id = "API_005",
                name = "API CORS Wildcard",
                description = "CORS allowing all origins",
                severity = Severity.HIGH,
                cwe = 942,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """Access-Control-Allow-Origin:\s*\*""",
            ),
            Rule(
                id = "API_006",
                name = "Mass Assignment Vulnerability",
                description = "Binding request directly to entity without DTO",
                severity = Severity.HIGH,
                cwe = 915,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@RequestBody.*@Entity""",
            ),
            Rule(
                id = "API_007",
                name = "API Error Message Leaking Info",
                description = "Detailed error messages exposed to client",
                severity = Severity.MEDIUM,
                cwe = 209,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """catch.*\.getMessage\(\).*return|response\.send\(error\)""",
            ),
            Rule(
                id = "API_008",
                name = "Missing API Input Size Limit",
                description = "No maximum size validation on request body",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@RequestBody(?!.*@Size|.*maxSize)""",
            ),
            Rule(
                id = "API_009",
                name = "API Without HTTPS Enforcement",
                description = "API not enforcing HTTPS connections",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """@RestController(?!.*requiresSecure|.*HTTPS)""",
            ),
            Rule(
                id = "API_010",
                name = "Insecure API Token Storage",
                description = "API tokens stored in localStorage",
                severity = Severity.HIGH,
                cwe = 922,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """localStorage\.setItem.*token|apiKey""",
            ),
            Rule(
                id = "API_011",
                name = "API Endpoint Enumeration",
                description = "Sequential IDs allowing resource enumeration",
                severity = Severity.MEDIUM,
                cwe = 639,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """@PathVariable.*Long\s+id(?!.*UUID)""",
            ),
            Rule(
                id = "API_012",
                name = "API Without Timeout",
                description = "API client without request timeout",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """RestTemplate\((?!.*timeout|.*connectionTimeout)""",
            ),
            
            // Session Management (8 rules)
            Rule(
                id = "SESSION_ADV_001",
                name = "Session Fixation Vulnerability",
                description = "Session ID not regenerated after login",
                severity = Severity.HIGH,
                cwe = 384,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """login.*session(?!.*regenerateId|.*invalidate)""",
            ),
            Rule(
                id = "SESSION_002",
                name = "Insecure Session Cookie",
                description = "Session cookie without Secure and HttpOnly flags",
                severity = Severity.HIGH,
                cwe = 614,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """setMaxAge(?!.*setSecure.*setHttpOnly)""",
            ),
            Rule(
                id = "SESSION_003",
                name = "Session Timeout Too Long",
                description = "Session timeout exceeds 30 minutes",
                severity = Severity.MEDIUM,
                cwe = 613,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """session\.timeout.*([3-9]\d{2,}|[2-9]\d{3,})""",
            ),
            Rule(
                id = "SESSION_004",
                name = "Session ID in URL",
                description = "Session identifier exposed in URL",
                severity = Severity.HIGH,
                cwe = 598,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """jsessionid|sessionid.*\?""",
            ),
            Rule(
                id = "SESSION_005",
                name = "Predictable Session ID",
                description = "Session ID using weak random generator",
                severity = Severity.CRITICAL,
                cwe = 330,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """sessionId.*=.*Math\.random|new Date\(\)\.getTime""",
            ),
            Rule(
                id = "SESSION_006",
                name = "Concurrent Session Not Limited",
                description = "No limit on concurrent sessions per user",
                severity = Severity.MEDIUM,
                cwe = 645,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """SessionManagement(?!.*maximumSessions)""",
            ),
            Rule(
                id = "SESSION_007",
                name = "Session Data in Client Side",
                description = "Storing session data in client-side storage",
                severity = Severity.HIGH,
                cwe = 922,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """sessionStorage\.setItem.*user|userId|role""",
            ),
            Rule(
                id = "SESSION_008",
                name = "No Session Invalidation on Logout",
                description = "Session not properly destroyed on logout",
                severity = Severity.HIGH,
                cwe = 613,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """logout.*(?!session\.invalidate|session\.destroy)""",
            ),
            
            // Input Validation Advanced (10 rules)
            Rule(
                id = "INPUT_ADV_001",
                name = "Regex DoS (ReDoS)",
                description = "Regex with exponential backtracking",
                severity = Severity.HIGH,
                cwe = 1333,
                owasp = "A04:2021 - Insecure Design",
                pattern = """\(.*\+.*\)\+|\(.*\*.*\)\*""",
            ),
            Rule(
                id = "INPUT_002",
                name = "User Input in Reflection",
                description = "Using user input in reflection API",
                severity = Severity.CRITICAL,
                cwe = 470,
                owasp = "A03:2021 - Injection",
                pattern = """Class\.forName.*\+|newInstance.*\+""",
            ),
            Rule(
                id = "INPUT_003",
                name = "Integer Overflow Risk",
                description = "Arithmetic operation without overflow check",
                severity = Severity.MEDIUM,
                cwe = 190,
                owasp = "A04:2021 - Insecure Design",
                pattern = """int.*\+.*(?!Math\.addExact|.*overflow)""",
            ),
            Rule(
                id = "INPUT_004",
                name = "Array Index Without Bounds Check",
                description = "Array access without validating index",
                severity = Severity.MEDIUM,
                cwe = 129,
                owasp = "A04:2021 - Insecure Design",
                pattern = """\[\s*\w+\s*\](?!.*length|.*size)""",
            ),
            Rule(
                id = "INPUT_005",
                name = "Email Validation Weak",
                description = "Weak email validation regex",
                severity = Severity.LOW,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """@.*\..*(?!.*RFC5322)""",
            ),
            Rule(
                id = "INPUT_006",
                name = "Phone Number Without Sanitization",
                description = "Phone number accepted without format validation",
                severity = Severity.LOW,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """phone.*@RequestParam(?!.*@Pattern)""",
            ),
            Rule(
                id = "INPUT_007",
                name = "Date Input Without Validation",
                description = "Date parameter without format validation",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """date.*String(?!.*DateTimeFormatter|.*@DateTimeFormat)""",
            ),
            Rule(
                id = "INPUT_008",
                name = "URL Validation Missing",
                description = "User-provided URL without validation",
                severity = Severity.HIGH,
                cwe = 601,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """URL\(.*\+(?!.*isValidUrl|.*whitelist)""",
            ),
            Rule(
                id = "INPUT_009",
                name = "Filename Not Sanitized",
                description = "User-provided filename without sanitization",
                severity = Severity.HIGH,
                cwe = 22,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """new File\(.*\+(?!.*sanitize|.*basename)""",
            ),
            Rule(
                id = "INPUT_010",
                name = "Content Type Not Validated",
                description = "File content type trusted from user input",
                severity = Severity.HIGH,
                cwe = 434,
                owasp = "A04:2021 - Insecure Design",
                pattern = """getContentType\(\)(?!.*whitelist|.*ALLOWED_TYPES)""",
            ),
            
            // Memory & Performance (8 rules)
            Rule(
                id = "PERF_001",
                name = "N+1 Query Problem",
                description = "Lazy loading causing N+1 queries",
                severity = Severity.MEDIUM,
                cwe = 1050,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@OneToMany.*fetch\s*=\s*FetchType\.LAZY(?!.*@BatchSize)""",
            ),
            Rule(
                id = "PERF_002",
                name = "Large Object in Session",
                description = "Storing large objects in HTTP session",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """session\.setAttribute.*List|Collection(?!.*size)""",
            ),
            Rule(
                id = "PERF_003",
                name = "String Concatenation in Loop",
                description = "String concatenation in loop causing memory issues",
                severity = Severity.LOW,
                cwe = 1050,
                owasp = "A04:2021 - Insecure Design",
                pattern = """(for|while).*\+\s*=\s*["'](?!.*StringBuilder)""",
            ),
            Rule(
                id = "PERF_004",
                name = "Unbounded Thread Pool",
                description = "Thread pool without maximum size",
                severity = Severity.MEDIUM,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """Executors\.newCachedThreadPool\(\)""",
            ),
            Rule(
                id = "PERF_005",
                name = "Resource Leak in Stream",
                description = "Stream not properly closed",
                severity = Severity.MEDIUM,
                cwe = 772,
                owasp = "A04:2021 - Insecure Design",
                pattern = """Files\.lines|BufferedReader(?!.*try-with-resources)""",
            ),
            Rule(
                id = "PERF_006",
                name = "Database Connection Not Pooled",
                description = "Creating new connection for each request",
                severity = Severity.HIGH,
                cwe = 405,
                owasp = "A04:2021 - Insecure Design",
                pattern = """DriverManager\.getConnection(?!.*pool)""",
            ),
            Rule(
                id = "PERF_007",
                name = "Caching Sensitive Data",
                description = "Caching sensitive information",
                severity = Severity.MEDIUM,
                cwe = 524,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """@Cacheable.*password|secret|token""",
            ),
            Rule(
                id = "PERF_008",
                name = "Large IN Clause in SQL",
                description = "IN clause with unbounded parameters",
                severity = Severity.MEDIUM,
                cwe = 1050,
                owasp = "A04:2021 - Insecure Design",
                pattern = """IN\s*\([^)]{100,}\)""",
            ),
            
            // GraphQL Security (6 rules)
            Rule(
                id = "GRAPHQL_ADV_001",
                name = "GraphQL Query Depth Not Limited",
                description = "GraphQL without query depth limiting",
                severity = Severity.HIGH,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@(Query|Mutation)(?!.*@MaxQueryDepth|.*depthLimit)""",
            ),
            Rule(
                id = "GRAPHQL_ADV_002",
                name = "GraphQL Introspection Enabled in Production",
                description = "GraphQL introspection not disabled in production",
                severity = Severity.MEDIUM,
                cwe = 200,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """introspection.*true|enableIntrospection.*true""",
            ),
            Rule(
                id = "GRAPHQL_ADV_003",
                name = "GraphQL Query Complexity Not Limited",
                description = "No complexity analysis on GraphQL queries",
                severity = Severity.HIGH,
                cwe = 400,
                owasp = "A04:2021 - Insecure Design",
                pattern = """GraphQLSchema(?!.*maxComplexity|.*complexityLimit)""",
            ),
            Rule(
                id = "GRAPHQL_004",
                name = "GraphQL Batch Query DoS",
                description = "No limit on batch query operations",
                severity = Severity.HIGH,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """operationName.*\[\](?!.*maxBatchSize)""",
            ),
            Rule(
                id = "GRAPHQL_005",
                name = "GraphQL Field Access Not Authorized",
                description = "GraphQL field without authorization check",
                severity = Severity.HIGH,
                cwe = 862,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """@Field(?!.*@Authorized|.*@PreAuthorize|.*@Secured)""",
            ),
            Rule(
                id = "GRAPHQL_006",
                name = "GraphQL Error Stack Trace Exposed",
                description = "GraphQL exposing detailed error messages",
                severity = Severity.MEDIUM,
                cwe = 209,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """GraphQLError.*printStackTrace|includeExceptionDetails.*true""",
            ),
            
            // OAuth & SSO Security (8 rules)
            Rule(
                id = "OAUTH_001",
                name = "OAuth State Parameter Missing",
                description = "OAuth flow without state parameter for CSRF protection",
                severity = Severity.HIGH,
                cwe = 352,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """oauth.*authorize(?!.*state=)""",
            ),
            Rule(
                id = "OAUTH_002",
                name = "OAuth Redirect URI Not Validated",
                description = "OAuth redirect URI without whitelist validation",
                severity = Severity.CRITICAL,
                cwe = 601,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """redirect_uri.*\+|redirect_uri.*concat(?!.*whitelist|.*ALLOWED)""",
            ),
            Rule(
                id = "OAUTH_003",
                name = "OAuth Token in URL Fragment",
                description = "OAuth implicit flow exposing token in URL",
                severity = Severity.HIGH,
                cwe = 598,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """response_type=token(?!.*response_type=code)""",
            ),
            Rule(
                id = "OAUTH_004",
                name = "OAuth Client Secret in Frontend",
                description = "OAuth client secret exposed in client-side code",
                severity = Severity.CRITICAL,
                cwe = 798,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """client_secret.*=.*['"]\w{20,}['"]""",
            ),
            Rule(
                id = "OAUTH_005",
                name = "JWT Not Verified",
                description = "JWT token accepted without signature verification",
                severity = Severity.CRITICAL,
                cwe = 347,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """decode.*JWT(?!.*verify|.*validateToken)""",
            ),
            Rule(
                id = "OAUTH_006",
                name = "JWT Algorithm None Accepted",
                description = "JWT accepting 'none' algorithm",
                severity = Severity.CRITICAL,
                cwe = 347,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """alg.*none|algorithm.*none""",
            ),
            Rule(
                id = "OAUTH_007",
                name = "SAML Response Not Validated",
                description = "SAML response without signature validation",
                severity = Severity.CRITICAL,
                cwe = 347,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """SAMLResponse(?!.*validateSignature|.*verifySignature)""",
            ),
            Rule(
                id = "OAUTH_008",
                name = "PKCE Not Used for OAuth",
                description = "OAuth flow without PKCE for mobile/SPA apps",
                severity = Severity.MEDIUM,
                cwe = 940,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """authorization_code(?!.*code_challenge|.*code_verifier)""",
            ),
            
            // gRPC & Protobuf Security (5 rules)
            Rule(
                id = "GRPC_001",
                name = "gRPC Without TLS",
                description = "gRPC service without TLS encryption",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """NewServer\((?!.*tls|.*credentials)""",
            ),
            Rule(
                id = "GRPC_002",
                name = "gRPC Without Authentication",
                description = "gRPC endpoint without authentication interceptor",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """@GrpcService(?!.*@PreAuthorize|.*interceptor)""",
            ),
            Rule(
                id = "GRPC_003",
                name = "Protobuf Message Size Not Limited",
                description = "No size limit on protobuf messages",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """proto3(?!.*max_size|.*MaxMessageSize)""",
            ),
            Rule(
                id = "GRPC_004",
                name = "gRPC Reflection Enabled in Production",
                description = "gRPC server reflection enabled",
                severity = Severity.LOW,
                cwe = 200,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """reflection\.Register|EnableReflection.*true""",
            ),
            Rule(
                id = "GRPC_005",
                name = "gRPC Error Details Exposed",
                description = "gRPC exposing internal error details",
                severity = Severity.MEDIUM,
                cwe = 209,
                owasp = "A09:2021 - Security Logging and Monitoring Failures",
                pattern = """Status\.INTERNAL.*Exception|\.withDescription\(e\.getMessage""",
            ),
            
            // WebSocket Security (6 rules)
            Rule(
                id = "WS_001",
                name = "WebSocket Without Origin Validation",
                description = "WebSocket accepting connections without origin check",
                severity = Severity.HIGH,
                cwe = 346,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """@ServerEndpoint(?!.*Configurator|.*checkOrigin)""",
            ),
            Rule(
                id = "WS_002",
                name = "WebSocket Without Authentication",
                description = "WebSocket endpoint without authentication",
                severity = Severity.HIGH,
                cwe = 306,
                owasp = "A07:2021 - Identification and Authentication Failures",
                pattern = """@OnOpen(?!.*Principal|.*authenticate)""",
            ),
            Rule(
                id = "WS_003",
                name = "WebSocket Message Size Not Limited",
                description = "No size limit on WebSocket messages",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """@OnMessage(?!.*maxMessageSize|.*@Size)""",
            ),
            Rule(
                id = "WS_004",
                name = "WebSocket Without Rate Limiting",
                description = "WebSocket without connection rate limiting",
                severity = Severity.MEDIUM,
                cwe = 770,
                owasp = "A04:2021 - Insecure Design",
                pattern = """WebSocketHandler(?!.*RateLimiter|.*throttle)""",
            ),
            Rule(
                id = "WS_005",
                name = "WebSocket Over Non-Secure Connection",
                description = "WebSocket using ws:// instead of wss://",
                severity = Severity.HIGH,
                cwe = 319,
                owasp = "A02:2021 - Cryptographic Failures",
                pattern = """ws://(?!.*wss://)""",
            ),
            Rule(
                id = "WS_006",
                name = "WebSocket CSRF Token Missing",
                description = "WebSocket handshake without CSRF token",
                severity = Severity.MEDIUM,
                cwe = 352,
                owasp = "A01:2021 - Broken Access Control",
                pattern = """HandshakeInterceptor(?!.*csrf|.*token)""",
            ),
            
            // Serialization Security (7 rules)
            Rule(
                id = "SERIAL_001",
                name = "Java Deserialization of Untrusted Data",
                description = "Deserializing data from untrusted source",
                severity = Severity.CRITICAL,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """ObjectInputStream.*readObject\(\)""",
            ),
            Rule(
                id = "SERIAL_002",
                name = "XML External Entity (XXE) Risk",
                description = "XML parser without XXE protection",
                severity = Severity.CRITICAL,
                cwe = 611,
                owasp = "A05:2021 - Security Misconfiguration",
                pattern = """DocumentBuilderFactory(?!.*setFeature.*XMLConstants\.FEATURE_SECURE_PROCESSING)""",
            ),
            Rule(
                id = "SERIAL_003",
                name = "YAML Deserialization Vulnerability",
                description = "YAML loading with unsafe constructor",
                severity = Severity.CRITICAL,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """Yaml\(\)\.load(?!.*SafeConstructor)""",
            ),
            Rule(
                id = "SERIAL_004",
                name = "Jackson Polymorphic Deserialization",
                description = "Jackson with default typing enabled",
                severity = Severity.HIGH,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """enableDefaultTyping\(\)|@JsonTypeInfo.*use\s*=\s*Id\.CLASS""",
            ),
            Rule(
                id = "SERIAL_005",
                name = "Pickle Deserialization in Python",
                description = "Unsafe pickle load from untrusted source",
                severity = Severity.CRITICAL,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """pickle\.loads?\((?!.*safe)""",
            ),
            Rule(
                id = "SERIAL_006",
                name = "PHP Unserialize on User Input",
                description = "PHP unserialize on untrusted data",
                severity = Severity.CRITICAL,
                cwe = 502,
                owasp = "A08:2021 - Software and Data Integrity Failures",
                pattern = """unserialize\(.*GET|POST|REQUEST|COOKIE""",
            ),
            Rule(
                id = "SERIAL_007",
                name = "Protobuf Without Schema Validation",
                description = "Protobuf deserialization without schema check",
                severity = Severity.MEDIUM,
                cwe = 20,
                owasp = "A03:2021 - Injection",
                pattern = """parseFrom\((?!.*validate|.*schema)""",
            )
        )
    }
    
    override fun close() {
        executorService.shutdown()
    }
    
    companion object {
        private val LOG = com.intellij.openapi.diagnostic.Logger.getInstance(VulnSpeedEngine::class.java)

        fun getInstance(project: Project): VulnSpeedEngine {
            return ApplicationManager.getApplication().getService(VulnSpeedEngine::class.java)
        }
    }
}
