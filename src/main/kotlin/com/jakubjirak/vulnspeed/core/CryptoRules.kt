/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
// vulnspeed-ignore-file: rule names, descriptions and patterns quote the very code they detect.
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.core.RuleCatalog.A02
import com.jakubjirak.vulnspeed.core.RuleCatalog.A05
import com.jakubjirak.vulnspeed.core.RuleCatalog.A07
import com.jakubjirak.vulnspeed.core.RuleCatalog.A08
import com.jakubjirak.vulnspeed.core.RuleCatalog.A09
import com.jakubjirak.vulnspeed.core.RuleCatalog.JS
import com.jakubjirak.vulnspeed.core.RuleCatalog.JVM
import com.jakubjirak.vulnspeed.core.RuleCatalog.MANAGED
import com.jakubjirak.vulnspeed.core.SourceLanguages.DOCKERFILE
import com.jakubjirak.vulnspeed.core.SourceLanguages.PROPERTIES
import com.jakubjirak.vulnspeed.core.SourceLanguages.PYTHON
import com.jakubjirak.vulnspeed.core.SourceLanguages.YAML
import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity

/**
 * Deserialization, cryptography and credential rules.
 * Positive / negative samples: `rule-samples.txt` (tests).
 */
internal object CryptoRules {
    val RULES: List<Rule> = listOf(
        Rule(
            id = "DESER_001",
            name = "Insecure Deserialization - ObjectInputStream",
            description = "Java native deserialization without an ObjectInputFilter can instantiate attacker-chosen classes",
            severity = Severity.HIGH, cwe = 502, owasp = A08,
            languages = JVM,
            excludeIfFileContains = """ObjectInputFilter|ValidatingObjectInputStream|resolveClass""",
            skipTestFiles = true,
            pattern = """\bnew\s+ObjectInputStream\s*\(""",
        ),
        Rule(
            id = "DESER_002",
            name = "Insecure Deserialization - PyYAML load",
            description = "yaml.load / yaml.unsafe_load without SafeLoader can construct arbitrary Python objects",
            severity = Severity.HIGH, cwe = 502, owasp = A08,
            languages = setOf(PYTHON),
            pattern = """\byaml\.(?:unsafe_load(?:_all)?|load(?:_all)?)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)""",
        ),
        Rule(
            id = "SERIAL_003",
            name = "SnakeYAML Without SafeConstructor",
            description = "new Yaml() loads documents with the default constructor (unsafe before SnakeYAML 2.0)",
            severity = Severity.MEDIUM, cwe = 502, owasp = A08,
            languages = JVM,
            requiresInFile = """\.load(?:As|All)?\s*\(""",
            excludeIfFileContains = """SafeConstructor""",
            pattern = """\bnew\s+Yaml\s*\(\s*\)""",
        ),
        Rule(
            id = "PYTHON_001",
            name = "Python Unsafe Deserialization (pickle and friends)",
            description = "pickle / marshal / shelve / dill / jsonpickle execute code while loading untrusted data",
            severity = Severity.HIGH, cwe = 502, owasp = A08,
            languages = setOf(PYTHON),
            pattern = """\b(?:pickle|cPickle|_pickle|dill|marshal)\.(?:loads?|""" +
                """Unpickler)\s*\(|\bshelve\.open\s*\(|\bjsonpickle\.decode\s*\(""",
        ),
        Rule(
            id = "SERIAL_004",
            name = "Jackson Polymorphic Deserialization",
            description = "Default typing / class-name type ids let JSON input choose the class to instantiate",
            severity = Severity.HIGH, cwe = 502, owasp = A08,
            languages = JVM,
            pattern = """\b(?:enableDefaultTyping|activateDefaultTyping)\s*\(|""" +
                """\buse\s*=\s*(?:JsonTypeInfo\.)?Id\.(?:CLASS|MINIMAL_CLASS)\b""",
        ),
        Rule(
            id = "XXE_001",
            name = "XXE - XML Parser Without Hardening",
            description = "An XML parser factory is created in a file that never disables DOCTYPEs / external entities",
            severity = Severity.MEDIUM, cwe = 611, owasp = A05,
            languages = JVM,
            excludeIfFileContains = """disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|SUPPORT_DTD|""" +
                """IS_SUPPORTING_EXTERNAL_ENTITIES|external-general-entities|setExpandEntityReferences\(\s*false""",
            pattern = """\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|""" +
                """SchemaFactory|TransformerFactory)\.newInstance\s*\(|""" +
                """\bnew\s+(?:SAXReader|SAXBuilder)\s*\(""",
        ),
        Rule(
            id = "CRYPTO_001",
            name = "Weak Hash Algorithm - MD5/SHA-1",
            description = "MD5 / SHA-1 are broken for collision resistance; do not use them for signatures, passwords or integrity",
            severity = Severity.MEDIUM, cwe = 328, owasp = A02,
            languages = MANAGED,
            pattern = """MessageDigest\.getInstance\(\s*"(?:MD2|MD4|MD5|SHA-?1|SHA)"|""" +
                """\bhashlib\.(?:md5|sha1)\s*\((?![^)]*usedforsecurity\s*=\s*False)|\bhashlib\.new\(\s*["'](?:md5|sha1)["']|""" +
                """\bcrypto\.createHash\(\s*["'](?:md5|sha1)["']|\bDigestUtils\.(?:md5|""" +
                """sha1|sha)(?:Hex)?\s*\(|\b(?:md5|sha1)\.(?:New|Sum)\(""",
        ),
        Rule(
            id = "CRYPTO_002",
            name = "Weak Cipher - DES/3DES/RC4/Blowfish or ECB Mode",
            description = "Deprecated ciphers or ECB mode (including Java's default \"AES\") leak plaintext structure",
            severity = Severity.HIGH, cwe = 327, owasp = A02,
            languages = MANAGED,
            pattern = """Cipher\.getInstance\(\s*"(?:DES|DESede|TripleDES|3DES|RC2|""" +
                """RC4|ARCFOUR|Blowfish)\b|Cipher\.getInstance\(\s*"AES"\s*\)|""" +
                """"[A-Za-z0-9]+/ECB/|\bAES\.MODE_ECB\b|\b(?:DES|DES3|ARC2|ARC4|Blowfish)\.new\s*\(|\bmodes\.ECB\s*\(|""" +
                """\balgorithms\.(?:TripleDES|ARC4|Blowfish)\s*\(|createCipher(?:iv)?\(\s*["'](?i:des|des-ede3?|des-ede3-cbc|rc4|bf|""" +
                """aes-\d+-ecb)["']|\b(?:des|rc4)\.NewCipher\(""",
        ),
        Rule(
            id = "CRYPTO_003",
            name = "Hardcoded Cryptographic Key or IV",
            description = "A secret key or IV is built from a string literal in source code",
            severity = Severity.CRITICAL, cwe = 321, owasp = A02,
            languages = JVM,
            pattern = """\b(?:SecretKeySpec|IvParameterSpec)\s*\(\s*"[^"]*"\s*\.(?:getBytes|toByteArray)\s*\(""",
        ),
        Rule(
            id = "CRYPTO_004",
            name = "Insecure TLS/SSL Protocol Version",
            description = "SSLv3 / TLS 1.0 / TLS 1.1 are deprecated (RFC 8996)",
            severity = Severity.HIGH, cwe = 326, owasp = A02,
            languages = MANAGED,
            pattern = """SSLContext\.getInstance\(\s*"(?:SSL|SSLv2|SSLv3|TLSv1|""" +
                """TLSv1\.1)"|\bssl\.PROTOCOL_(?:SSLv2|SSLv3|TLSv1|TLSv1_1)\b|""" +
                """MinVersion\s*:\s*tls\.Version(?:SSL30|TLS10|TLS11)\b|secureProtocol\s*:\s*["'](?:SSLv3|TLSv1|TLSv1_1)_method|""" +
                """setEnabledProtocols\([^)]*"(?:SSLv3|TLSv1|TLSv1\.1)"""",
        ),
        Rule(
            id = "CRYPTO_005",
            name = "Certificate or Hostname Validation Disabled",
            description = "TLS certificate or hostname verification is switched off, enabling man-in-the-middle attacks",
            severity = Severity.HIGH, cwe = 295, owasp = A02,
            languages = MANAGED,
            skipTestFiles = true,
            pattern = """\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bNoopHostnameVerifier\b|\bTrustAllStrategy\b|\bInsecureSkipVerify\s*:\s*true|""" +
                """\brejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|\bssl\._create_unverified_context\b|""" +
                """\b(?:cert_reqs|verify_mode)\s*=\s*(?:ssl\.)?CERT_NONE\b|\bcheck_hostname\s*=\s*False|""" +
                """\b(?:requests|httpx|session|client)\.\w+\([^)]*\bverify\s*=\s*False|""" +
                """\bsetHostnameVerifier\s*\(\s*(?:\{\s*_\s*,\s*_\s*->\s*true|\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true)""",
        ),
        Rule(
            id = "CRYPTO_BASIC_001",
            name = "Insecure Random Number for a Security Value",
            description = "A token, password, salt or nonce is generated with a non-cryptographic random number generator",
            severity = Severity.MEDIUM, cwe = 338, owasp = A02,
            languages = MANAGED,
            skipTestFiles = true,
            pattern = """(?i:\b\w*(?:token|secret|passw(?:or)?d|nonce|salt|otp|session_?id|api_?key|csrf|reset_?code|""" +
                """verification_?code)\w*)\s*(?::\s*\w+\s*)?:?=\s*[^=;\n]*?(?:Math\.random\(|new\s+(?:java\.util\.)?Random\(|""" +
                """\brandom\.(?:random|randint|choice|choices|randrange|getrandbits|sample)\(|\brand\.(?:Intn?|Int63)\()""",
        ),
        Rule(
            id = "CRYPTO_006",
            name = "Weak RSA Key Size",
            description = "RSA keys shorter than 2048 bits are considered breakable",
            severity = Severity.HIGH, cwe = 326, owasp = A02,
            languages = MANAGED,
            pattern = """\.initialize\s*\(\s*(?:512|768|1024)\s*[,)]|\bkey_size\s*=\s*(?:512|768|1024)\b|""" +
                """\brsa\.GenerateKey\([^,]+,\s*(?:512|768|1024)\s*\)|\bmodulusLength\s*:\s*(?:512|768|1024)\b""",
        ),
        Rule(
            id = "CRYPTO_008",
            name = "Insufficient PBKDF2 Iterations",
            description = "PBKDF2 runs fewer than 10,000 iterations (OWASP recommends 600,000 for PBKDF2-HMAC-SHA256)",
            severity = Severity.MEDIUM, cwe = 916, owasp = A02,
            languages = JVM + JS + PYTHON,
            pattern = """\bPBEKeySpec\s*\([^,]+,[^,]+,\s*\d{1,4}\s*[,)]|\bpbkdf2_hmac\s*\([^,]+,[^,]+,[^,]+,\s*\d{1,4}\s*[,)]|""" +
                """\bpbkdf2(?:Sync)?\s*\([^,]+,[^,]+,\s*\d{1,4}\s*,|\bPBKDF2HMAC\([^)]*\biterations\s*=\s*\d{1,4}\b""",
        ),
        Rule(
            id = "JWT_001",
            name = "JWT Signature Verification Disabled",
            description = "A JWT is accepted without verifying its signature (alg=none or verification switched off)",
            severity = Severity.CRITICAL, cwe = 347, owasp = A02,
            languages = MANAGED,
            pattern = """\b(?:algorithms?|alg)\s*[=:]\s*\[?\s*["']none["']|\bjwt\.decode\([^)]*\bverify\s*=\s*False|""" +
                """["']verify_signature["']\s*:\s*False|\bparseUnsecuredClaims\s*\(|""" +
                """\bJwts\.parser\(\)(?:\.setSigningKey\([^)]*\))?\.parse\(""",
        ),
        Rule(
            id = "AUTH_001",
            name = "Hardcoded Credentials",
            description = "A password, secret or API key is assigned a string literal",
            severity = Severity.HIGH, cwe = 798, owasp = A07,
            languages = SourceLanguages.CODE,
            skipTestFiles = true,
            excludePattern = """[:=]\s*["'](?:(?i:\$\{|\{\{|<|%\(|%s|\*{3,}|x{3,}|changeme|change_me|password|passwd|secret|example|""" +
                """dummy|sample|placeholder|your[_-]|test|fake|redacted|null|none|undefined)|[A-Z][A-Z0-9_]{3,}["'])""",
            pattern = """(?i)\b(?:password|passwd|pwd|secret|secret_?key|api_?key|access_?token|auth_?token|client_?secret|""" +
                """private_?key)\b["']?\]?\s*(?::\s*\w+\??\s*)?[:=]\s*["'][^"'\s]{4,}["']""",
        ),
        Rule(
            id = "CONFIG_001",
            name = "Hardcoded Secret in Configuration",
            description = "A password, secret, token or key is stored in plain text in a YAML / .properties file",
            severity = Severity.HIGH, cwe = 798, owasp = A07,
            languages = setOf(YAML, PROPERTIES),
            skipTestFiles = true,
            excludePattern = """(?i)[=:]\s*["']?(?:changeme|change_me|password|secret|example|dummy|placeholder|xxx+|\*{3,}|none|null|""" +
                """true|false)["']?\s*$""",
            pattern = """^\s*(?:-\s*)?["']?[\w.-]*(?i:password|passwd|secret|api[-_]?key|access[-_]?key|client[-_]?secret|token)""" +
                """["']?\s*[=:]\s*["']?(?!\$\{|\{\{|<|%\(|\$[A-Za-z_]|ENC\(|!)[^\s"'#]{4,}""",
        ),
        Rule(
            id = "PCI_001",
            name = "Credit Card Number in Code",
            description = "A literal payment card number is stored in source code",
            severity = Severity.HIGH, cwe = 311, owasp = A02,
            languages = SourceLanguages.CODE,
            skipTestFiles = true,
            pattern = """(?i)\b(?:credit_?card(?:_?number)?|card_?number|cc_?num(?:ber)?|pan)\b\s*[:=]\s*["']\d{13,19}["']""",
        ),
        Rule(
            id = "DOCKER_002",
            name = "Secret Baked Into Docker Image",
            description = "ENV / ARG sets a secret value that is stored in the image layers and history",
            severity = Severity.HIGH, cwe = 798, owasp = A07,
            languages = setOf(DOCKERFILE),
            pattern = """^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)\w*""" +
                """(?:\s*=\s*|\s+)(?!\$)["']?[^\s"'$]{3,}""",
        ),
        Rule(
            id = "GDPR_003",
            name = "Password or Secret Written to Logs",
            description = "A password / secret / API key variable is passed to a logging call",
            severity = Severity.MEDIUM, cwe = 532, owasp = A09,
            languages = SourceLanguages.CODE,
            skipTestFiles = true,
            pattern = """\b(?:log|logger|LOG|LOGGER|console|logging|Log|Timber)\.(?:info|debug|warn|warning|error|trace|log|fine|""" +
                """[diwev])\s*\([^)]*(?:[+,]\s*|\$\{?|\{)\w*(?i:passw(?:or)?d|secret|api_?key)\w*\b""",
        ),
    )
}
