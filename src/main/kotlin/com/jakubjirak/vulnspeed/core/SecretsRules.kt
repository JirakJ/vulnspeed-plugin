/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.Rule
import com.jakubjirak.vulnspeed.model.Severity

/**
 * High-signal secret and credential detection rules (CWE-798).
 *
 * Each pattern targets a vendor-specific token format with a distinctive prefix,
 * so false-positive rates stay near zero — unlike generic entropy heuristics.
 */
object SecretsRules {

    private const val OWASP = "A07:2021 - Identification and Authentication Failures"

    val RULES: List<Rule> = listOf(
        Rule(
            id = "SECRET_AWS_001",
            name = "AWS Access Key ID",
            description = "Hardcoded AWS access key ID detected. Rotate the key and load credentials from the environment or AWS " +
                "Secrets Manager.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b""",
        ),
        Rule(
            id = "SECRET_GITHUB_001",
            name = "GitHub Token",
            description = "Hardcoded GitHub personal access / OAuth / app token detected. Revoke it and use a credential store.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bgh[pousr]_[A-Za-z0-9]{36,}\b""",
        ),
        Rule(
            id = "SECRET_GITLAB_001",
            name = "GitLab Personal Access Token",
            description = "Hardcoded GitLab personal access token detected. Revoke it and use CI/CD variables instead.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bglpat-[A-Za-z0-9_\-]{20,}\b""",
        ),
        Rule(
            id = "SECRET_SLACK_001",
            name = "Slack Token",
            description = "Hardcoded Slack bot/user/app token detected. Revoke it in the Slack admin console.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bxox[baprs]-[A-Za-z0-9\-]{10,}\b""",
        ),
        Rule(
            id = "SECRET_STRIPE_001",
            name = "Stripe Live Secret Key",
            description = "Hardcoded Stripe live secret/restricted key detected. Roll the key immediately in the Stripe dashboard.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\b[sr]k_live_[A-Za-z0-9]{20,}\b""",
        ),
        Rule(
            id = "SECRET_GOOGLE_001",
            name = "Google API Key",
            description = "Hardcoded Google API key detected. Restrict and rotate the key in Google Cloud Console.",
            severity = Severity.HIGH,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bAIza[0-9A-Za-z_\-]{35}\b""",
        ),
        Rule(
            id = "SECRET_PEM_001",
            name = "Private Key Material",
            description = "Private key block embedded in source. Move the key to a secure store and rotate it.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----""",
        ),
        Rule(
            id = "SECRET_NPM_001",
            name = "npm Access Token",
            description = "Hardcoded npm access token detected. Revoke it with `npm token revoke`.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bnpm_[A-Za-z0-9]{36}\b""",
        ),
        Rule(
            id = "SECRET_SENDGRID_001",
            name = "SendGrid API Key",
            description = "Hardcoded SendGrid API key detected. Delete it in SendGrid settings and use environment variables.",
            severity = Severity.CRITICAL,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b""",
        ),
        Rule(
            id = "SECRET_TWILIO_001",
            name = "Twilio API Key",
            description = "Hardcoded Twilio API key SID detected. Rotate it in the Twilio console.",
            severity = Severity.HIGH,
            cwe = 798,
            owasp = OWASP,
            pattern = """\bSK[0-9a-fA-F]{32}\b""",
        ),
        Rule(
            id = "SECRET_URL_001",
            name = "Credentials in URL",
            description = "URL contains embedded username:password credentials. Use a credential provider or config outside source " +
                "control.",
            severity = Severity.HIGH,
            cwe = 798,
            owasp = OWASP,
            pattern = """[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@'"]{1,64}:[^/\s:@'"]{1,128}@""",
        ),
        Rule(
            id = "SECRET_JWT_001",
            name = "Hardcoded JWT",
            description = "JSON Web Token literal embedded in source. Tokens in code leak via VCS history — issue them at runtime instead.",
            severity = Severity.MEDIUM,
            cwe = 798,
            owasp = OWASP,
            pattern = """\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}""",
        ),
    )
}
