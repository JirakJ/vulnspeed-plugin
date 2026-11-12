# VulnSpeed SAST

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) ![Version](https://img.shields.io/badge/version-2026.10.0-green)

> **Free & open source.** Since 2026.8.0 the plugin is completely free — every feature is unlocked for everyone, no license needed — and the source code is available under the Apache License 2.0.

Fast, low-noise static application security testing (SAST) for JetBrains IDEs and CI. VulnSpeed runs a curated set of line-level regex rules — each scoped to the languages and file types where it is meaningful — over Java, Kotlin, Python, JavaScript/TypeScript, Go, C/C++, Swift, Dockerfiles, YAML and `.properties` files, and maps every finding to CWE and the OWASP Top 10. It is a pattern scanner: it does not do data-flow or taint analysis, so it reports what a single line (plus a little file context) proves.

## Screenshots

| Inline detection in the editor | Security dashboard |
|---|---|
| ![Inline detection](docs/screenshots/01-inline-detection.png) | ![Dashboard](docs/screenshots/02-dashboard.png) |

| Secrets detection |
|---|
| ![Secrets](docs/screenshots/03-secrets-detection.png) |

## Features

- **84 precise rules + 12 secret rules** — injection (SQL, NoSQL, OS command, code, template, LDAP, XPath), XSS, SSRF, open redirect, path traversal / zip slip, unsafe deserialization, XXE, weak crypto / TLS / JWT verification, CSRF / CORS / cookie misconfiguration, container / Kubernetes / IAM misconfiguration and unbounded C string functions — see [Rules & precision](#rules--precision)
- **Real-time vulnerability detection** — annotators scan code as you type with inline severity highlighting for Java, Kotlin, Python, JavaScript, and TypeScript
- **Secrets detection** — 12 high-signal rules for AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid, Twilio, npm tokens, private keys, JWTs, and credentials in URLs (CWE-798)
- **Inline suppression** — `// vulnspeed-ignore` or `// vulnspeed-ignore: RULE_ID` accepts a finding in place; `vulnspeed-ignore-file` opts out a generated file
- **Shareable HTML report** — export the latest scan as a single self-contained HTML file with severity summary and CWE links
- **Scan Project / CLI file types** — Java, Kotlin, Python, JavaScript / TypeScript (`.js .mjs .cjs .jsx .ts .tsx`), Go, Rust, C/C++, Swift, `Dockerfile`, YAML and `.properties` (Rust currently gets only the secret and generic credential rules)
- **OWASP Top 10 mapping** — every rule carries a CWE id and an OWASP Top 10 (2021) category; coverage is pattern-based, so categories that need data-flow or runtime context (e.g. most broken access control) are covered only where a single line proves the issue
- **Remediation guidance** — every finding carries a fix suggestion with OWASP / CWE references
- **Scan file** — right-click in editor → "Scan File with VulnSpeed" for on-demand analysis
- **Scan on save** — optional per-project setting that re-scans a file whenever it is saved
- **Scan project** — right-click project folder → "Scan Project with VulnSpeed" for full project scanning
- **VulnSpeed tool window** — bottom panel displaying vulnerability list and statistics
- **Configurable settings** — toggle real-time scanning, set the max file size to scan, enable scan on save
- **Standalone CLI for CI** — `vulnspeed-cli-<version>.jar` (attached to every GitHub release) runs the same rules without an IDE: scan to findings JSON / SARIF, baseline compare and CVE enrichment, with exit codes for gating
- **Findings JSON export** — Tools → VulnSpeed → Export Findings JSON hands an IDE scan to the CLI

## Installation

1. **JetBrains Marketplace**: Settings → Plugins → Marketplace → Search "VulnSpeed"
2. **Manual**: Download from [Releases](https://github.com/JirakJ/vulnspeed-plugin/releases) → Settings → Plugins → ⚙️ → Install from disk

## Requirements

- IntelliJ IDEA 2025.1+ or any JetBrains IDE (PyCharm, WebStorm, CLion, etc.)
- 2 GB free RAM

## Configuration

Settings → Tools → VulnSpeed (two pages: application-wide and per-project).

| Setting | Scope | Default | Effect |
|---|---|---|---|
| Enable real-time scanning | IDE | on | Turns the as-you-type editor highlighting on or off. Manual scans keep working. |
| Max file size (KB) | IDE | 1000 | Files larger than this are skipped by editor highlighting, Scan File, Scan Project and scan on save. |
| Scan changed file on save | Project | off | Runs the file scan whenever a supported file is saved; results update the VulnSpeed tool window without stealing focus. |

VulnSpeed collects no telemetry and sends no source code anywhere. The only network
access is the explicit, opt-in CVE enrichment (OSV.dev / NVD) described below.

## Usage

### Scan a File
Right-click in the editor → **Scan File with VulnSpeed**. Vulnerabilities appear highlighted inline and in the VulnSpeed tool window.

### Scan a Project
Right-click a project folder → **Scan Project with VulnSpeed**. Review all findings in the tool window with severity levels and CWE/OWASP classifications.

### Real-Time Scanning
With real-time scanning enabled (default), vulnerabilities are detected and highlighted as you type — no manual scan needed. Switch it off in Settings → Tools → VulnSpeed if you prefer on-demand or on-save scans only.

### Fix Findings
Each finding includes a fix suggestion (title, description, example code and references). Apply the change yourself, or accept the finding with a `// vulnspeed-ignore` comment.

## Command-Line Scanner (CI)

Every [GitHub release](https://github.com/JirakJ/vulnspeed-plugin/releases) ships a
self-contained `vulnspeed-cli-<version>.jar` next to the plugin zip. It needs only a
Java 17+ runtime (no IDE, no Gradle plugin in your build) and runs **the same rules**
as the plugin, with the same skip rules: files above the max file size (default
1000 KB) are skipped, `// vulnspeed-ignore` / `vulnspeed-ignore-file` comments are
honoured, and hidden directories (`.git`, `.idea`, …), dependency and build output
directories (`node_modules`, `bower_components`, `vendor`, `build`, `dist`, `target`, `out`,
`__pycache__`, `venv`, `site-packages`) and minified bundles (`*.min.js`, `*.bundle.js`)
are not scanned.

```bash
VULNSPEED_VERSION=2026.10.0
curl -fsSL -o vulnspeed-cli.jar \
  "https://github.com/JirakJ/vulnspeed-plugin/releases/download/v${VULNSPEED_VERSION}/vulnspeed-cli-${VULNSPEED_VERSION}.jar"

java -jar vulnspeed-cli.jar scan --project=. \
  --out-json=build/vulnspeed/findings.json \
  --out-sarif=build/vulnspeed/vulnspeed.sarif
```

| Command | What it does |
|---------|--------------|
| `scan --project=<dir> [--out-json=<file>] [--out-sarif=<file>] [--fail-on=severity:HIGH] [--max-file-size-kb=<n>] [--max-files=<n>]` | Scans the project, writes findings JSON and/or a SARIF 2.1.0 report and prints a summary. `--max-files` defaults to 1000 (the same cap as Scan Project); the CLI warns when it truncates. |
| `baseline --create\|--compare --project=<dir> --findings=<file> ...` | Security baseline — see [below](#security-baseline--differential-scan). |
| `enrich --findings=<file> ...` | CVE enrichment — see [below](#cve-enrichment-osv--nvd). |
| `version` | Prints the CLI version. |

Exit codes for all commands: `0` success, `1` bad arguments or IO error, `2` the
`--fail-on` / `--fail-on-severity` policy was triggered.

The findings JSON is the same format the IDE writes with **Tools → VulnSpeed →
Export Findings JSON**, so you can also scan in the IDE, commit or upload the
exported file, and run `baseline` / `enrich` over it in CI.

## Rules & Precision

Every rule is written to be **precise rather than exhaustive**:

- **Scoped** — a rule runs only on the languages / file types where its pattern means something
  (Docker rules on Dockerfiles, Spring rules on Java/Kotlin and Spring config, …).
- **Anchored** — patterns match a concrete API or syntax (`yaml.load(` without `SafeLoader`,
  `res.redirect(req.query…)`, `"SELECT … FROM …" + var`), never a bare keyword.
- **Context-aware** — some rules require file context (`LDAP_001` only in files using LDAP) or
  are skipped when the file shows the hardening (`XXE_001` is skipped once the file disables DOCTYPEs).
- **Comment-free** — comment lines, block comments, KDoc / Javadoc and Python docstrings are not
  reported, and lines longer than 1,000 characters (minified / generated code) are skipped. Secret
  rules are the exception: a key pasted into a comment leaks just the same.
- **Test-aware** — rules for hard-coded credentials, disabled TLS verification, insecure randomness,
  CSRF, cookies, debug mode, gRPC/WebSocket plaintext and DOM XSS skip test sources
  (`src/test/`, `tests/`, `__tests__/`, `*Test.kt`, `test_*.py`, `*_test.go`, `*.spec.ts`, …).
- **Deduplicated** — a rule reports a line once, and when several rules with the same CWE match one
  line only the most severe finding is kept.
- **Tested** — every rule has positive and negative samples
  ([`rule-samples.txt`](src/test/resources/rule-samples.txt)), and a regression test keeps a scan of
  VulnSpeed's own production sources within a fixed budget (currently 0 findings).

### Before / after (2026.9.2 → 2026.10.0)

Scans with the CLI's default settings:

| Project | 2026.9.2 | 2026.10.0 |
|---|---:|---:|
| VulnSpeed's own sources (`src/`, incl. deliberately vulnerable test fixtures) | 1,157 | 31 |
| VulnSpeed's own production code (`src/main`) | 850 | 0 |
| [spring-petclinic](https://github.com/spring-projects/spring-petclinic) | 205 | 4 |
| [express](https://github.com/expressjs/express) | 1,104 | 2 |
| [flask](https://github.com/pallets/flask) | 1,507 | 1 |
| [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) (intentionally vulnerable) | 385 | 9 |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (intentionally vulnerable) | 377 | 9 |

On the two intentionally vulnerable apps, 2026.10.0 reports all ten planted issues we checked
(SQL injection, SSTI ×2, JWT without verification, `yaml.load`, MD5 password hash, hard-coded
password, server-side `eval` ×3 counted as one, MongoDB `$where` injection, open redirect);
2026.9.2 reported only three of them correctly and labelled the SQL injection as a Dockerfile issue.

### Rule catalogue

The 12 `SECRET_*` rules (AWS, GitHub, GitLab, Slack, Stripe, Google, npm, SendGrid, Twilio, private
keys, JWTs, credentials in URLs) run on every scanned file. The other rules:

| Rule | Severity | CWE | Applies to | Detects |
|---|---|---|---|---|
| `SQL_001` | Critical | 89 | Java, Kotlin, JS/TS, Python, Go, Swift | SQL Injection via String Concatenation |
| `SQL_002` | Critical | 89 | Java, Kotlin | SQL/HQL Injection in JPA or Hibernate Query |
| `SQL_003` | High | 943 | JS/TS, Python | NoSQL Injection via MongoDB $where |
| `SQL_004` | Critical | 89 | Python | SQL Injection via Python String Formatting |
| `SQL_005` | Critical | 89 | JS/TS, Kotlin | SQL Injection via String Interpolation |
| `SQL_006` | Critical | 89 | Go, Java, Kotlin | SQL Injection via Format String |
| `NODE_002` | High | 943 | JS/TS | NoSQL Injection via Raw Request Object |
| `PRISMA_001` | Critical | 89 | JS/TS | Prisma Unsafe Raw Query |
| `SEQUELIZE_001` | Critical | 89 | JS/TS | Sequelize Raw Query Injection |
| `TYPEORM_001` | High | 89 | JS/TS | Query Builder Raw Condition Injection |
| `CMD_001` | Critical | 78 | Java, Kotlin | Command Injection - Runtime.exec() |
| `CMD_002` | High | 78 | Java, Kotlin | Command Injection - ProcessBuilder |
| `CMD_003` | Critical | 78 | Python | Command Injection - Python Shell Execution |
| `CMD_004` | Medium | 78 | Python | Subprocess With shell=True |
| `CMD_005` | High | 78 | Go | Command Injection - Go exec.Command via Shell |
| `CMD_006` | High | 78 | C/C++ | Command Injection - system()/popen() With Variable |
| `JS_003` | Critical | 78 | JS/TS | Command Injection - Node.js child_process |
| `PYTHON_002` | Critical | 95 | Python | Python Code Injection via eval()/exec() |
| `JS_004` | Critical | 95 | JS/TS | JavaScript Code Injection via eval() |
| `SCRIPT_001` | Critical | 94 | Java, Kotlin | Script Engine Injection |
| `EXPR_001` | Critical | 917 | Java, Kotlin | Expression Language Injection |
| `ATTACK_001` | High | 1336 | Python | Server-Side Template Injection (SSTI) |
| `LDAP_001` | High | 90 | Java, Kotlin, Python | LDAP Injection |
| `XPATH_001` | High | 643 | Java, Kotlin, Python | XPath Injection |
| `REFLECT_001` | High | 470 | Java, Kotlin | Unsafe Reflection From Request Data |
| `REGEX_001` | Medium | 1333 | Java, Kotlin, JS/TS, Python, Go | Regular Expression Denial of Service (ReDoS) |
| `DESER_001` | High | 502 | Java, Kotlin | Insecure Deserialization - ObjectInputStream |
| `DESER_002` | High | 502 | Python | Insecure Deserialization - PyYAML load |
| `SERIAL_003` | Medium | 502 | Java, Kotlin | SnakeYAML Without SafeConstructor |
| `PYTHON_001` | High | 502 | Python | Python Unsafe Deserialization (pickle and friends) |
| `SERIAL_004` | High | 502 | Java, Kotlin | Jackson Polymorphic Deserialization |
| `XXE_001` | Medium | 611 | Java, Kotlin | XXE - XML Parser Without Hardening |
| `CRYPTO_001` | Medium | 328 | Java, Kotlin, JS/TS, Python, Go | Weak Hash Algorithm - MD5/SHA-1 |
| `CRYPTO_002` | High | 327 | Java, Kotlin, JS/TS, Python, Go | Weak Cipher - DES/3DES/RC4/Blowfish or ECB Mode |
| `CRYPTO_003` | Critical | 321 | Java, Kotlin | Hardcoded Cryptographic Key or IV |
| `CRYPTO_004` | High | 326 | Java, Kotlin, JS/TS, Python, Go | Insecure TLS/SSL Protocol Version |
| `CRYPTO_005` | High | 295 | Java, Kotlin, JS/TS, Python, Go | Certificate or Hostname Validation Disabled |
| `CRYPTO_BASIC_001` | Medium | 338 | Java, Kotlin, JS/TS, Python, Go | Insecure Random Number for a Security Value |
| `CRYPTO_006` | High | 326 | Java, Kotlin, JS/TS, Python, Go | Weak RSA Key Size |
| `CRYPTO_008` | Medium | 916 | Java, Kotlin, JS/TS, Python | Insufficient PBKDF2 Iterations |
| `JWT_001` | Critical | 347 | Java, Kotlin, JS/TS, Python, Go | JWT Signature Verification Disabled |
| `AUTH_001` | High | 798 | all code | Hardcoded Credentials |
| `CONFIG_001` | High | 798 | YAML, .properties | Hardcoded Secret in Configuration |
| `PCI_001` | High | 311 | all code | Credit Card Number in Code |
| `DOCKER_002` | High | 798 | Dockerfile | Secret Baked Into Docker Image |
| `GDPR_003` | Medium | 532 | all code | Password or Secret Written to Logs |
| `XSS_001` | High | 79 | JS/TS | Cross-Site Scripting via innerHTML |
| `XSS_002` | High | 79 | JS/TS | DOM-based XSS - document.write |
| `XSS_003` | Medium | 79 | JS/TS | React XSS - dangerouslySetInnerHTML |
| `XSS_004` | High | 79 | Python | XSS via Markup / mark_safe |
| `XSS_005` | High | 79 | Java, Kotlin | Reflected XSS in Servlet Response |
| `XSS_006` | Medium | 79 | Python | Jinja2 Autoescape Disabled |
| `ANGULAR_001` | Medium | 79 | JS/TS | Angular Sanitizer Bypass |
| `REDIRECT_001` | Medium | 601 | Java, Kotlin, JS/TS, Python | Open Redirect |
| `SSRF_001` | High | 918 | Java, Kotlin, JS/TS, Python | Server-Side Request Forgery |
| `CORS_001` | Medium | 942 | Java, Kotlin, JS/TS, Python, Go | Overly Permissive CORS |
| `CSRF_001` | Medium | 352 | Java, Kotlin, Python | CSRF Protection Disabled |
| `COOKIE_001` | Medium | 614 | Java, Kotlin, JS/TS, Python | Insecure Cookie Flags |
| `API_010` | Medium | 922 | JS/TS | Sensitive Token in Web Storage |
| `OAUTH_003` | Medium | 598 | all code | OAuth Implicit Flow |
| `GRAPHQL_002` | Low | 200 | JS/TS, .properties | GraphQL Introspection Enabled |
| `SPRING_001` | High | 862 | Java, Kotlin | Spring Security Permits Every Request |
| `SPRING_003` | Medium | 200 | YAML, .properties | All Actuator Endpoints Exposed |
| `PYTHON_003` | Medium | 489 | Python | Python Web App Debug Mode Enabled |
| `DOCKER_001` | Low | 1357 | Dockerfile | Docker Base Image Uses :latest |
| `DOCKER_005` | Medium | 250 | Dockerfile | Container Runs as Root |
| `DOCKER_006` | Medium | 494 | Dockerfile | Remote Script Piped to Shell |
| `K8S_005` | High | 250 | YAML | Privileged Container |
| `K8S_006` | Medium | 250 | YAML | Privilege Escalation Allowed |
| `K8S_007` | Medium | 668 | YAML | Host Namespace Shared With Container |
| `CONTAINER_001` | High | 250 | YAML | Docker Socket Mounted Into Container |
| `ISTIO_001` | Medium | 319 | YAML | Istio mTLS in Permissive Mode |
| `LAMBDA_003` | Medium | 269 | YAML | IAM Policy Allows All Actions |
| `CLOUD_002` | High | 732 | Java, Kotlin, JS/TS, Python, Go, YAML | Public S3 Bucket or Object ACL |
| `PATH_001` | High | 22 | Java, Kotlin, JS/TS, Python | Path Traversal |
| `PATH_002` | High | 22 | Java, Kotlin | Zip Slip |
| `PATH_003` | Medium | 22 | Python | Tar Slip - tarfile.extractall Without Filter |
| `TEMP_001` | Medium | 377 | Python | Insecure Temporary File |
| `NET_001` | Medium | 319 | Java, Kotlin, Python | Cleartext FTP / Telnet Client |
| `NET_006` | Medium | 319 | Java, Kotlin, JS/TS, Python, Go | Unencrypted WebSocket (ws://) |
| `GRPC_001` | Medium | 319 | Java, Kotlin, JS/TS, Python, Go | gRPC Without TLS |
| `MOBILE_002` | Medium | 312 | Java, Kotlin, Swift | Credential in Unencrypted Mobile Storage |
| `BUFFER_001` | High | 120 | C/C++ | Unbounded C String Function |
| `FORMAT_001` | High | 134 | C/C++ | Format String Vulnerability |

## Security Baseline & Differential Scan

Large legacy codebases usually produce thousands of historical SAST findings —
without a baseline, security gates either drown teams in noise or get muted
entirely. VulnSpeed's baseline feature snapshots today's findings as the
accepted state and surfaces only *new regressions* on subsequent scans.

### In the IDE

- **Tools → VulnSpeed → Create Security Baseline** writes
  `<project>/.vulnspeed-baseline.json` atomically from the latest scan.
- **Tools → VulnSpeed → Compare Against Security Baseline** opens a three-tab
  dialog (New Regressions / Fixed / Persisted) with buttons to copy a
  Markdown report, export the diff as JSON, update the baseline, or jump to
  the first regression in the editor.

Fingerprints are SHA-256 of `ruleId|cwe|relativeFilePath|startLine|normalizedMessage`
so cosmetic reformatting and numeric literal changes do not cause spurious
regressions. Paths outside the project root fall back to a `file://` prefix.

### In CI (GitHub Actions)

Create the baseline once from a trusted branch and commit it:

```bash
java -jar vulnspeed-cli.jar scan --project=. --out-json=build/vulnspeed/findings.json
java -jar vulnspeed-cli.jar baseline --create --project=. \
  --findings=build/vulnspeed/findings.json --baseline=.vulnspeed-baseline.json
```

Then gate pull requests on new findings only:

```yaml
name: Security Gate
on:
  pull_request:
jobs:
  vulnspeed:
    runs-on: ubuntu-latest
    env:
      VULNSPEED_VERSION: 2026.10.0
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 17

      - name: Download VulnSpeed CLI
        run: |
          curl -fsSL -o vulnspeed-cli.jar \
            "https://github.com/JirakJ/vulnspeed-plugin/releases/download/v${VULNSPEED_VERSION}/vulnspeed-cli-${VULNSPEED_VERSION}.jar"

      - name: Scan
        run: java -jar vulnspeed-cli.jar scan --project="$PWD" --out-json=build/vulnspeed/findings.json

      - name: Differential scan vs baseline
        run: |
          java -jar vulnspeed-cli.jar baseline --compare \
            --project="$PWD" \
            --baseline=.vulnspeed-baseline.json \
            --findings=build/vulnspeed/findings.json \
            --output=md \
            --output-file=vulnspeed-diff.md \
            --fail-on=severity:HIGH

      - name: Comment diff on PR
        if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: vulnspeed-diff.md
```

`baseline --compare` exits `2` when `--fail-on` trips (`regression` = any new
finding, `severity:HIGH` = a new HIGH or CRITICAL finding), `0` otherwise — so the
job fails the PR check only when new findings at that level are introduced.
Re-run `--create` to accept the current state.

## CVE Enrichment (OSV + NVD)

VulnSpeed enriches findings whose rule id, id, name or tags contain a
`CVE-YYYY-NNNNN` identifier with CVSS score & vector, textual severity, CWE
mappings, publish / modify dates, reference links and fixed versions. Data is
pulled from [OSV.dev](https://osv.dev) first, with [NVD](https://nvd.nist.gov) as
fallback. VulnSpeed's built-in rules detect code patterns, not vulnerable dependency
versions, so they are mapped to CWE ids and carry no CVE id — their findings pass
through enrichment unchanged. Enrichment is useful for findings JSON that
references CVEs (for example findings merged in from a dependency scanner).

### Offline-first cache

Responses are stored in a TTL-bound disk cache and reused across runs:

- Inside the IDE: `<IDE config dir>/vulnspeed/cve-cache/`.
- CLI: `~/.vulnspeed/cve-cache/` (override with `--cache-dir`).

Each CVE is a JSON file named `<CVE-ID>.json`. Deleting the directory forces a
refresh. Use `--offline` to require cache hits only (no network calls).

### In the IDE

**Tools → VulnSpeed → Enrich Vulnerabilities (OSV / NVD)** opens a table of the
last scan's vulnerabilities resolved against OSV/NVD. Copy a Markdown report
for a PR, export JSON, or open the referenced advisories.

### Command line

```bash
java -jar vulnspeed-cli.jar enrich \
  --findings=build/vulnspeed/findings.json \
  --out=build/vulnspeed/enriched.md \
  --format=md \
  --fail-on-severity=HIGH
```

Flags:

| Flag | Description |
|------|-------------|
| `--findings=PATH` | Findings JSON from `scan --out-json` or **Export Findings JSON** (required). |
| `--out=PATH` | Output file; prints to stdout when omitted. |
| `--format=json\|md` | Report format (default `json`). |
| `--offline` | Disable network; use the cache only. |
| `--cache-dir=PATH` | Override the cache location. |
| `--max-age-days=N` | Maximum age of cached entries (default 7). |
| `--nvd-key=KEY` | NVD API key (or set `NVD_API_KEY`). |
| `--fail-on-severity=LOW\|MEDIUM\|HIGH\|CRITICAL` | Exit `2` if any finding meets or exceeds the level. |

### In CI (GitHub Actions)

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.vulnspeed/cve-cache
    key: vulnspeed-cve-${{ runner.os }}
- name: Enrich findings
  run: |
    java -jar vulnspeed-cli.jar enrich \
      --findings=build/vulnspeed/findings.json \
      --out=build/vulnspeed/enriched.md \
      --format=md
```

## Building from Source

```bash
./gradlew buildPlugin   # plugin zip in build/distributions/
./gradlew cliJar        # build/cli/vulnspeed-cli-<version>.jar
```

## SARIF Report Export

VulnSpeed can export its scan results as a **SARIF 2.1.0** report — the
industry-standard format understood by GitHub Code Scanning, GitLab SAST, Azure
DevOps, SonarQube, and DefectDojo.

### How to export

1. Run a scan (**Scan File / Scan Project with VulnSpeed**).
2. Open **Tools → VulnSpeed → Export SARIF Report**.
3. Choose a destination — defaults to `vulnspeed-report.sarif` in the project root.

Without an IDE, `java -jar vulnspeed-cli.jar scan --project=. --out-sarif=<file>` writes the same report.

The exporter writes UTF-8, generates stable `partialFingerprints` so repeated
runs deduplicate in downstream systems, and is 100% schema-compliant with
`https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json`.

### GitHub Code Scanning integration

Drop this into `.github/workflows/vulnspeed.yml` to upload VulnSpeed findings to
the **Security → Code scanning** tab of your repository:

```yaml
name: VulnSpeed SAST
on: [push, pull_request]

jobs:
  vulnspeed:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    env:
      VULNSPEED_VERSION: 2026.10.0
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 17
      - name: Run VulnSpeed scan
        run: |
          curl -fsSL -o vulnspeed-cli.jar \
            "https://github.com/JirakJ/vulnspeed-plugin/releases/download/v${VULNSPEED_VERSION}/vulnspeed-cli-${VULNSPEED_VERSION}.jar"
          java -jar vulnspeed-cli.jar scan --project="$PWD" --out-sarif=build/vulnspeed/vulnspeed.sarif
      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: build/vulnspeed/vulnspeed.sarif
          category: vulnspeed
```

For GitLab, point the `sast` report artifact at the SARIF file; for Azure DevOps
use the SARIF SAST Scans Tab extension.

## CycloneDX SBOM Export

VulnSpeed can also export a **CycloneDX 1.5** Software Bill of Materials (SBOM)
— the industry-standard supply-chain document consumed by Dependency-Track,
Sonatype Lifecycle, GitHub Dependency Graph, FOSSA, and the `cyclonedx-cli`
tool.

### How to export

1. Run a scan (optional — the exporter will offer to run one if no scan is cached).
2. Open **Tools → VulnSpeed → Export CycloneDX SBOM**.
3. Choose a destination — defaults to `vulnspeed-sbom.cdx.json` in the project root.

Components are discovered from `pom.xml`, `package.json` + `package-lock.json`,
`requirements.txt`, and literal `implementation("g:a:v")` strings in
`build.gradle.kts` / `build.gradle`. Vulnerabilities from the latest scan are
cross-referenced into the `vulnerabilities[]` section with CVSS v3.1 ratings
and CWE identifiers. The `serialNumber` is a deterministic UUIDv5 derived
from sorted component PURLs, so repeat exports stay identical unless the
component set changes.

### Dependency-Track upload example

```bash
curl -X POST \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -H "Content-Type: multipart/form-data" \
  -F "autoCreate=true" \
  -F "projectName=my-app" \
  -F "projectVersion=1.0.0" \
  -F "bom=@vulnspeed-sbom.cdx.json" \
  https://dtrack.example.com/api/v1/bom
```

## Contributing

Issues and pull requests are welcome at https://github.com/JirakJ/vulnspeed-plugin.

## License

Copyright 2026 Jakub Jirák. Licensed under the [Apache License, Version 2.0](LICENSE).
