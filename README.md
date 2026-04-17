# VulnSpeed SAST

GPU-accelerated static application security testing (SAST) plugin for JetBrains IDEs. Real-time vulnerability detection across Java, Python, C/C++, JavaScript, TypeScript, and Swift with OWASP Top 10 and CWE Top 25 coverage.

## Features

- **Real-time vulnerability detection** — annotators scan code as you type with inline severity highlighting for Java, Python, JavaScript, and TypeScript
- **Multi-language support** — full scanning for Java, Python, C/C++, JavaScript, TypeScript, and Swift
- **OWASP Top 10 coverage** — detects all 10 categories including injection, broken access control, cryptographic failures, SSRF, and more
- **CWE Top 25 coverage** — SQL injection (CWE-89), XSS (CWE-79), OS command injection (CWE-78), information disclosure (CWE-200), and 21+ more
- **Global inspection** — VulnSpeed Security Analysis inspection integrated into IDE's inspection framework
- **One-click auto-fixes** — quick-fix suggestions applied instantly via Alt+Enter
- **Scan file** — right-click in editor → "Scan File with VulnSpeed" for on-demand analysis
- **Scan project** — right-click project folder → "Scan Project with VulnSpeed" for full project scanning
- **VulnSpeed tool window** — bottom panel displaying vulnerability list, statistics, and quick access to fixes
- **GPU acceleration** — Metal/CUDA/Vulkan accelerated scanning, 50–100x faster than CPU-based SAST
- **Taint flow analysis** — advanced taint and data flow analysis for tracking vulnerability propagation
- **AI-powered false positive filtering** — ML-based filtering to reduce noise
- **Custom security rules** — define organization-specific vulnerability patterns
- **Team dashboard & metrics** — collaborative security metrics and reporting
- **Configurable settings** — toggle real-time scanning, auto-fix, max file size, and telemetry preferences

## Installation

1. **JetBrains Marketplace**: Settings → Plugins → Marketplace → Search "VulnSpeed"
2. **Manual**: Download from [Releases](https://github.com/JirakJ/vulnspeed-plugin/releases) → Settings → Plugins → ⚙️ → Install from disk

## Requirements

- IntelliJ IDEA 2023.3+ or any JetBrains IDE (PyCharm, WebStorm, CLion, etc.)
- JDK 11+ (included with IDE)
- 2 GB free RAM

## Configuration

Settings → Tools → VulnSpeed

Toggle real-time scanning, configure max file size limits, enable/disable auto-fix suggestions.

## Usage

### Scan a File
Right-click in the editor → **Scan File with VulnSpeed**. Vulnerabilities appear highlighted inline and in the VulnSpeed tool window.

### Scan a Project
Right-click a project folder → **Scan Project with VulnSpeed**. Review all findings in the tool window with severity levels and CWE/OWASP classifications.

### Apply Fixes
Click on a highlighted vulnerability → **Alt+Enter** → select the suggested fix to apply it instantly.

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

```yaml
name: Security Gate
on:
  pull_request:
jobs:
  vulnspeed:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run VulnSpeed scan
        run: ./gradlew vulnspeedScan # produces build/reports/vulnspeed/findings.json and vulnspeed-report.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: build/reports/vulnspeed/vulnspeed-report.sarif

      - name: Differential scan vs baseline
        run: |
          java -cp build/libs/vulnspeed-plugin-*.jar \
            com.jakubjirak.vulnspeed.baseline.VulnBaselineCli \
            --compare \
            --project="$PWD" \
            --baseline=.vulnspeed-baseline.json \
            --findings=build/reports/vulnspeed/findings.json \
            --output=md \
            --output-file=vulnspeed-diff.md \
            --fail-on=severity:HIGH

      - name: Comment diff on PR
        if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: vulnspeed-diff.md
```

The CLI exits `2` when `--fail-on` trips, `0` otherwise — so the job fails the
PR check only when HIGH/CRITICAL regressions are introduced. Use `--create` to
refresh the baseline from a trusted branch.

### Real-Time Scanning
With real-time scanning enabled (default), vulnerabilities are detected and highlighted as you type — no manual scan needed.

## CVE Enrichment (OSV + NVD)

VulnSpeed enriches scan findings whose `ruleId` contains a `CVE-YYYY-NNNNN`
identifier with CVSS score & vector, textual severity, CWE mappings, publish /
modify dates, reference links and fixed versions. Data is pulled from
[OSV.dev](https://osv.dev) first, with [NVD](https://nvd.nist.gov) as fallback.

### Offline-first cache

Responses are stored in a TTL-bound disk cache and reused across runs:

- Inside the IDE: `<configPath>/vulnspeed/cve-cache/` (per `PathManager`).
- In CLI / CI: `~/.vulnspeed/cve-cache/` (or `$VULNSPEED_HOME/cve-cache`).

Each CVE is a JSON file named `<CVE-ID>.json`. Deleting the directory forces a
refresh. Use `--offline` to require cache hits only (no network calls).

### In the IDE

**Tools → VulnSpeed → Enrich Findings with CVE Metadata** opens a table of the
last scan's vulnerabilities resolved against OSV/NVD. Copy a Markdown report
for a PR, export JSON, or open the referenced advisories.

### Headless CLI

```bash
java -cp vulnspeed.jar com.jakubjirak.vulnspeed.enrichment.CveEnrichmentCli \
  --findings=build/vulnspeed/findings.json \
  --out=build/vulnspeed/enriched.md \
  --format=md \
  --fail-on-severity=HIGH
```

Flags:

| Flag | Description |
|------|-------------|
| `--findings=PATH` | JSON array of `Vulnerability` objects (from `--output=json` baseline CLI). |
| `--out=PATH` | Output file (Markdown or JSON). |
| `--format=md\|json` | Report format (default `md`). |
| `--offline` | Disable network; use cache only. |
| `--cache-dir=PATH` | Override cache location. |
| `--cache-ttl-hours=N` | TTL for cached entries (default 168 = 7 days). |
| `--fail-on-severity=LOW\|MEDIUM\|HIGH\|CRITICAL` | Exit `2` if any enriched finding meets or exceeds the level. |
| `--timeout-ms=N` | Per-request timeout (default 10000). |

Exit codes: `0` success, `1` fatal error, `2` severity policy tripped.

### In CI (GitHub Actions)

```yaml
- name: Enrich findings
  run: |
    java -cp build/libs/vulnspeed.jar \
      com.jakubjirak.vulnspeed.enrichment.CveEnrichmentCli \
      --findings=build/vulnspeed/findings.json \
      --out=build/vulnspeed/enriched.md \
      --format=md \
      --fail-on-severity=HIGH
- uses: actions/cache@v4
  with:
    path: ~/.vulnspeed/cve-cache
    key: vulnspeed-cve-${{ runner.os }}
```

## Building from Source

```bash
./gradlew buildPlugin
```

## License

Copyright © 2026 Jakub Jirák. All rights reserved.

## SARIF Report Export

VulnSpeed can export its scan results as a **SARIF 2.1.0** report — the
industry-standard format understood by GitHub Code Scanning, GitLab SAST, Azure
DevOps, SonarQube, and DefectDojo.

### How to export

1. Run a scan (**Scan File / Scan Project with VulnSpeed**).
2. Open **Tools → VulnSpeed → Export SARIF Report**.
3. Choose a destination — defaults to `vulnspeed-report.sarif` in the project root.

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
    steps:
      - uses: actions/checkout@v4
      - name: Run VulnSpeed scan
        run: ./gradlew vulnspeedScan --console=plain
      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: build/reports/vulnspeed-report.sarif
          category: vulnspeed
```

For GitLab, point the `sast` report artifact at `vulnspeed-report.sarif`; for
Azure DevOps use the SARIF SAST Scans Tab extension.

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
