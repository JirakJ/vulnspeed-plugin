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

### Real-Time Scanning
With real-time scanning enabled (default), vulnerabilities are detected and highlighted as you type — no manual scan needed.

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
