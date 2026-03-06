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
