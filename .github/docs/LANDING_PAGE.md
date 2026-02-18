# VulnSpeed — GPU-Accelerated Security Scanning in Your IDE

> **Find and fix vulnerabilities as you type, not at build time.**

---

## The Problem

Traditional SAST tools run in CI/CD pipelines — you find out about vulnerabilities minutes or hours after writing the code. By then you have moved on, context is lost, and fixing takes 10x longer. Teams need security feedback at the speed of development, not at the speed of a pipeline. And with codebases growing larger, CPU-based scanners struggle to keep up.

---

## Key Features

### 1. Real-Time Vulnerability Detection
Finds OWASP Top 10 and CWE Top 25 vulnerabilities as you type. Inline severity highlighting appears instantly in the editor — no manual scan required.

### 2. Multi-Language Support
Full scanning for 7 languages: Java, Kotlin, Python, JavaScript, TypeScript, C/C++, and Swift. Each language has dedicated detection rules tuned for common vulnerability patterns.

### 3. One-Click Auto-Fix
Automated remediation suggestions for detected vulnerabilities. Press Alt+Enter on a highlighted issue and apply the fix instantly.

### 4. File and Project Scanning
On-demand scanning of individual files (right-click → Scan File) or entire projects (right-click → Scan Project). Results appear in the VulnSpeed tool window with severity levels and CWE/OWASP classifications.

### 5. Security Dashboard
The VulnSpeed tool window shows a project-wide vulnerability list, statistics, and severity breakdown. Quick access to fixes and drill-down into individual findings.

### 6. GPU-Accelerated Scanning (Pro)
Metal, CUDA, and Vulkan accelerated engine for 50-100x faster analysis on large codebases. Massively parallel scanning that keeps up with enterprise-scale projects.

### 7. Advanced Taint Analysis (Pro)
Data flow and taint tracking across function boundaries to trace how untrusted input reaches sensitive sinks. Catches complex vulnerability patterns that simple pattern matching misses.

### 8. Compliance Reports (Pro)
Generate SOC 2, HIPAA, and PCI DSS compliance reports from scan results. Export evidence for audits directly from your IDE.

---

## How It Works

1. **Install and code** — Install the plugin and write code as usual. Real-time scanning highlights vulnerabilities inline as you type.
2. **Review findings** — Click on highlighted vulnerabilities to see severity, CWE/OWASP classification, and a description of the issue.
3. **Apply fixes** — Press Alt+Enter on a finding and select the suggested auto-fix to remediate the vulnerability instantly.
4. **Scan your project** — Run a full project scan to get a complete vulnerability inventory with metrics and severity breakdown.

---

## Pricing

| Feature | Free | Pro |
|---------|:----:|:---:|
| Real-time detection | ✅ | ✅ |
| OWASP Top 10 coverage | ✅ | ✅ |
| Inline severity highlighting | ✅ | ✅ |
| Basic auto-fix | ✅ | ✅ |
| File and project scanning | ✅ | ✅ |
| Security dashboard | ✅ | ✅ |
| Full CWE Top 25 coverage | — | ✅ |
| GPU acceleration | — | ✅ |
| Advanced taint analysis | — | ✅ |
| AI false positive filtering | — | ✅ |
| Custom security rules | — | ✅ |
| Compliance reports (SOC 2, HIPAA, PCI DSS) | — | ✅ |
| CI/CD integration | — | ✅ |
| Team security dashboards | — | ✅ |

---

## Testimonials

> *"VulnSpeed caught a SQL injection in our API layer that our CI scanner missed for months. The real-time feedback is a game changer."*
> — **Security Engineer, FinTech Company**

> *"The GPU acceleration is not marketing hype — our full project scan went from 12 minutes to 8 seconds. We scan on every save now."*
> — **CTO, SaaS Startup**

> *"The auto-fix feature means junior developers learn secure coding patterns as they go. Our vulnerability backlog dropped 60% in three months."*
> — **AppSec Lead, Enterprise Software Company**

---

## FAQ

**Q: Does real-time scanning slow down the IDE?**
A: No. The scanning engine runs asynchronously and is optimized for minimal impact. With GPU acceleration (Pro), even large files are scanned in milliseconds.

**Q: Which vulnerability standards are covered?**
A: The Free tier covers OWASP Top 10. The Pro tier adds full CWE Top 25 coverage including SQL injection (CWE-89), XSS (CWE-79), OS command injection (CWE-78), and 22+ more.

**Q: Do I need a GPU for the plugin to work?**
A: No. The Free tier runs on CPU only. GPU acceleration is a Pro feature that supports Metal (macOS), CUDA (NVIDIA), and Vulkan.

**Q: Can I define custom security rules?**
A: Yes, with the Pro tier. Define organization-specific vulnerability patterns for your codebase.

**Q: Which JetBrains IDEs are supported?**
A: All JetBrains IDEs 2023.3+ including IntelliJ IDEA, PyCharm, WebStorm, CLion, GoLand, and others. JDK 11+ required.

---

## Get Started

Install from the [JetBrains Marketplace](https://plugins.jetbrains.com) and start finding vulnerabilities in real time.
