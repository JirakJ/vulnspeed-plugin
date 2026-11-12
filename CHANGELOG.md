# Changelog

All notable changes to **VulnSpeed** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic-ish date versioning](https://jakumjirak.example) (`YYYY.M.release_order`).

## [Unreleased]

## [2026.10.0] - 2026-11-12

### Changed
- **Rule precision overhaul.** Every rule is now scoped to the languages / file types where it is
  meaningful, anchored on a concrete API or syntax, and skips comment lines, block comments,
  KDoc / Javadoc, Python docstrings and lines longer than 1,000 characters (minified code); secret
  rules still match everywhere. Ambiguous rules require file context (`requiresInFile`) or are
  skipped when the file shows the hardening (`excludeIfFileContains`); credential, TLS, randomness,
  CSRF, cookie, debug-mode and DOM-XSS rules skip test sources. A rule reports a line once, and
  same-CWE findings on one line keep only the most severe.
- Findings before → after (CLI defaults):

  | Project | 2026.9.2 | 2026.10.0 |
  |---|---:|---:|
  | VulnSpeed `src/` (incl. deliberately vulnerable test fixtures) | 1,157 | 31 |
  | VulnSpeed `src/main` | 850 | 0 |
  | spring-projects/spring-petclinic @500158f | 205 | 4 |
  | expressjs/express @43fca52 | 1,104 | 2 |
  | pallets/flask @49943b5 | 1,507 | 1 |
  | we45/Vulnerable-Flask-App @b6a4f97 | 385 | 9 |
  | OWASP/NodeGoat @c5cb68a | 377 | 9 |

  Top offenders that are gone: `INPUT_005` (890), `INPUT_004` (868), `TERRAFORM_001` (761),
  `NODE_001` (680), `PERF_007` (165), `SERIAL_006` (146), `SESSION_007` (138), `ATTACK_006` (112),
  `LAMBDA_004` (91), `SPRING_006` (88), `GITLAB_001` (87), `DOCKER_004` (28). On the two
  intentionally vulnerable apps all ten planted issues checked are reported (2026.9.2: three).
- Rules kept their ids where the intent is the same (`SQL_001`, `XSS_001`, `CRYPTO_001`, `CMD_001`, …),
  so existing `vulnspeed-ignore` comments and baselines keep working for them.
- Fix suggestions are now specific to each rule family (e.g. container hardening for Docker rules,
  bounded string functions for C rules) instead of generic boilerplate.
- Plugin renamed from "VulnSpeed - GPU-Accelerated SAST" to **"VulnSpeed - Fast Regex SAST"**
  (plugin id unchanged); the plugin description now describes the pattern-based engine honestly.

### Added
- Rules for Python string-formatted / f-string SQL, JS template-literal and Kotlin-template SQL,
  Go `fmt.Sprintf` SQL, Python `shell=True`, Go `exec.Command("sh", "-c", …)`, C `system()` /
  format strings, server-side JS `eval(req…)`, Jinja2 SSTI and `autoescape=False`, `Markup(f"…")`,
  servlet reflected XSS, Angular `bypassSecurityTrust*`, tar slip, MongoDB `$where`, Docker
  (`:latest`, `USER root`, `curl | sh`, secrets in `ENV`/`ARG`), Kubernetes / Compose (privileged,
  privilege escalation, host namespaces, mounted Docker socket), IAM `Action: "*"` and hard-coded
  secrets in YAML / `.properties`.
- Scan Project and the CLI now also scan `Dockerfile`s, `*.yml` / `*.yaml`, `*.properties`,
  `.mjs` / `.cjs` / `.jsx` / `.mts` / `.cts` / `.tsx` and `.hpp` / `.hh` / `.hxx` C++ headers.
- Per-rule positive and negative samples for every rule (`src/test/resources/rule-samples.txt`) and a
  regression test that keeps the self-scan of `src/main` within a fixed budget.

### Removed
- 182 of 266 non-secret rules (84 remain, plus the 12 secret rules): duplicates were merged, and
  rules a line regex cannot judge were dropped — "annotation X without Y" heuristics (missing
  `@Valid`, `@RateLimit`, `@PreAuthorize`, circuit breakers, timeouts, pagination), code-quality and
  performance rules (`QUALITY_*`, `PERF_*`, `INPUT_*`, `KOTLIN_*`, `REACT_*`), compliance keyword
  rules (`GDPR_001/002`, `HIPAA_001`, `PRIVACY_*`) and rules for file types VulnSpeed never scans
  (Terraform, PHP, HTML / Vue templates, Firestore rules, GitHub Actions in `.github/`).
- `vendor/`, `dist/`, `target/`, `out/`, `__pycache__/`, `venv/`, `site-packages/` and minified bundles
  (`*.min.js`, `*-min.js`, `*.bundle.js`) are no longer scanned.
- The leftover GPU "What's New" claims in the plugin change notes, the unused `DeviceInfo` GPU model
  class, and the settings screenshot that still showed the removed auto-fix and telemetry switches.

## [2026.9.2] - 2026-11-12

### Added
- **Standalone CLI** `vulnspeed-cli-<version>.jar`, attached to every GitHub release: `java -jar vulnspeed-cli.jar scan|baseline|enrich`.
  `scan --project=<dir> --out-json=<file> --out-sarif=<file> [--fail-on=severity:HIGH]` runs the plugin's rules without an IDE,
  with the same max file size, `vulnspeed-ignore` comments and excluded directories.
- **Tools → VulnSpeed → Export Findings JSON** writes the latest scan in the format the `baseline` and `enrich` commands read.

### Fixed
- README CI examples called a `./gradlew vulnspeedScan` task that never existed and fed the baseline / enrichment CLIs a
  findings file nothing produced. They now download the CLI jar from the GitHub release and run it; the enrichment flags
  table lists the flags that actually exist.
- A project located in a hidden (dot-prefixed) directory is now scanned by Scan Project.

## [2026.9.1] - 2026-11-12

### Fixed
- **Enable real-time scanning** now actually switches the as-you-type editor highlighting on and off.
- **Max file size** is now enforced: files above the limit are skipped by editor highlighting,
  Scan File, Scan Project and scan on save.
- **Scan changed file on save** now runs the file scan when a supported file is saved and updates
  the VulnSpeed tool window (without stealing focus).

### Removed
- The telemetry switch — VulnSpeed never collected telemetry and, as a free open-source plugin, never will.
- The "auto-fix suggestions" and "apply safe auto-fixes on save" switches and the unused quick-fix class
  behind them: there is no automatic fix engine. Findings keep their fix suggestions and references.
- The empty "VulnSpeed Security Analysis" global inspection, which never reported anything.

## [2026.9.0] - 2026-11-11

### Changed
- Plugin description and README now list only features that actually ship: the never-wired
  GPU acceleration, taint analysis, AI false-positive filtering, custom rules and compliance
  report claims were removed, together with the unused analyzer classes behind them.
- Declares K2 Kotlin plugin mode compatibility.
- HTML report footer no longer claims GPU acceleration.

## [2026.8.0] - 2026-11-10

### Changed
- The plugin is now completely free — all features unlocked, no license needed.
- Source code is now open source under the Apache License 2.0: https://github.com/JirakJ/vulnspeed-plugin

## [2026.6.7] - 2026-06-22

### Fixed
- Plugin-version lookup migrated from the plugin-by-ID lookups (`PluginManagerCore.getPlugin` /
  `PluginManager.findEnabledPlugin` — flagged as internal API by JetBrains Marketplace review,
  warned it "may start returning null any time soon") to the public, by-class
  `PluginManager.getPluginByClass(javaClass)` at all 6 call sites. Bytecode verified:
  0 references to the by-ID lookups.

## [2026.6.6] - 2026-06-21

### Fixed
- Clean re-release of the 2026.6.5 internal-API fix. Re-verified locally with the
  IntelliJ Plugin Verifier against IC 2025.1.7 / 2025.2.6.1 / 2025.3 / 2026.1:
  **0 internal-API usages**, dynamic-plugin eligible, Compatible on all four.
  (2026.6.5 was uploaded but stuck pending moderation; this supersedes it.)

## [2026.6.5] - 2026-06-21

### Fixed
- Remove internal `PluginManager.findEnabledPlugin(PluginId)` at all 6 call sites;
  replaced with the public `PluginManagerCore.getPlugin(PluginId)` API.
  Versions 2026.6.3 and 2026.6.4 were published with this bug re-introduced.

## [2026.6.2] - 2026-06-10

### Fixed
- Plugin-version lookup no longer uses `PluginManager.findEnabledPlugin(PluginId)`,
  which is marked `@ApiStatus.Internal` and flagged by the Marketplace Plugin
  Verifier ("Internal method usage"). Replaced with the public
  `PluginManagerCore.getPlugin(PluginId)` at all 6 call sites. Note: the
  2026.6.1 migration went in the wrong direction — `PluginManagerCore.getPlugin`
  carries no internal/deprecated annotations and is the correct public API.

## [2026.6.1] - 2026-06-10

### Changed
- Plugin-version lookup migrated from `PluginManagerCore` to the public
  `PluginManager.getInstance().findEnabledPlugin(...)` API (6 call sites).
- Removed unused internal-API imports (`HighlightInfo`, `HighlightInfoType`)
  from `VulnSpeedAnnotator`.

## [2026.6.0] - 2026-06-10

### Added
- **Secrets detection (12 rules, CWE-798).** New `SECRET_*` ruleset detects
  hardcoded AWS access keys, GitHub/GitLab/Slack/npm tokens, Stripe live keys,
  Google/SendGrid/Twilio API keys, private key blocks, JWT literals, and
  credentials embedded in URLs. Vendor-specific token formats keep false
  positives near zero, and every finding ships a rotation-focused fix suggestion.
- **Inline suppression directives.** `// vulnspeed-ignore` (same line or a
  comment line above) suppresses findings on a line, `// vulnspeed-ignore:
  RULE_ID, OTHER_ID` suppresses selectively, and `vulnspeed-ignore-file` within
  the first five lines opts out a whole file. Works with `//`, `#`, `--`, `;`,
  block, and HTML comment styles.
- **HTML report export.** Tools → VulnSpeed → Export HTML Report renders the
  latest scan as a single self-contained HTML file (severity summary cards +
  per-finding table with CWE links), ready to share with a security team.
- **Kotlin inline highlighting.** The as-you-type annotator now registers for
  Kotlin via an optional plugin dependency — previously advertised but never wired.
- **Tool window icon** (13 px, light + dark) and a dark-theme marketplace
  plugin icon (`pluginIcon_dark.svg`).

### Changed
- **Modernized settings UI.** Both the application and project settings pages
  are now built with the IntelliJ Kotlin UI DSL — grouped sections (Real-Time
  Analysis / Performance / Privacy), aligned labels, inline help comments, and
  a properly sized numeric "Max file size" field with a `KB` suffix instead of
  the previous stretched full-width text box.

### Fixed
- **Inline highlights never appeared in the editor.** The annotator gated on
  `firstChild` (whose range is just the first token), so every finding outside
  it threw "Range must be inside element being annotated" and was dropped. It
  now annotates on the file node, whose range covers the whole document.
- **Project settings were never saved.** The hand-rolled project configurable
  hard-coded `isModified = true` and had an empty `apply()`; the bound UI DSL
  now persists Scan-on-save / Auto-fix-on-save correctly.
- **Tool window population crashed off the EDT.** Scan actions added content to
  the VulnSpeed tool window from a background thread (`ContentManager` is
  EDT-only); results are now published via `invokeLater`.
- **Findings in the first 10 columns of a line were silently dropped.**
  Snippet extraction used `minOf(0, column - 10)` instead of `maxOf`, producing
  a negative substring index; the resulting exception aborted the rule's whole
  file scan and swallowed every remaining finding.
- **Editor annotations never appeared reliably.** The annotator created
  annotations from `invokeLater` on a pooled thread after the highlighting pass
  had finished — `AnnotationHolder` is only valid synchronously. Scanning now
  runs inside `annotate()`.
- **8 duplicate rule IDs** (`API_001–003`, `GRAPHQL_001–003`, `INPUT_001`,
  `SESSION_001` existed twice) broke per-rule suppression, SARIF rule metadata,
  and baseline fingerprints. The advanced variants are now `*_ADV_*`.
- Engine and annotator exceptions are now logged via the platform `Logger`
  instead of `printStackTrace()`.

### Tests
- 56 new tests (250 total): suppression directives, secrets rules incl.
  negative samples, HTML exporter escaping/structure, and engine regression
  tests for the column-1 snippet crash and rule-id uniqueness.

## [2026.4.6] - 2026-04-17

### Fixed
- **IntelliJ Platform API compatibility (2025.3 / 2026.1).** Replaced all 5
  scheduled-for-removal API usages (`PluginId.findId(String)`) with the modern
  `PluginId.getId(String)` equivalent in `ExportCycloneDxSbomAction`,
  `ExportSarifReportAction`, `CompareAgainstVulnBaselineAction`,
  `CreateVulnBaselineAction`, and `EnrichVulnerabilitiesAction`. Without this
  change, the SBOM/SARIF/baseline/enrichment actions would have stopped
  resolving the plugin descriptor in the next major IntelliJ Platform release.
- **Deprecated API removals.** Replaced all 3 usages of the deprecated
  `FileSaverDescriptor(title, description, String... extensions)` constructor
  with `FileSaverDescriptor(title, description).withExtensionFilter(ext)`
  in the CycloneDX SBOM, SARIF report, and baseline-diff export dialogs.

### Changed
- Bumped IntelliJ Platform Gradle plugin to `2.6.0` and extended plugin
  verification matrix to include `IC-2025.1.7`, `IC-2025.2.6.1`,
  `IC-2025.3.2`, and `IC-2026.1`.

## [2026.4.5] - 2026-04-17

### Added
- **CVE Enrichment Layer (OSV + NVD).** Scan findings whose `ruleId` contains a
  `CVE-YYYY-NNNNN` identifier are resolved against
  [OSV.dev](https://osv.dev) (primary) and [NVD](https://nvd.nist.gov)
  (fallback), yielding CVSS score / vector, textual severity, CWE mappings,
  published / modified timestamps, reference URLs, fixed versions and affected
  version ranges.
- **Offline-first disk cache.** Responses are persisted to
  `<configPath>/vulnspeed/cve-cache/` inside the IDE (or `~/.vulnspeed/cve-cache/`
  for CLI/CI) with atomic writes and a configurable TTL (default 7 days). Each
  CVE is a single JSON file, trivially cacheable across CI jobs.
- **Resilient HTTP transport.** Retries with exponential backoff, honours
  `Retry-After` on HTTP 429, treats 404 as "not found" (non-retry), and
  swallows per-finding errors so one missing CVE never fails a whole scan.
- **Headless CVE CLI.**
  `com.jakubjirak.vulnspeed.enrichment.CveEnrichmentCli` reads a findings JSON
  array, enriches each entry, emits Markdown or JSON, and exits `2` when
  `--fail-on-severity=HIGH|CRITICAL` trips — ready for PR gating.
- **IDE action.** **Tools → VulnSpeed → Enrich Findings with CVE Metadata**
  surfaces the last scan as a JBTable with CVSS, severity, CWE and fix-version
  columns and a one-click Markdown export.
- **Extensive tests.** OSV/NVD parsers, retry/backoff, 429/404 behaviour,
  cache TTL & atomic writes, orchestrator fallback, Markdown reporter and
  CLI exit codes are all covered against an in-process
  `com.sun.net.httpserver.HttpServer` — 100% offline, zero flaky network calls.



### Added
- **Security Baseline & Differential Scan.** Snapshot the current scan as an
  accepted baseline via **Tools → VulnSpeed → Create Security Baseline**. The
  baseline is written atomically to `<project>/.vulnspeed-baseline.json` with
  deterministic SHA-256 fingerprints over `ruleId|cwe|relativeFilePath|line|
  normalizedMessage`. Subsequent runs of **Compare Against Security Baseline**
  open a three-tab dialog (New Regressions / Fixed / Persisted) and can copy a
  PR-ready Markdown report, export the diff as JSON, update the baseline, or
  jump to the first regression in the Problems view.
- **Headless baseline CLI** (`com.jakubjirak.vulnspeed.baseline.VulnBaselineCli`)
  with `--create` / `--compare`, configurable `--fail-on=regression` or
  `--fail-on=severity:HIGH`, and `--output=md|json`. Exits `2` when the policy
  trips so CI can gate builds without the IDE.

## [2026.4.3] - 2026-04-17

### Added
- **CycloneDX v1.5 SBOM export.** New action **Tools → VulnSpeed → Export
  CycloneDX SBOM** emits a Software Bill of Materials JSON file
  (`vulnspeed-sbom.cdx.json`) compatible with Dependency-Track, Sonatype
  Lifecycle, GitHub Dependency Graph, and FOSSA. Components are discovered
  from `pom.xml`, `package.json` + `package-lock.json`, `requirements.txt`,
  and literal Gradle `implementation("g:a:v")` strings. Vulnerabilities from
  the latest cached scan are cross-referenced into the `vulnerabilities[]`
  section with CVSS v3.1 ratings and CWE identifiers.
- Deterministic UUIDv5 `serialNumber` derived from sorted component PURLs —
  identical inputs yield identical SBOM identifiers, which makes SBOM diffs
  in Git and change-detection in Dependency-Track trivially reliable.

## [2026.4.2] - 2026-04-15

### Added
- **SARIF v2.1.0 report export.** New action **Tools → VulnSpeed → Export SARIF
  Report** writes the latest scan as a fully-schema-compliant SARIF 2.1.0 JSON
  file. Designed for direct ingestion by GitHub Code Scanning
  (`actions/upload-sarif@v3`), GitLab SAST, Azure DevOps, SonarQube, and
  DefectDojo. Findings carry stable `partialFingerprints` so downstream systems
  can deduplicate across runs.
- Project-level `LastScanResultHolder` service caches the most recent scan so
  report export does not need to re-scan unless no scan has run yet.

### Changed
- `ScanFileAction` and `ScanProjectAction` now publish their results into the
  new `LastScanResultHolder`.

## [2026.4.1] - 2026-03-28

### Fixed
- Rebuilt plugin distribution to fix "archive cannot be extracted" error on
  JetBrains Marketplace.
