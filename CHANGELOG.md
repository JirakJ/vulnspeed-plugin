# Changelog

All notable changes to **VulnSpeed** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic-ish date versioning](https://jakumjirak.example) (`YYYY.M.release_order`).

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
