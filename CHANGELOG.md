# Changelog

All notable changes to **VulnSpeed** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic-ish date versioning](https://jakumjirak.example) (`YYYY.M.release_order`).

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
