# Changelog

All notable changes to the **SOC Alert Analyzer** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.1] - 2026-10-20

### Added
- Cryptographic server-side session management (`app/security/session.py`) using 256-bit high-entropy tokens (`soc_...`).
- Server-side SHA-256 token hashing to prevent plaintext exposure in memory dumps.
- Automatic session pruning, session rotation on authentication to prevent fixation, and explicit server-side revocation on logout (`POST /api/v1/auth/logout`).
- Double-Submit Cookie CSRF protection via `soc_csrf` cookie and `X-CSRF-Token` header validation for state-changing browser requests (`POST`, `PUT`, `DELETE`, `PATCH`).
- Short-lived, single-use WebSocket connection tickets (`POST /api/v1/auth/ws-ticket` -> `wst_...`) eliminating long-lived credentials from query parameters and access logs.
- Strict Origin header validation on `/ws/threats` rejecting Cross-Site WebSocket Hijacking (CSWSH) with policy code `1008`.
- Granular telemetry streaming separation withholding genuine host findings and raw logs from unauthenticated users and demo viewers.
- Automated executable background HTTP API smoke tests in GitHub Actions release workflow.
- Standard project governance documents: `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and GitHub issue/PR templates.

### Changed
- Replaced plaintext API keys in cookies with opaque, secure session tokens (`HttpOnly`, `SameSite=Lax`, `Secure`).
- Updated frontend client (`app/static/js/app.js`) to attach `X-CSRF-Token` headers and utilize single-use WebSocket tickets.
- Synchronized documentation, acceptance criteria, and `.env.example` to 25 MB max upload limit.
- Replaced Python checksum instructions with native PowerShell `Get-FileHash` commands.
- Expanded operational limitations in `README.md` clarifying boundaries between an EDR-Lite workbench and enterprise SIEM/kernel-EDR tools.

### Fixed
- Fixed unauthenticated access to real alerts and host status by returning sanitized demonstration datasets when unauthenticated.
- Expanded automated test suite from 82 to 88 passing pytest tests (100% pass rate).

---

## [1.2.0] - 2026-10-19

### Added
- Natural operational notifications with single-shield icon (`🛡️`) and human-friendly clearance prompts.
- Access clearance modal with password visibility eye toggles and `%LOCALAPPDATA%` credential guidance.
- Rich event narrative synthesis eliminating generic fallback alerts.
- Structured composite correlation key (`correlation_key`) preventing duplicate incidents across batches.
- RFC-compliant IP classifier for Carrier-Grade NAT (RFC 6598), documentation blocks (RFC 5737, RFC 3849), and benchmark ranges.
- Standalone Windows executable release workflow in GitHub Actions.

### Changed
- Hardened production startup to fail immediately on known default secrets or weak keys.
- Bounded file upload streaming to 25 MB and capped events per upload to 5,000.
- Implemented batched database commits (250 items per batch).
- Updated Flake8 forward-reference type annotations in ORM models.

---

## [1.1.0] - 2026-10-18

### Added
- Role-Based Access Control (RBAC) with `ADMIN`, `ANALYST`, and `VIEWER` tiers.
- Behavioral host sensor (EDR-Lite) inspecting parent-child process trees, system binary masquerading, LOLBins, and ransomware shadow copy deletion.
- Multi-format timestamp normalizer preserving invalid timestamp flags.
- SQL-level aggregation and pagination for alerts and KPI metrics.

---

## [1.0.0] - 2026-10-15

### Added
- Initial release of SOC Alert Analyzer.
- Multi-format log parsing (Wazuh, Suricata, Linux auth.log, Windows Event logs).
- 0-100 explainable risk scoring engine.
- MITRE ATT&CK technique mapping.
- Nicole's Security Lab UI/UX visual theme and dashboard.
- Real-time WebSocket threat feed.
