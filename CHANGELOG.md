# Changelog

All notable changes to the **SOC Alert Analyzer** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.6] - 2026-10-21

### Added
- **In-Memory Active Candidate Index**: High-speed in-memory indexing for $O(1)$ intra-batch recurrence deduplication during high-volume security log ingestion.
- **Dedicated Standalone Verification Scripting**: Added standalone verification script (`scripts/verify_release_checksum.py`) validating digest format, binary presence, and exact hash matches.

### Changed
- **Route Architecture & Shadowing Elimination**: Removed duplicate shadowed route handlers in `app/main.py` (`/api/v1/host/monitor/toggle`, `/api/v1/simulation/toggle`, `/api/v1/stream/toggle`, `/api/v1/stream/status`), moved `/api/v1/sample-data/load/{dataset_type}` to `app/api/routes.py`, and added route-organization assertions (`tests/test_route_organization.py`) guaranteeing zero duplicate path/method registrations across the application.
- **Canonical Version Synchronization**: Unified package versioning across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` application metadata to strictly align with release `v1.2.6`.
- **Release Verification & Documentation**: Reconciled documentation, badges, changelog records, and evaluation metrics to accurately reflect **230 passing tests**, **86% (Linux) / 88% (Windows)** cross-platform test coverage, and v1.2.6 verified standalone executable status.

### Fixed
- **Provenance-Isolated Alert Recurrence**: Fixed sliding-window deduplication in `app/security/host_sensor.py` and `app/api/routes.py` to filter strictly on matching `telemetry_origin`, preventing cross-origin contamination between `HOST_TELEMETRY`, `HISTORICAL_LOG`, `SIMULATED_DEMO`, and `SECURITY_DRILL`.
- **Event-Timestamp-Anchored Deduplication Window**: Transitioned deduplication from wall-clock time (`datetime.now()`) to incoming event timestamps (`ev_ts ± DEDUP_WINDOW_SECONDS`), enabling robust sliding-window deduplication for historical batch uploads/replays, bounded isolation for future-dated clock anomalies, safe non-merging for stale out-of-order events, and deterministic most-recent candidate selection (`ORDER BY desc(coalesce(last_seen, timestamp))`).
- **Recurrence Edge-Case Hardening**: Resolved intra-batch burst deduplication race conditions by enforcing transactional flushes in `host_sensor.py` and `routes.py`, hardened username whitespace sanitization to `None`, guaranteed boundary preservation for legacy null-timestamp records, and enforced non-merge isolation for resolved/closed alerts.
- **Alert Recurrence Multi-Field Precision**: Refined deduplication matching in `host_sensor.py` and `routes.py` to evaluate `destination_ip` and `username`, preventing erroneous merging of distinct user accounts or network endpoints with identical generic rule descriptions.
- **Host Sensor Status & Event Loop Reliability**: Fixed `HostSecuritySensor.get_host_info()` to accurately report `stream_manager.host_monitoring_active` rather than `simulation_active`. Upgraded stream toggles to `async def` and stored application event loop references to guarantee dependable background task spawning on restart across execution contexts.

### Performance & Internal Improvements
- **High-Performance Ingestion & Batched Transaction Resilience**: Replaced individual `db.flush()` calls on every event in `app/api/routes.py` with an in-memory active candidate index for $O(1)$ intra-batch recurrence deduplication and bounded chunked flushes (`DB_BATCH_SIZE = 250`). Wrapped the entire ingestion, flushing, and correlation pipeline in an atomic database transaction with automatic `db.rollback()` on failure, eliminating partial imports, dirty session states, and excessive round-trips. Delivered an **8.3x throughput speedup** (from ~904 to ~7510 events/sec on 1,000-event datasets).
- **Test Suite & CI Matrix Expansion**: Expanded automated test suite from 203 to **230 passing tests** across 6 platform/Python configurations (Ubuntu/Windows on Python 3.11, 3.12, 3.13) + Security Audit.
- **Hardened Windows Standalone Executable Verification**: Rebuilt standalone executable `SOC_Alert_Analyzer.exe` (26,543,857 bytes) on GitHub Actions Windows release runner and verified with SHA-256 digest `722a33735a61fb613cb67225f679bfd61b19a2518baacf556c4d532c97edba1c`.

### Security
- **Hardened Fail-Closed Production Configuration**: Blocked insecure overrides by failing closed (`RuntimeError`) if `COOKIE_SECURE=false` or `DEMO_MODE=true` in `ENVIRONMENT=production`.

---

## [1.2.5] - 2026-10-21

### Added
- **Synchronized Monitoring & Simulation Controls**: Authoritative configuration-driven initialization for real host security monitoring (`HOST_MONITORING_ENABLED`) and demonstration threat simulation (`SIMULATION_ENABLED`). Disentangled frontend dashboard controls into dedicated `Host Sensor` and `Simulation` buttons backed by non-optimistic confirmed state updates (`app/security/stream.py`, `app/main.py`, `app/static/js/app.js`, `app/templates/dashboard.html`).
- **Persistent Alert Recurrence Tracking & Deduplication**: Extended the `Alert` database model with `occurrence_count`, `first_seen`, and `last_seen` timestamp boundaries. Deduplication within sliding time windows (`DEDUP_WINDOW_SECONDS = 300`) monotonically increments occurrences and updates chronological visibility windows rather than silently dropping repeated detections. Includes lightweight auto-migration and Alembic migration `31a8e8b2f901` (`app/models/alert.py`, `app/database/connection.py`, `alembic/versions/31a8e8b2f901_add_alert_recurrence_tracking.py`).
- **Production Configuration Fail-Closed Safety**: Enforced strict validation ensuring production environments cannot disable authentication or activate insecure testing bypasses (`ALLOW_INSECURE_AUTH_DISABLED`). Session cookies automatically default to the `Secure` attribute in production deployments while preserving seamless local loopback HTTP operation in development and standalone desktop modes (`app/config.py`).
- **Independent Modular Detection Benchmark Suite**: Centralized behavioral evaluation scenarios into a versioned modular dataset (`app/security/detection_benchmark.py` v2.1.0) with automated overlap and train/test data leakage assertions. Generates machine-readable evaluation reports (`docs/detection_evaluation_report.json`).
- **Automated Checksum Verification & Packaging Integrity**: Added standalone verification script (`scripts/verify_release_checksum.py`) validating digest format, binary presence, and exact hash matches. Integrated automated SHA-256 assertions and smoke tests into CI and release workflows.
- **Enforced CI Coverage Floor**: Integrated `--cov-fail-under=85` into GitHub Actions CI workflows, enforcing test coverage standards across Ubuntu and Windows matrices. Expanded automated test suite to **203 passing tests** with **88% code coverage**.

---

## [1.2.4] - 2026-10-20

### Added
- **Dashboard Stats Security & Telemetry Isolation**: Enforced user-aware role authorization on `GET /api/v1/dashboard/stats`. Anonymous visitors strictly receive statistics aggregated from `SIMULATED_DEMO` telemetry, while authenticated roles (`ADMIN`, `ANALYST`, `VIEWER`) obtain genuine operational metrics (`tests/test_api_stats_security.py`).
- **WebSocket Heartbeat Sensitive Telemetry Classification**: Host heartbeats (`HEARTBEAT`) are classified as sensitive telemetry. Unauthenticated demo viewers receive sanitized demonstration heartbeats (`demo-soc-sensor-01`), withholding real hostnames, IPs, and platform details. Authenticated analysts receive raw operational telemetry (`tests/test_stream_heartbeat_security.py`).
- **Time-Bounded Alert Deduplication & PID Reuse Resolution**: Replaced unbounded set storage in `HostSecuritySensor` with a timestamped sliding window (`DEDUP_WINDOW_SECONDS = 300`). Process signatures incorporate process creation times (`create_time`) to prevent false-suppression of distinct processes upon OS PID reuse. Added automatic pruning when signature cache exceeds bounds (`tests/test_dedup_time_window.py`).
- **Decoupled Host Monitoring & Threat Simulation**: Strictly segregated real-time host intrusion auditing (`host_monitoring_active`) from synthetic demonstration threat generation (`simulation_active`). Added independent granular toggle routes (`POST /api/v1/host/monitor/toggle`, `POST /api/v1/simulation/toggle`, `GET /api/v1/stream/status`). Demo threat generation isolates SQL aggregation strictly to synthetic alerts (`tests/test_simulator_separation.py`).
- **Hardened Docker & Environment Propagation**: Propagated `ENVIRONMENT`, `COOKIE_SECURE`, `ALLOW_INSECURE_AUTH_DISABLED`, `ALLOWED_ORIGINS`, and `DEDUP_WINDOW_SECONDS` to `docker-compose.yml`, accompanied by container health checks via `/api/v1/stream/status`.
- **Deep Coverage Expansion**: Boosted automated test suite to **179 passing tests (100%)** and **88% codebase coverage**, verifying deep edge cases across all log parsers (`firewall.py` 100%, `wazuh.py` 98%, `web_access.py` 96%, `suricata.py` 95%, `windows_event.py` 90%), `mitre_mapper.py` (99%), `risk_engine.py` (97%), and API route lifecycle transitions.

### Changed
- **Windows Local Credential Access Control**: Configured `icacls` invocation in local standalone credential generation to properly format `USERDOMAIN\USERNAME` principal and grant full control permissions (`(F)`), ensuring persistent portability and reliable loading across Windows environments.
- **Standalone Windows Executable**: Rebuilt standalone executable `dist/SOC_Alert_Analyzer.exe` with updated version `1.2.4` and verified runtime HTTP API smoke tests on Windows.

---

## [1.2.3] - 2026-10-20

### Added
- **Authentication-Disabled Security**: Restrict unauthenticated mode strictly to verified loopback sockets (`127.0.0.1`, `::1`, `localhost`, `testclient`). Remote access is rejected with `403 Forbidden`. External spoofable headers (`Host`, `X-Forwarded-For`) are disregarded for authentication.
- **Strict Startup Configuration**: Prohibit `AUTH_ENABLED=False` in `ENVIRONMENT=production` and require explicit `ALLOW_INSECURE_AUTH_DISABLED=true` in development.
- **Origin & CORS Validation (RFC 3986)**: Reject malformed origins containing paths, queries, fragments, or user credentials. Restrict localhost origins to standard web ports (80, 443, 8080) and launcher ranges (8000–8099). Disallow wildcard `*` with credentials.
- **Atomic Session Rotation**: Thread-safe session rotation under mutex locks to prevent fixation race conditions. Added bounded memory stores (`MAX_SESSIONS = 10000`, `MAX_WS_TICKETS = 5000`) and automatic pruning of stale attempts and lockouts.
- **Threat Stream RBAC**: Granular WebSocket stream filtering ensuring raw `HOST_TELEMETRY` and `REAL_THREAT` events are broadcast strictly to authenticated `ADMIN` and `ANALYST` clients.
- **Single-Worker Launcher Guard**: Added explicit guard in `launcher.py` rejecting `--workers > 1` to prevent unshared in-memory session and ticket desynchronization across multi-worker architectures.
- **Held-Out Detection Benchmark**: Implemented 30-scenario held-out evaluation dataset (15 malicious threats, 15 difficult benign edge cases) plus alert deduplication testing (`tests/detection_eval/test_eval_held_out_benchmark.py`).
- **Empirical Detection Evaluation Runner**: Added standalone evaluation script (`scripts/evaluate_detection.py`) generating confusion matrices across 50 total scenarios (100% Precision, 100% Recall, 0% FPR).
- **Hardened Standalone Windows Executable**: Rebuilt `SOC_Alert_Analyzer.exe` with verified background HTTP API smoke tests and updated SHA-256 release checksum (`8b14680499e985b6f2823cad397f7e061c098c97023c2a686fcdf25c11133170`).

### Changed
- **Correlator Ingestion Sorting**: Chronologically sort alerts before time-window clustering to guarantee deterministic incident aggregation under out-of-order log ingestion.
- **Suricata Parser Precision**: Replaced naive substring matching (`"dos"`) with word-boundary regular expressions (`\bdos\b`) and contextual phrases, eliminating false positives on benign words like "shadows" or "paradox".
- **Risk Scoring Resilience**: Clamped composite risk scores strictly between 0 and 100 with defensive guards against `NaN` and `Inf` float confidence inputs, providing safe defaults for missing event types.
- **MITRE ATT&CK & Host Sensor Refinements**: Refined mappings for `T1003` (OS Credential Dumping), `T1105` (Ingress Tool Transfer), `T1204.002` (Malicious File), `T1490` (Inhibit System Recovery), and `T1036.005` (Masquerading). Added behavioral detection for LSASS memory dumps, `certutil` download cradles, and firewall disablement.

### Fixed
- Expanded automated test suite from 115 to **139 passed tests (100%)** with **79% code coverage**.
- Resolved documentation discrepancies, synchronizing all architectural specifications with actual implementation state.

---

## [1.2.2] - 2026-10-20

### Added
- HTML Route Access Controls: Enforced authentication across all server-rendered endpoints (`/alerts`, `/incidents`, `/alerts/{id}`, `/incidents/{id}`, `/upload`). Anonymous visitors are isolated to `SIMULATED_DEMO` telemetry, and host metrics are redacted for unauthenticated guests.
- Automated HTML access control regression test suite (`tests/test_html_route_security.py`).
- Cross-platform process masquerading detection and test parity (`tests/test_host_sensor_behavioral.py`).
- Expanded empirical host behavioral detection benchmark suite to 20 balanced scenarios (10 true positives, 10 true negatives) including false-positive edge cases (`docs/detection_evaluation.md`).

### Changed
- WebSocket Origin validation: Rewrote `is_allowed_origin` in `app/security/auth.py` with strict scheme, host, and port matching, restricting loopback connections to standard web ports (80, 443, 8080) and launcher ranges (8000–8099), preventing Cross-Site WebSocket Hijacking without relying on unvalidated Host headers.
- Replaced legacy `soc_api_key` cookie and WebSocket query parameter authentication (`?token=`, `?api_key=`) with cryptographically secure session management and short-lived tickets.
- Removed legacy API key storage and lookup in frontend `app/static/js/app.js`.

### Fixed
- Fixed Linux CI failures in Ubuntu Python 3.11–3.13 environments by removing platform gating from host sensor masquerading detection.
- Fixed logout CSRF vulnerability: Enforced double-submit `X-CSRF-Token` header verification for active browser session revocation in `POST /api/v1/auth/logout`.
- Expanded test suite from 88 to 115 passing tests across Windows and Linux environments.

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
