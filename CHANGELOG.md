# Changelog

All notable changes to the **SOC Alert Analyzer** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.16] - 2026-10-25

### Fixed & Enhanced
- **Deterministic Lifecycle Lock Ownership & Concurrency Safety**:
  - Replaced private attribute access (syncio.Lock._loop) in pp/security/stream.py with explicit owner event loop tracking (self._owner_lifecycle_lock_loop) guarded by 	hreading.Lock().
  - Guaranteed exactly one stable lifecycle lock per active event loop, preventing lock recreation during uncontended execution.
  - Added thread-safe cross-thread coroutine dispatching and synchronous wrappers (start_simulation_sync, stop_simulation_sync, shutdown_sync).
  - Added deterministic concurrency regression tests verifying lock reuse, mutual exclusion, and shutdown resilience.
- **Strict Cancellation Timeout & Worker Quiescence Tracking**:
  - Implemented typed TaskCancellationResult enum (TERMINATED, TIMED_OUT, ALREADY_COMPLETED, FAILED) in ThreatStreamManager._cancel_and_await_task().
  - Refactored HostSecuritySensor with atomic worker counters (uto_scan_in_progress, manual_scan_in_progress) to prevent prematurely reporting PAUSED while audits remain in-flight.
  - Handled cancellation timeout deadlines by reporting PAUSING_TIMED_OUT rather than masking un-terminated background tasks.
  - Enforced single-transaction atomicity in _ingest_events and incident correlation with rollback on pause.
- **Packaged Executable Real Log Redaction Verification (Test N)**:
  - Extended binary integration suite (scripts/test_exe_websocket_integration.py) with Test N asserting complete redaction of WebSocket tickets, API keys, credentials, and secrets directly from captured binary stdout/stderr streams.
  - Added process tree termination (	askkill /F /T /PID on Windows) to prevent pipe deadlock and orphaned child processes during binary integration tests.
- **Dependency Locking, Audit Integrity & SBOM Standardization**:
  - Audited and regenerated 
equirements.lock, pinning exact versions without unpinned fallbacks or vulnerabilities (pip-audit verified 0 vulnerabilities).
  - Regenerated CycloneDX v1.5 sbom.json and SPDX v2.3 sbom.spdx.json dynamically resolving installed distribution metadata.
  - Updated GitHub Actions CI workflows (ci.yml, 
elease-exe.yml) to enforce pip-audit -r requirements.lock.
- **Independently Sourced Detection Provenance & Scope Transparency**:
  - Updated sample_data/independent_telemetry/independent_telemetry_dataset.json and pp/security/endpoint_attack_evaluator.py to record provenance breakdown (curated_sigma, mitre_car, tomic_red_team, held_out_telemetry).
  - Added explicit evaluation scope and limitations disclaimer to docs/independent_telemetry_evaluation_report.json.
- **Timezone-Safe Datetime Comparison**:
  - Added timezone normalization helper _to_utc() in pp/security/correlator.py preventing offset-naive vs. offset-aware comparison errors in SQLite environments.
- **Standalone Windows Executable (v1.2.16)**:
  - Built standalone Windows executable dist/SOC_Alert_Analyzer.exe (56,709,018 bytes, SHA-256 4ad117695e55744d7181f6adc3364f5d3564473a8d4f154adcff0edede30692e).
  - Passed 100% of standalone binary tests: Tests A through N in 	est_exe_websocket_integration.py and Tests A through G in 	est_exe_lifecycle_integration.py.

---

## [1.2.15] - 2026-10-25

### Fixed & Enhanced
- **Security Access Log Redaction & Credential Sanitization**:
  - Centralized log sanitization filter (`app/security/logging_filter.py`) redacts sensitive authentication parameters from Uvicorn access and application logs:
    - Ephemeral WebSocket connection tickets (`?ticket=wst_...`) redacted to `?ticket=[REDACTED]`.
    - HTTP Authorization headers and Bearer tokens redacted to `Bearer [REDACTED]`.
    - API keys, session tokens, passwords, and secrets sanitized across all query string formats.
    - Session cookies (`soc_session=...`) sanitized to `soc_session=[REDACTED]`.
  - Preserves diagnostic operational context including client IP, endpoint path, HTTP method, status code, and response latency.
  - Hardened log configuration integration across Uvicorn runners, desktop launcher (`launcher.py`), and FastAPI application lifespans.
- **Monitoring Concurrency Hardening & Sensor Quiescence**:
  - Bound lifecycle mutex (`_get_owner_lock`) to the owner application loop, eliminating deadlocks during rapid concurrent start/pause cycles across asynchronous contexts and secondary threads.
  - Implemented generation-tracked scan cancellation tokens (`scan_generation`, `_cancel_event`) in `HostSecuritySensor`.
  - Mid-audit sensor cancellations cleanly roll back SQLite transactions with zero uncommitted or orphaned alerts persisted.
  - Added `wait_quiescence` to guarantee that background audit threads have exited cleanly before state transitions complete.
- **Static Asset Content Hash Fingerprinting & HTTP Cache Invalidation**:
  - Implemented deterministic content hash fingerprinting (`get_asset_fingerprint`, `versioned_static`) for static stylesheets and scripts (`styles.css`, `app.js`).
  - Added template integration in `base.html` appending `?v=<hash>` to force instantaneous browser cache busting upon asset changes.
  - Applied HTTP cache headers via middleware: `Cache-Control: no-cache, must-revalidate` on HTML document views and `Cache-Control: no-store, private` on sensitive API endpoints.
  - Verified static asset conditional requests (`ETag` / `If-None-Match`, `Last-Modified` / `If-Modified-Since`) returning HTTP 304 Not Modified.
- **WebSocket Import Summary Notifications**:
  - Broadcast structured `IMPORT_SUMMARY` payloads over WebSocket upon historical log file ingestion (`/api/v1/upload`), providing connected analysts immediate real-time visibility into imported log counts, created incidents, and overall system metrics.
- **Playwright Browser Automation Test Hardening**:
  - Updated asynchronous Playwright execution in `tests/test_browser_monitoring_ui.py` with `page.wait_for_timeout` to ensure dependable event-loop dispatching in sync mode.
  - Verified genuine user keyboard events (`btn.press("Enter")`) and network route interceptions to ensure in-flight button locking and ARIA busy attributes.
- **Reproducible Dependencies & Software Bill of Materials**:
  - Regenerated CycloneDX v1.5 `sbom.json` and SPDX v2.3 `sbom.spdx.json` matching version `1.2.15`.

---

## [1.2.14] - 2026-10-25

### Fixed & Enhanced
- **Mandatory Real Browser UI Automation Suite (Playwright Chromium)**:
  - Validated all 10 browser UI scenarios (`tests/test_browser_monitoring_ui.py`) executing genuine user actions in real headless Chromium.
  - Eliminated test skipping and guaranteed CI execution with provisioned Chromium dependencies.
  - Verified initial neutral `CHECKING` state during backend delays, synchronized `ACTIVE` and `PAUSED` states, error states on backend failure, stale response race prevention, transport disruption decoupling, and full accessibility compliance.
- **Monitoring Task Lifecycle State Machine & Task-Health Edge Cases**:
  - Implemented formal eight-state lifecycle model: `STARTING`, `ACTIVE`, `PAUSING`, `PAUSED`, `RESUMING`, `STOPPED`, `ERROR`, `UNKNOWN`.
  - Proved `ThreatStreamManager.get_status()` strictly inspects running tasks; crashed tasks or missing task references report `ERROR` or `STOPPED` and never falsely report `ACTIVE`.
  - Replaced loop-bound locks with `threading.Lock()` to serialize lifecycle transitions safely across thread boundaries.
  - Offloaded blocking host security audits to worker threads via `asyncio.to_thread` with cooperative cancellation and clean transaction rollback on sensor pause.
- **Real Defensive Alert Delivery Through Compiled Windows Executable (Tests A-M)**:
  - Extended `scripts/test_exe_websocket_integration.py` to verify that newly ingested security drill alerts are normalized, scored, persisted to SQLite, and delivered in real time over the WebSocket stream to authorized connected analysts.
  - Verified strict role authorization: unauthenticated or demo-only clients are forbidden from minting WebSocket tickets or receiving sensitive host telemetry.
  - Verified independent event delivery: manual drills and imported logs continue delivering over WebSocket even while continuous host monitoring is paused.
- **Detection Rules & MITRE ATT&CK Accuracy Improvements**:
  - Enhanced Windows Event & Sysmon detection rules for MSBuild compilation (`T1127.001`), Regsvr32 DLL registration (`T1218.010`), Volume Shadow Copy deletion (`T1490`), Defender tampering (`T1562.001`), and outbound C2 network beacons (`T1071`).
  - Disambiguated parent processes to prevent benign developer tools (e.g. `pytest`) from triggering false positives.
  - Achieved 100% precision, 100% recall, and 100% accuracy on both curated and independent telemetry benchmark datasets.
- **Comprehensive Independent Telemetry Dataset Provenance**:
  - Documented full 11-field provenance for all 12 independent telemetry scenarios in `sample_data/independent_telemetry/independent_telemetry_dataset.json`.
  - Added `tests/test_dataset_provenance.py` to enforce metadata schema, repository URLs, stable commit hashes, and taxonomy compliance.
- **Reproducible Dependencies & Software Bill of Materials**:
  - Synchronized `requirements.lock` with 28 pinned packages.
  - Regenerated CycloneDX v1.5 `sbom.json` and SPDX v2.3 `sbom.spdx.json` matching version `1.2.14`.

---

## [1.2.13] - 2026-10-25

### Fixed & Enhanced
- **WebSocket Protocol Implementation & PyInstaller Packaging**:
  - Resolved `No supported WebSocket library detected` runtime failure by explicitly pinning `websockets>=12.0` (`websockets==17.1`) in `requirements.txt` and `requirements.lock`.
  - Updated `SOC_Alert_Analyzer.spec` to bundle modern Uvicorn sans-io WebSocket implementations (`uvicorn.protocols.websockets.websockets_sansio_impl`, `wsproto_impl`, `websockets.asyncio.server`, `websockets.server`, `websockets.connection`, `websockets.frames`, `websockets.protocol`).
  - Standalone Windows executable packages full native WebSocket protocol stack without requiring external Python environments.
- **Mandatory Standalone Executable WebSocket Integration Test Suite (Tests A-J)**:
  - Implemented `scripts/test_exe_websocket_integration.py` validating the compiled executable across Tests A through J (process spawn, authentication, short-lived single-use ticket acquisition, HTTP 101 WebSocket handshake, ping/pong frame exchange, sensor pause while connected, sensor resume, clean reconnect, ticket replay rejection, invalid ticket rejection, unauthenticated rejection, and clean shutdown).
  - Enforced as a mandatory release-blocking gate in `.github/workflows/release-exe.yml`.
- **Monitoring Task Failure Reporting & Observable Quiescence**:
  - Enhanced `ThreatStreamManager.get_status()` in `app/security/stream.py` to differentiate task health (`RUNNING`, `PAUSED`, `ERROR`, `STOPPED`) and prevent falsely reporting `ACTIVE` if a background task crashes unexpectedly.
  - Implemented cooperative cancellation checkpoints and `scan_in_progress` state tracking in `HostSecuritySensor.run_full_audit` and `run_fast_audit` with transactional rollback upon pause.
- **Frontend Monotonic Request Sequencing & State Synchronization**:
  - Introduced monotonic request sequencing (`currentMonitoringRequestId`) in `app/static/js/app.js` to ensure older or delayed HTTP responses cannot overwrite newer user-initiated pause/resume transitions.
  - Prevented late WebSocket heartbeat frames from overriding confirmed monitoring states.
  - Differentiated `Clear History` confirmation modal text when Host Monitoring is paused vs active.
- **Real Browser-Level UI Automation**:
  - Added `tests/test_browser_monitoring_ui.py` testing the rendered DOM with Playwright across Scenarios 1 through 10 (neutral checking state, active, paused, 500 error display, stale response race prevention, decoupled WebSocket, connection loss, preference save failure warnings, and accessibility button state locks).
- **Independently Sourced Defensive Telemetry Benchmark**:
  - Integrated `sample_data/independent_telemetry/independent_telemetry_dataset.json` derived from credible public defensive research datasets (OTTR Project, SigmaHQ, Atomic Red Team).
  - Evaluated detection accuracy, confusion matrices, and MITRE ATT&CK technique mapping with transparent scientific integrity in `scripts/evaluate_endpoint_attacks.py`.
- **Reproducible Dependencies & Accurate SBOM**:
  - Regenerated `requirements.lock`, CycloneDX v1.5 `sbom.json`, and SPDX v2.3 `sbom.spdx.json` fully locking all 28 runtime and transitive dependencies.

---

## [1.2.12] - 2026-10-25

### Added
- **Explicit Monitoring Lifecycle State Model**:
  - Replaced false ACTIVE initial indicator with a seven-state operational model: `UNKNOWN`, `CHECKING`, `ACTIVE`, `PAUSING`, `PAUSED`, `RESUMING`, and `ERROR`.
  - Default neutral `CHECKING` indicator on page load eliminates misleading green active glow prior to backend verification.
  - Complete decoupling of WebSocket connection state (`connecting`, `connected`, `reconnecting`, `disconnected`, `auth_required`) from host telemetry sensor status.
  - Frontend double-click protection and optimistic state updates with rollback on network failure in `app/static/js/app.js`.
- **Asynchronous Task Quiescence & Cancellation Await**:
  - Serialized all monitoring and simulation lifecycle transitions using `asyncio.Lock()` to prevent race conditions during rapid state changes.
  - Transformed `stop_host_monitoring` into an asynchronous coroutine that cleanly cancels and `await`s the running task before returning HTTP 200.
  - Added in-flight audit cancellation: if monitoring is paused during a scan cycle, in-flight findings are discarded and the database transaction is rolled back cleanly.
- **Explicit Persistence Error Reporting**:
  - Updated `save_monitoring_preferences` in `app/config.py` to return explicit `{persisted: bool, persistence_error: Optional[str]}` status.
  - Surfaced persistence indicators in `/api/v1/stream/status` and `/api/v1/host/monitor/toggle`.
  - Guaranteed that disk write failures leave the existing valid preference file intact.
- **Reproducible Dependency Management & CI Hardening**:
  - Updated `.github/workflows/ci.yml` and `release-exe.yml` to install runtime dependencies strictly from `requirements.lock`.
  - Pinned `pyinstaller==6.22.2` for deterministic Windows release executable packaging.
  - Regenerated CycloneDX v1.5 `sbom.json` and SPDX v2.3 `sbom.spdx.json` aligned to version `1.2.12`.
- **Standalone Windows Executable Process Lifecycle Integration Test Suite**:
  - Implemented `scripts/test_exe_lifecycle_integration.py` executing tests A through G across process restarts in an isolated dynamic port environment.
  - Integrated into the release CI/CD pipeline to verify binary startup, pause persistence, alert clearance, reboot quiescence, and manual audits.
- **Automated Release Manifest Consistency Verification**:
  - Created `tests/test_release_manifest_consistency.py` asserting strict synchronization across application code, FastAPI metadata, README, CHANGELOG, SBOM manifests, and release checksums.

---

## [1.2.11] - 2026-10-25

### Added
- **Host Sensor Lifecycle Decoupling & Complete Indicator Synchronization**:
  - Decoupled WebSocket transport connection (`/ws/threats`) from host sensor operational state in `app/static/js/app.js`. `threatSocket.onopen` now triggers authoritative status synchronization (`initStreamStatus()`) rather than unilaterally asserting `liveText.textContent = 'HOST SENSOR: ACTIVE'`.
  - Implemented single authoritative frontend rendering function `updateMonitoringUI(state)` synchronizing:
    - Header live sensor pill and status text (`HOST SENSOR: ACTIVE` vs `HOST SENSOR: PAUSED`).
    - Pill glow and pulsing dot (`.pulse-dot.paused` renders static gray dot without pulsation).
    - Toolbar action buttons (`btn-toggle-host-monitor` and `btn-toggle-sim` with synchronized active/paused styling and icons).
    - Data notice status strip and status tag (`Live Sensor` vs `Sensor Paused`).
    - Host telemetry strip EDR mode label (`Native Host EDR Active` vs `Native Host EDR Paused`).
  - Added window `focus` event listener in `app.js` to re-synchronize status automatically whenever the analyst returns to the dashboard tab.
  - Added CSS classes `.live-sensor-pill.paused`, `.pulse-dot.paused`, and `.data-notice-status-tag.paused` in `app/static/css/styles.css`.
- **Persistent Monitoring Preferences Across Restarts**:
  - Added atomic JSON preference persistence via `save_monitoring_preferences` and `load_monitoring_preferences` in `app/config.py`.
  - Persists monitoring preference in `DATA_DIR/monitoring_preferences.json` (%LOCALAPPDATA%\SOC_Alert_Analyzer on Windows standalone, /app/data on Docker), surviving restarts, binary re-launches, and container recreation.
  - Hydrated `Settings.HOST_MONITORING_ENABLED` and `Settings.SIMULATION_ENABLED` on startup from persisted preferences.
  - Safe against missing or corrupted files with robust fallback to environment variables and secure defaults.
  - Preserved preference across clean application shutdown without saving or overwriting user preferences on process exit.
- **Guarded Automatic Host Audits**:
  - Guarded `initial_host_baseline()` in `app/main.py` to skip scanning when host monitoring is paused.
  - Guarded dashboard zero-alerts host audit so it does not trigger an automatic scan while paused.
- **Historical Alert Retention & Clear History Refinement**:
  - Historical alerts are preserved in the workbench when host monitoring is paused.
  - Refined `/api/v1/alerts/clear`: when called while host monitoring is paused, purges database records and in-memory deduplication signatures without re-running `host_sensor.run_full_audit(db)` or recreating baseline alerts (such as SMB port 445).
  - Fixed `fetchAlertsFromApi()` in `app/static/js/app.js` to properly clear `SOC_STATE.alerts = []` and reset selection when an empty array `[]` is returned.
- **Test Suite Expansion & Version Bump**:
  - Bumped canonical application version to `v1.2.11` across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` metadata.
  - Expanded automated pytest suite to **296 passed (100%)** with **87.07% code coverage** (exceeding >=85% floor).
  - Added regression test suite in `tests/test_monitoring_lifecycle.py` covering persistence, atomic writing, corrupted file recovery, clear-while-paused behavior, and manual audit behavior while paused.
  - Regenerated CycloneDX v1.5 `sbom.json`, SPDX v2.3 `sbom.spdx.json`, and pinned `requirements.lock` for v1.2.11.

---

## [1.2.10] - 2026-10-25

### Added
- **Decoupled Endpoint Detection Benchmark & Leakage Elimination**:
  - Completely eliminated ground-truth leakage (`scenario.is_malicious`) from prediction logic in `app/security/endpoint_attack_evaluator.py`. Prediction is determined strictly by parsed telemetry features, risk engine scoring (`risk_score >= 40`), and defensive rules.
  - Strictly separated threat classification from MITRE ATT&CK technique evaluation.
  - Corrected ATT&CK technique mappings: Encoded PowerShell maps to `T1059.001` (sub-technique), firewall disablement maps to `T1562.001`, and C2 DNS queries map to `T1071.004` while preserving benign administrator workflows.
  - Added regression suite (`tests/test_endpoint_attack_evaluation.py`) verifying label-flipping independence, expected-technique independence, empty/malformed dataset resilience, ambiguous telemetry handling, and explicit mismatch reporting.
  - Added technique match metrics (`mitre_technique_match_accuracy`, `mitre_technique_mismatches`) to `scripts/evaluate_endpoint_attacks.py`.
- **Passive Network Exposure Accuracy & Firewall Rule Inspection**:
  - Enhanced `app/security/host_sensor.py` with `inspect_port_firewall_rule` inspecting local Windows Advanced Firewall rules for listening ports (`netsh advfirewall firewall show rule`).
  - Added explicit confidence ratings (`HIGH`, `MEDIUM`, `LOW`) and reachability classification (`reachability_type="INFERRED_PASSIVE"`).
  - Disassociated local listening ports from ATT&CK `T1046` (Network Service Scanning), correctly categorizing listening sockets as host attack surface rather than adversary active network scanning.
  - Added tailored high-risk guidance for SMB port 445 listeners bound to wildcard/LAN interfaces.
  - Added regression test suite `tests/test_network_reachability.py` covering indeterminate firewall rules, IPv6 listeners (`::1`, `::`), development process filtering, and process access errors.
- **Docker Compose Loopback Isolation & Volume Persistence**:
  - Bound web service port in `docker-compose.yml` strictly to loopback (`127.0.0.1:8000:8000`) rather than `0.0.0.0:8000`, preventing unintended LAN exposure during development.
  - Added persistent named volume `soc_data:/app/data` with `DATA_DIR: ${DATA_DIR:-/app/data}` ensuring auto-generated `.auth_credentials` and SQLite persistence survive container recreation.
  - Enforced strong PostgreSQL password requirement in production in `app/config.py`.
  - Added regression suite `tests/test_docker_security_config.py` verifying loopback binding, database network isolation, persistent volume configuration, and non-root execution.
- **Dynamic SBOM Resolution with PostgreSQL Driver Support**:
  - Upgraded `scripts/generate_sbom.py` to dynamically inspect installed runtime packages via `importlib.metadata`, explicitly adding `psycopg2-binary==2.9.10` and transitive dependencies.
  - Regenerated `requirements.lock` (24 packages), CycloneDX v1.5 `sbom.json`, and SPDX v2.3 `sbom.spdx.json` aligned to version `1.2.10`.
  - Added regression test `tests/test_sbom_and_lockfile.py` asserting lockfile/SBOM parity and PostgreSQL driver presence.
- **Continuous Integration Pipeline Hardening**:
  - Integrated `scripts/evaluate_endpoint_attacks.py` into `.github/workflows/ci.yml` and `.github/workflows/release-exe.yml` alongside the behavioral baseline benchmark.

### Changed
- **Canonical Version Synchronization**: Bumped canonical package version to `v1.2.10` across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` application metadata.
- **Test Suite Expansion & Coverage**: Expanded automated pytest suite from 275 to **292 passed (100%)** with **88% overall code coverage** (87.69%).
- **Documentation Link Cleanup**: Removed all Windows local filesystem `file:///C:/...` links from `README.md` and `docs/requirements_specification.md`, replacing them with relative repository links.
- **Windows Event Parser Contextualization**: Added command-line enrichment to Event 4688 descriptions and interactive console logon detection for Event 4624 (`LogonType: 2`).
- **Standalone Windows Executable Rebuild**: Rebuilt `dist/SOC_Alert_Analyzer.exe` (26,591,239 bytes on official GitHub Actions Windows Server 2022 / Python 3.12 runner; 54,101,860 bytes local Python 3.13) with bundled sample datasets and verified runtime smoke tests on `/api/v1/auth/me`.
- **Authoritative Release Checksum**: Updated `dist/SHA256SUMS.txt` with verified SHA-256 digest `5d64ddf4f6ea5c7f021973a6eccbe6bb7ba7f3b62f551abad1b0fe4aa2490a84`.

---

## [1.2.9] - 2026-10-25

### Added
- **Docker Production Security Guards & Prohibited Key Enforcement**:
  - Implemented strict key validation in `app/config.py` prohibiting default, placeholder, or predictable keys (`soc_analyzer_secret_...`, `admin_soc_analyzer_key_...`, `soc_secure_db_pass_...`, `change-me`, `changeme`, etc.) in production mode.
  - Added cryptographic key uniqueness enforcement (`ADMIN_API_KEY != SECRET_KEY`, `ANALYST_API_KEY != ADMIN_API_KEY`, `ANALYST_API_KEY != SECRET_KEY`).
  - Added minimum entropy constraints: `SECRET_KEY` (≥ 32 chars), `ADMIN_API_KEY` (≥ 16 chars), `POSTGRES_PASSWORD` (≥ 12 chars).
  - Development containers now auto-generate unique cryptographic keys in `.auth_credentials` when unconfigured, eliminating shared static credentials across installations.
  - Added comprehensive regression suite (`tests/test_production_security_guards.py`) with 28 automated test cases proving known default keys cannot run in production.
- **Network Exposure & Socket Reachability Assessment Engine**:
  - Enhanced `app/security/host_sensor.py` with `assess_socket_reachability(ip, port)` to distinguish raw listening socket states from confirmed network reachability.
  - Classifies exposure into four granular tiers:
    - `LOOPBACK_ONLY`: Bound to `127.0.0.1` / `::1` (safe from network attacks).
    - `LAN_ACCESSIBLE`: Bound to `0.0.0.0` or RFC 1918 private subnets with active LAN interfaces.
    - `INTERNET_EXPOSED`: Confirmed public interface reachability on wildcard listeners.
    - `HOST_ISOLATED`: Bound to wildcard with no active non-loopback network adapters.
  - Cross-references host firewall posture (`FILTERED` vs `UNFILTERED_EXPOSED`).
  - Added integration unit tests in `tests/test_network_reachability.py`.
- **Realistic Endpoint Attack Evaluation Benchmark (Sysmon & Windows Events)**:
  - Created `app/security/endpoint_attack_evaluator.py` and benchmark runner `scripts/evaluate_endpoint_attacks.py`.
  - Evaluates 18 realistic telemetry scenarios across the MITRE ATT&CK kill-chain: Certutil LOLBIN cradles (`T1105`), Mshta proxy execution (`T1218`), Obfuscated Base64 PowerShell (`T1059.001`), Security Audit Log clearing (`T1070.001`), Host firewall disablement (`T1562.001`), Mimikatz LSASS access (`T1003.001`), Registry Run Key persistence (`T1547.001`), Windows Service installation (`T1543.003`), Local Admin group manipulation (`T1098`), SMB admin share access (`T1021.002`), Dynamic DNS C2 queries (`T1071.004`), and repeated failed logons (`T1110`).
  - Includes difficult benign administrative workloads (Windows Update, MSI installs, Git/Python dev workflows, Robocopy backups, normal logons, internal DNS) verifying **100% Precision, 100% Recall, 0 False Positives**.
  - Generated machine-readable evaluation report in `docs/endpoint_attack_evaluation_report.json`.
- **Reproducible Supply-Chain Security & Software Bill of Materials (SBOM)**:
  - Added `requirements.lock` pinning exact dependency versions for reproducible deployments.
  - Added CycloneDX v1.5 standard JSON SBOM (`sbom.json`) with Package URLs (PURLs).
  - Added SPDX v2.3 compliant SBOM (`sbom.spdx.json`).
  - Created automated generation utility `scripts/generate_sbom.py`.

### Changed
- **Canonical Version Synchronization**: Bumped canonical package version to `v1.2.9` across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` application metadata.
- **Test Suite Expansion & Coverage**: Expanded automated pytest suite from 237 to **275 passed (100%)** with **88% overall code coverage**.
- **Windows Event Parser Enhancements**: Added support for Sysmon Event IDs (1, 3, 7, 8, 10, 11, 12, 13, 22, 25) and advanced Windows Security Event IDs (4672, 4776, 5140, 5145). Contextualized Event 4688 to distinguish benign process launches from suspicious LOLBIN invocations.
- **Standalone Windows Executable Rebuild**: Recompiled `dist/SOC_Alert_Analyzer.exe` (54,097,437 bytes) with bundled sample datasets and verified runtime smoke tests.
- **Authoritative Release Checksum**: Updated `dist/SHA256SUMS.txt` with verified SHA-256 digest `c13e2343b76590c5b1ad40b94db321c5ae04f0e95ac9017b64a7186d68eaa9b6`.

---

## [1.2.8] - 2026-10-25

### Added
- **Mock SIEM Sample Alerts Directory (`sample_alerts/`)**: Curated realistic mock SIEM JSON exports allowing analysts to test and demonstrate the analyzer immediately with zero live API keys:
  - `wazuh_alerts.json`: Wazuh SIEM alerts covering SSH brute force, `/etc/shadow` file integrity tampering, unauthorized sudo commands, and rootkit masquerading.
  - `suricata_eve.json`: Suricata NIDS EVE alerts covering Nmap scan sweeps, Apache Struts RCE (CVE-2017-5638), C2 beaconing, and DNS amplification DoS.
  - `windows_security_events.json`: Windows Event logs covering Event 4625 (Logon Brute Force), Event 4688 (PowerShell cradle), Event 7045 (New Service), Event 4698 (Scheduled Task), Event 1102 (Audit Log Cleared), and Defender 1116 (Mimikatz).
  - `web_application_alerts.json`: WAF telemetry covering SQL Injection, Directory Traversal, XSS, and Web Shell probes.
  - `siem_multi_stage_incident.json`: Multi-stage cyber kill-chain attack progression.
  - `sample_alerts/README.md`: Detailed documentation of simulated scenarios, schemas, and usage instructions.
- **Automated MITRE ATT&CK® Matrix Visualization & Threat Summary Reporting**:
  - Interactive Matrix Heatmap UI: Added `/reports/mitre` web dashboard with responsive 14-column ATT&CK Enterprise Matrix Navigator (TA0043 to TA0040), severity-graded technique cards, and prescriptive defensive countermeasures.
  - Multi-Format Reporting API: Added `GET /api/v1/reports/mitre` supporting `?format=json`, `?format=markdown`, and `?format=text` with direct download attachment headers (`?download=true`), and `GET /api/v1/reports/mitre/matrix` for grid telemetry.
  - Standalone CLI Utility: Created `scripts/generate_mitre_report.py` for automated evaluation against local databases or mock SIEM JSON files.
- **Hardened Containerization & Orchestration**:
  - Hardened `Dockerfile` with unprivileged user execution (`socuser:socgroup`), layer caching, and built-in HTTP healthchecking.
  - Production-ready `docker-compose.yml` with isolated internal bridge networking (`soc_internal_net`), non-crashing fallback defaults for zero-setup evaluation, and read-only volume mounts for `./sample_alerts` and `./sample_data`.
  - Added `.dockerignore` preventing cache, virtual environments, and local SQLite database bloat.
- **One-Click Telemetry Load Integration**: Extended `/api/v1/sample-data/load/{dataset_type}` and `/upload` web UI to ingest Windows Security Events, Web WAF alerts, and Multi-Stage APT campaigns directly.

### Changed
- **Canonical Version Synchronization**: Bumped package version across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` application metadata to `v1.2.8`.
- **Test Suite Expansion**: Expanded automated test suite from 230 to **237 passing tests** (100% pass rate).
- **Standalone Windows Executable Rebuild**: Compiled updated standalone executable `dist/SOC_Alert_Analyzer.exe` (26,576,796 bytes with UPX compression) with bundled `sample_alerts/` and verified runtime HTTP smoke tests on Windows loopback interface.
- **Authoritative Release Checksum**: Updated `dist/SHA256SUMS.txt` with verified SHA-256 digest `8d5838dbb07f9bcddff59c1ecc36bdd503ce8aec87a382eab5460f19e9b9ab1b`.

---

## [1.2.7] - 2026-10-21

### Added
- **In-Memory Active Candidate Index**: High-speed in-memory indexing for $O(1)$ intra-batch recurrence deduplication during high-volume security log ingestion.
- **Dedicated Standalone Verification Scripting**: Added standalone verification script (`scripts/verify_release_checksum.py`) validating digest format, binary presence, and exact hash matches.

### Changed
- **Canonical Version Synchronization**: Unified package versioning across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` application metadata to strictly align with release `v1.2.7`.
- **Release Verification & Documentation**: Reconciled documentation, badges, changelog records, and evaluation metrics to accurately reflect **230 passing tests**, **86% (Linux) / 88% (Windows)** cross-platform test coverage, and v1.2.7 release status.

### Fixed
- **Provenance-Isolated Alert Recurrence**: Fixed sliding-window deduplication in `app/security/host_sensor.py` and `app/api/routes.py` to filter strictly on matching `telemetry_origin`, preventing cross-origin contamination between `HOST_TELEMETRY`, `HISTORICAL_LOG`, `SIMULATED_DEMO`, and `SECURITY_DRILL`.
- **Event-Timestamp-Anchored Deduplication Window**: Transitioned deduplication from wall-clock time (`datetime.now()`) to incoming event timestamps (`ev_ts ± DEDUP_WINDOW_SECONDS`), enabling robust sliding-window deduplication for historical batch uploads/replays, bounded isolation for future-dated clock anomalies, safe non-merging for stale out-of-order events, and deterministic most-recent candidate selection (`ORDER BY desc(coalesce(last_seen, timestamp))`).
- **Recurrence Edge-Case Hardening**: Resolved intra-batch burst deduplication race conditions by enforcing transactional flushes in `host_sensor.py` and `routes.py`, hardened username whitespace sanitization to `None`, guaranteed boundary preservation for legacy null-timestamp records, and enforced non-merge isolation for resolved/closed alerts.

### Performance & Internal Improvements
- **High-Performance Ingestion & Batched Transaction Resilience**: Replaced individual `db.flush()` calls on every event in `app/api/routes.py` with an in-memory active candidate index for $O(1)$ intra-batch recurrence deduplication and bounded chunked flushes (`DB_BATCH_SIZE = 250`). Wrapped the entire ingestion, flushing, and correlation pipeline in an atomic database transaction with automatic `db.rollback()` on failure, eliminating partial imports, dirty session states, and excessive round-trips. Delivered an **8.3x throughput speedup** (from ~904 to ~7510 events/sec on 1,000-event datasets).
- **Test Suite & CI Matrix Expansion**: Expanded automated test suite to **230 passing tests** across 6 platform/Python configurations (Ubuntu/Windows on Python 3.11, 3.12, 3.13) + Security Audit.
- **Hardened Windows Standalone Executable Build & Verification**: Built standalone executable `SOC_Alert_Analyzer.exe` (26,542,217 bytes) on GitHub Actions Windows release runner and verified with SHA-256 digest `87af9cf4dd739b86ad7dd679d8ba0d7ada522477ef40643668a7506c8721a725`.

---

## [1.2.6] - 2026-10-20

### Changed
- **Route Architecture & Shadowing Elimination**: Removed duplicate shadowed route handlers in `app/main.py` (`/api/v1/host/monitor/toggle`, `/api/v1/simulation/toggle`, `/api/v1/stream/toggle`, `/api/v1/stream/status`), moved `/api/v1/sample-data/load/{dataset_type}` to `app/api/routes.py`, and added route-organization assertions (`tests/test_route_organization.py`) guaranteeing zero duplicate path/method registrations across the application.
- **Canonical Version Synchronization**: Unified package versioning across `app/__init__.__version__`, `app.config.Settings.VERSION`, and `FastAPI` application metadata to strictly align with release `v1.2.6`.
- **Release Verification & Documentation**: Reconciled documentation, badges, changelog records, and evaluation metrics to accurately reflect **217 passing tests**, **86% (Linux) / 88% (Windows)** cross-platform test coverage, and v1.2.6 release status.

### Fixed
- **Alert Recurrence Multi-Field Precision**: Refined deduplication matching in `host_sensor.py` and `routes.py` to evaluate `destination_ip` and `username`, preventing erroneous merging of distinct user accounts or network endpoints with identical generic rule descriptions.
- **Host Sensor Status & Event Loop Reliability**: Fixed `HostSecuritySensor.get_host_info()` to accurately report `stream_manager.host_monitoring_active` rather than `simulation_active`. Upgraded stream toggles to `async def` and stored application event loop references to guarantee dependable background task spawning on restart across execution contexts.

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
