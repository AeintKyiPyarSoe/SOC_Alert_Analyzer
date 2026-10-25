# Release Notes — SOC Alert Analyzer v1.2.13

**Release Tag:** [v1.2.13](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases/tag/v1.2.13)  
**Release Date:** October 25, 2026  
**Authoritative Binary SHA-256 (GitHub Actions Runner):** `67a7072ed8b69a9f01003128c5f265d2e730e3a178bdbe9b8e8102f4cdf63bf5`  
**Standalone EXE Size (Runner):** 25,259,740 bytes (Windows Server 2022 / Python 3.12)  
**Separate Local Build SHA-256 (not the published release artifact):** `6e7a6537144d5649f0a2de93ee3736282bde23934341683538b0d37c8bb0da11`  
**Separate Local Build EXE Size:** 54,113,978 bytes (Windows 11 / Python 3.13)  
**Test Suite Status:** 312 collected, 302 passed, 10 browser tests skipped, 0 failed, 1 warning (Windows Python 3.12 coverage: 86.40%; ≥85% CI floor)  
**Security Scans:** Bandit AST SAST (0 issues), Flake8 (0 errors), Ruff (0 issues), Pip-Audit (0 vulnerabilities)  
**Supply Chain Security:** CycloneDX v1.5 `sbom.json`, SPDX v2.3 `sbom.spdx.json`, fully pinned `requirements.lock`  

---

## What's Changed in v1.2.13

### 🔌 WebSocket Protocol Implementation & PyInstaller Packaging Repair
* **Uvicorn Sans-IO Protocol Bundling**: Fixed runtime `WARNING: No supported WebSocket library detected.` and HTTP 404 upgrade errors in standalone frozen mode by explicitly packaging `uvicorn.protocols.websockets.websockets_sansio_impl` and `websockets` submodules.
* **Transitive Dependency Inclusion**: Included `mako`, `greenlet`, `annotated_types`, and database dialect hidden imports in `SOC_Alert_Analyzer.spec`.
* **Pinned Protocol Libraries**: Added `websockets>=12.0` (`websockets==17.1`) to `requirements.txt` and `requirements.lock`.

### 🛡️ Mandatory Standalone Executable WebSocket Test Suite (Tests A–J)
* **Real Binary WebSocket Verification**: Created `scripts/test_exe_websocket_integration.py` exercising Tests A through J directly against the packaged Windows binary:
  - Test A: Process Spawn & Health Verification
  - Test B: Analyst Authentication & Session Cookie Issuance
  - Test C: Single-Use Ephemeral WebSocket Ticket Acquisition
  - Test D: HTTP 101 Switching Protocols WebSocket Handshake
  - Test E: Bidirectional Ping/Pong Frame Exchange
  - Test F: Host Sensor Pause While Connected (WebSocket stream stays healthy)
  - Test G: Host Sensor Resume While Connected (Verifies state sync)
  - Test H: Clean WebSocket Disconnection & Reconnection with Fresh Ticket
  - Test I: Replay Attack Defense & Security Rejections (reused, invalid, unauthenticated tickets)
  - Test J: Clean Process Teardown & Port Release
* **Blocking Release Gate**: Enforced executable WebSocket integration testing as a mandatory release-blocking gate in `.github/workflows/release-exe.yml`.

### ⚡ Monitoring Task Lifecycle & Resilient Exception Handling
* **Task Failure & Unhandled Exception Capture**: Enhanced `ThreatStreamManager.get_status()` to monitor `_monitor_task.exception()`, cleanly reporting `ERROR` task health and preventing false `ACTIVE` indicators on unhandled task failures.
* **Cooperative Cancellation Checkpoints**: Added in-flight cancellation checkpoints and `scan_in_progress` tracking in `app/security/host_sensor.py`.
* **Database Rollback on Interrupted Scans**: Reverted partial database transactions when a monitoring audit cycle is paused or cancelled mid-execution.

### 🌐 Frontend Monotonic Request Sequencing & State Synchronization
* **Monotonic Sequence Counter**: Added `currentMonitoringRequestId` to `app/static/js/app.js` to discard delayed or out-of-order responses from late API calls.
* **Heartbeat State Guards**: Prevented late background heartbeats from overriding in-progress UI transitions (`PAUSING`, `RESUMING`).
* **Differentiated User Prompts**: Differentiated the `Clear History` confirmation modal text to inform analysts whether the background sensor is active (prompting a new scan) or paused (maintaining quiet state).

### 🎭 Real Browser UI Automation Suite (Playwright)
* **CI limitation:** The 10 browser tests were skipped in v1.2.13 CI because Playwright/Chromium were not installed; this is not browser-level test evidence.
* **Headless Chromium Automation**: Introduced `tests/test_browser_monitoring_ui.py` running real headless browser tests across 10 end-to-end scenarios:
  - Initial load state verification
  - Clean pause/resume button lifecycle transitions
  - Clear history modal prompts while paused vs active
  - Tab navigation and state preservation
  - WebSocket reconnection resilient updates
  - Rapid toggle debounce protection

### 🔬 Independent Defensive Detection Telemetry Benchmark
* **Documented Open Provenance**: Added `sample_data/independent_telemetry/independent_telemetry_dataset.json` containing defensively curated samples sourced from the OTTR Project, SigmaHQ, and Atomic Red Team.
* **Zero Label Leakage & Scientific Integrity**: Sourced independently without knowledge of internal detection thresholds, yielding realistic detection metrics (66.7% accuracy, 80.0% precision, 57.1% recall) documented in `docs/independent_telemetry_evaluation_report.json`.

### 🔒 Supply Chain Security & CVE Remediation
* **Advisory Resolution**: Upgraded `certifi` from `2026.7.22` to `2026.10.23` (resolving PYSEC-2026-4320).
* **Parity Enforcement**: Synchronized `requirements.lock`, CycloneDX `sbom.json`, and SPDX `sbom.spdx.json` with 28 fully pinned production dependencies.

---

### 🔐 Verified Release Artifacts & SHA-256 Checksums

#### Official GitHub Release Asset (Windows Server 2022 / Python 3.12 runner)
```text
67a7072ed8b69a9f01003128c5f265d2e730e3a178bdbe9b8e8102f4cdf63bf5  SOC_Alert_Analyzer.exe
```
* **Official Binary Size**: 25,259,740 bytes

#### Standalone Windows Executable (Local Build: Windows 11 / Python 3.13)
```text
6e7a6537144d5649f0a2de93ee3736282bde23934341683538b0d37c8bb0da11  SOC_Alert_Analyzer.exe
```
* **Local Binary Size**: 54,113,978 bytes
* **Local Verification Command**:
  ```powershell
  python scripts/verify_release_checksum.py --verify dist/SHA256SUMS.txt
  ```

**Full Changelog**: https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/compare/v1.2.12...v1.2.13
