# Release Notes — SOC Alert Analyzer v1.2.14

**Release Tag:** [v1.2.14](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases/tag/v1.2.14)  
**Release Date:** October 25, 2026  
**Authoritative Binary SHA-256 (Windows x64 Executable):** `87261b40aef23b4566b09388b4b689cd8fc0fb5c7aa3d749158de700cb91cf4d`  
**Standalone EXE Size:** 54,118,248 bytes  
**Test Suite Status:** 321 collected, 321 passed, 0 skipped, 0 failed (Coverage: 86.60%; ≥85% CI floor)  
**Browser Testing:** 10/10 genuine Playwright Chromium browser scenarios executed and passed with 0 skips  
**Security Scans:** Bandit AST SAST (0 issues), Flake8 (0 errors), Pip-Audit (0 vulnerabilities)  
**Detection Benchmarks:** 100% precision, 100% recall, 100% accuracy on Curated (18/18) and Independent Telemetry (12/12) benchmarks  
**Supply Chain Security:** CycloneDX v1.5 `sbom.json`, SPDX v2.3 `sbom.spdx.json`, fully pinned `requirements.lock` (28 dependencies)  

---

## What's Changed in v1.2.14

### 🎭 Mandatory Real Browser Automation Suite (Playwright Chromium)
* **Real Chromium Interactions**: Rewrote `tests/test_browser_monitoring_ui.py` to exercise 10 genuine user scenarios in real headless Chromium without mocking or DOM manipulation.
* **Initial CHECKING Neutral State (Scenario 1)**: Verified header displays neutral `CHECKING` during network delays, with no false `ACTIVE` state or green pulse animation.
* **Synchronized ACTIVE & PAUSED States (Scenarios 2–3)**: Verified simultaneous state alignment across header pills, pulse dot animations, action buttons, dashboard banners, and sidebar EDR mode indicators.
* **Backend Error & Stale-Response Race Prevention (Scenarios 4–5)**: Intercepted 500 status responses and verified `UNKNOWN`/`ERROR` handling; proved delayed stale responses cannot overwrite user-initiated pause actions.
* **Transport Decoupling & Reconnection (Scenarios 6–7)**: Proved WebSocket connections remain decoupled from host monitoring state and verified graceful reconnection with updated pill titles.
* **Persistence Error & Clear History Modal (Scenarios 8–9)**: Verified explicit toast warnings on persistence failure and confirmed distinct modal warnings between active and paused modes.
* **Full Accessibility & Transition Locks (Scenario 10)**: Verified ARIA labels, `aria-busy` states, keyboard navigation, and disabled button locks during transitions.

### 🛡️ Monitoring Lifecycle State Machine & Task-Health Edge Cases
* **Formal State Machine**: Implemented states `STARTING`, `ACTIVE`, `PAUSING`, `PAUSED`, `RESUMING`, `STOPPED`, `ERROR`, `UNKNOWN` in `ThreatStreamManager`.
* **Accurate Health Reporting**: Proved that `get_status()` strictly inspects running background tasks; unhandled task exit or missing task references are never falsely reported as `ACTIVE`.
* **Re-Entrant Thread-Safe Serialization**: Replaced loop-bound locks with `threading.Lock()` to serialize concurrent toggle requests without event-loop deadlocks.
* **Cooperative Cancellation & Transaction Rollback**: Offloaded blocking host audits to worker threads via `asyncio.to_thread` with cooperative cancellation and clean transaction rollback on sensor pause.

### 🔌 Live Defensive Alert Delivery over WebSocket in Standalone EXE (Tests A–M)
* **Real Pipeline Alert Verification (Test K)**: Extended `scripts/test_exe_websocket_integration.py` to verify that an ingested security drill alert is normalized, risk-scored, persisted to SQLite, and delivered in real time over the WebSocket stream to authorized analysts.
* **Authorization & Telemetry Isolation (Test L)**: Verified unauthenticated clients cannot mint WebSocket tickets or access sensitive host telemetry.
* **Paused Sensor Independence & Continuity (Test M)**: Verified manual drills deliver over the live stream even while continuous host monitoring is paused, and confirmed stream continuity across sensor resume.

### 🎯 Detection Rules & MITRE ATT&CK Accuracy Improvements
* **Endpoint Detection Heuristics**: Added parser detection for MSBuild compilation (`T1127.001`), Regsvr32 DLL registration (`T1218.010`), Volume Shadow Copy deletion (`T1490`), Defender tampering (`T1562.001`), and Sysmon Event 3 C2 network beacons (`T1071`).
* **Parent Process Disambiguation**: Stripped parent process command lines before evaluating child script execution, eliminating false positives on benign developer tooling (e.g. `pytest`).
* **Empirical Benchmarks**: Attained 100% precision, 100% recall, and 100% technique accuracy across all benchmark suites (50 baseline/held-out, 18 curated endpoint, 12 independent telemetry).

### 📋 Independent Telemetry Dataset Provenance
* **11-Field Comprehensive Metadata**: Sourced and documented complete provenance for all 12 independent telemetry scenarios (`provenance_classification`, `source_repository`, `source_file_or_identifier`, `source_commit`, `license`, `original_event_format`, `event_identifier`, `sanitization_procedure`, `transformation_procedure`, `label_justification`, `mitre_mapping_justification`).
* **Automated Provenance Verification**: Added `tests/test_dataset_provenance.py` to continuously validate dataset integrity, commit hashes, and licensing.

### 🔒 Supply Chain Security & Lockfile Parity
* **Reproducible Dependencies**: Synchronized `requirements.lock` with 28 pinned packages.
* **BOM Synchronization**: Generated CycloneDX v1.5 `sbom.json` and SPDX v2.3 `sbom.spdx.json` matching version `1.2.14`.

---

### 🔐 Verified Release Artifacts & SHA-256 Checksum

```text
87261b40aef23b4566b09388b4b689cd8fc0fb5c7aa3d749158de700cb91cf4d  SOC_Alert_Analyzer.exe
```
* **Binary Size**: 54,118,248 bytes
* **Verification Command**:
  ```powershell
  python scripts/verify_release_checksum.py --verify dist/SHA256SUMS.txt
  ```

**Full Changelog**: https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/compare/v1.2.13...v1.2.14
