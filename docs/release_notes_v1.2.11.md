# Release Notes — SOC Alert Analyzer v1.2.11

**Release Tag:** [v1.2.11](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases/tag/v1.2.11)  
**Release Date:** October 25, 2026  
**Authoritative Binary SHA-256:** `5d62d4bf8bb8d7fe15bb2a8e26c939b18fc8a958ce2acb4b00469d9dbb6fa221`  
**Standalone EXE Size:** 26,593,215 bytes (Official GitHub Actions Windows Server 2022 runner)  
**Test Suite Status:** 296 passed (100% passing rate, 87.07% code coverage, ≥85% CI floor)  
**Security Scans:** Bandit AST SAST (0 issues), Flake8 (0 errors), Pip-Audit (0 vulnerabilities)  

---

## What's Changed in v1.2.11

### ⚡ Host Sensor Lifecycle Decoupling & Indicator Synchronization
* **Decoupled WebSocket Transport**: Decoupled WebSocket transport connection (`/ws/threats`) from host sensor operational state in `app/static/js/app.js`. `threatSocket.onopen` now triggers authoritative status synchronization (`initStreamStatus()`) rather than unilaterally asserting `liveText.textContent = 'HOST SENSOR: ACTIVE'`.
* **Synchronized Single-Source UI State**: Implemented single authoritative frontend rendering function `updateMonitoringUI(state)` synchronizing:
  - Header live sensor pill and status text (`HOST SENSOR: ACTIVE` vs `HOST SENSOR: PAUSED`).
  - Pill glow and pulsing dot (`.pulse-dot.paused` renders static gray dot without pulsation).
  - Toolbar action buttons (`btn-toggle-host-monitor` and `btn-toggle-sim` with synchronized active/paused styling and icons).
  - Data notice status strip and status tag (`Live Sensor` vs `Sensor Paused`).
  - Host telemetry strip EDR mode label (`Native Host EDR Active` vs `Native Host EDR Paused`).
* **Instant Focus Re-sync**: Added window `focus` event listener in `app.js` to re-synchronize status automatically whenever the analyst returns to the dashboard tab.
* **Accessible Visual States**: Added CSS classes `.live-sensor-pill.paused`, `.pulse-dot.paused`, and `.data-notice-status-tag.paused` in `app/static/css/styles.css`.

### 💾 Persistent Monitoring Preferences Across Restarts
* **Atomic File Persistence**: Added atomic JSON preference persistence via `save_monitoring_preferences` and `load_monitoring_preferences` in `app/config.py`.
* **Survives Standalone Re-launches & Restarts**: Persists monitoring preference in `DATA_DIR/monitoring_preferences.json` (`%LOCALAPPDATA%\SOC_Alert_Analyzer` on Windows standalone, `/app/data` on Docker), surviving restarts, binary re-launches, and container recreation.
* **Clean Shutdown Safety**: Preserves user preference across clean application shutdown without saving or overwriting user preferences on process exit.
* **Fault-Tolerant Hydration**: Robust fallback to environment variables and secure defaults if the preference file is missing or corrupted.

### 🛡️ Guarded Automatic Audits & Historical Alert Retention
* **Startup Baseline Guarded**: Guarded `initial_host_baseline()` in `app/main.py` to skip scanning when host monitoring is paused.
* **Dashboard Load Guarded**: Guarded dashboard zero-alerts host audit so it does not trigger an automatic scan while paused.
* **Historical Alerts Preserved**: Historical alerts are preserved in the workbench when host monitoring is paused.
* **Guarded Clear History**: Refined `/api/v1/alerts/clear`: when called while host monitoring is paused, purges database records and in-memory deduplication signatures without re-running `host_sensor.run_full_audit(db)` or recreating baseline alerts (such as SMB port 445).
* **Clean Empty Queue Transition**: Fixed `fetchAlertsFromApi()` in `app/static/js/app.js` to properly clear `SOC_STATE.alerts = []` and reset selection when an empty array `[]` is returned.

### 🧪 Comprehensive Quality Assurance & Test Verification
* **Test Suite Expansion**: Added comprehensive regression tests in `tests/test_monitoring_lifecycle.py` covering persistence, atomic writing, corrupted file recovery, clear-while-paused behavior, and manual audit behavior while paused.
* **Full Suite Pass**: Automated Pytest suite expanded to **296 passed tests (100% pass rate)** with **87.07% code coverage** (exceeding ≥85% CI floor).
* **Multi-Platform CI**: 7/7 CI jobs passed across Ubuntu and Windows matrices (Python 3.11, 3.12, 3.13).
* **Security Scans**: Bandit AST SAST (0 issues), Flake8 (0 syntax/fatal errors), Pip-Audit (0 known vulnerabilities).
* **Supply Chain Parity**: Regenerated CycloneDX v1.5 `sbom.json`, SPDX v2.3 `sbom.spdx.json`, and pinned `requirements.lock` for v1.2.11.

---

### 🔐 Verified Release Artifacts & SHA-256 Checksums
```text
5d62d4bf8bb8d7fe15bb2a8e26c939b18fc8a958ce2acb4b00469d9dbb6fa221  SOC_Alert_Analyzer.exe
```
* **Binary Size**: 26,593,215 bytes (official Windows Server 2022 / Python 3.12 release runner)
* **Local SHA-256 Verification**:
  ```powershell
  Get-FileHash -Algorithm SHA256 dist\SOC_Alert_Analyzer.exe
  # or
  certutil -hashfile dist\SOC_Alert_Analyzer.exe SHA256
  ```

**Full Changelog**: https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/compare/v1.2.10...v1.2.11
