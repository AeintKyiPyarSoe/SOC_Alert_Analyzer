# Release Notes — SOC Alert Analyzer v1.2.12

**Release Tag:** [v1.2.12](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases/tag/v1.2.12)  
**Release Date:** October 25, 2026  
**Authoritative Binary SHA-256:** `c902ac6f4d44eea802511f77a65bea968c5a4fb3557a2e9fb3af6e91d9879d27`  
**Standalone EXE Size:** 54,110,131 bytes  
**Test Suite Status:** 301 passed (100% passing rate, 86.65% code coverage, ≥85% CI floor)  
**Security Scans:** Bandit AST SAST (0 issues), Flake8 (0 errors), Ruff (0 issues), Pip-Audit (0 vulnerabilities)  
**Detection & Telemetry Benchmarks:** 100% Precision, 100% Recall, 100% F1, 0.0% FPR across 50 detection & 18 endpoint attack evaluation scenarios  

---

## What's Changed in v1.2.12

### ⚡ Explicit Monitoring Lifecycle State Model & Neutral Indicator
* **Seven Discrete Lifecycle States**: Replaced false ACTIVE initial indicator with a seven-state operational model: `UNKNOWN`, `CHECKING`, `ACTIVE`, `PAUSING`, `PAUSED`, `RESUMING`, and `ERROR`.
* **Elimination of False Green Glow**: Default neutral `CHECKING` indicator on page load eliminates misleading green active glow prior to backend verification.
* **Complete WebSocket Decoupling**: Decoupled WebSocket transport connection (`connecting`, `connected`, `reconnecting`, `disconnected`, `auth_required`) from host telemetry sensor status.
* **Debounced State Toggles**: Added debounce protection and optimistic state transitions with rollback on network failure in `app/static/js/app.js`.

### 🔄 Asynchronous Task Quiescence, Cancellation Await & Transaction Rollback
* **Serialized Start/Stop Lifecycle Transitions**: Guarded all monitoring and simulation transitions using `asyncio.Lock()` to prevent race conditions during rapid state changes.
* **Clean Asynchronous Task Await**: Transformed `stop_host_monitoring` into an asynchronous coroutine that cleanly cancels and `await`s the running task before returning HTTP 200, ensuring complete task quiescence.
* **In-Flight Findings Discard**: If host monitoring is paused during a scan cycle, in-flight findings are discarded and the database transaction is rolled back cleanly.

### 💾 Explicit Persistence Error Reporting & Atomic Guarantees
* **Persistence Status Reporting**: Updated `save_monitoring_preferences` in `app/config.py` to return explicit `{persisted: bool, persistence_error: Optional[str]}` status.
* **API Visibility**: Surfaced persistence indicators in `/api/v1/stream/status` and `/api/v1/host/monitor/toggle`.
* **Atomic File Fallback**: Guaranteed that disk write failures leave the existing valid preference file intact.
* **Dynamic DATA_DIR Support in Frozen Mode**: Enabled `os.getenv("DATA_DIR")` override in PyInstaller standalone frozen mode for testing and portable profiles.

### 🧪 Standalone Windows Executable Process Lifecycle Integration Suite
* **End-to-End Tests A through G Across Restarts**: Implemented `scripts/test_exe_lifecycle_integration.py` executing tests A through G across process restarts in an isolated dynamic port environment.
  - Test A: Process Spawn & Health Verification
  - Test B: Pause Host Monitoring & Preference Disk Verification
  - Test C: Clear Alerts & Quiescence Verification (zero alerts, no background rescan)
  - Test D: Process Kill & Restart; Verify PAUSED Preference Survived Reboot
  - Test E: Manual Host Audit During Paused State (remains PAUSED)
  - Test F: Resume Host Monitoring (restores ACTIVE and task RUNNING)
  - Test G: Second Restart Verification & Clean Shutdown
* **CI/CD Integration**: Integrated executable integration test into release workflow.

### 📦 Reproducible Dependency Management & Supply Chain Security
* **Lockfile Installation in CI**: Updated `.github/workflows/ci.yml` and `release-exe.yml` to install dependencies strictly via `requirements.lock`.
* **Pinned Packaging Tooling**: Pinned `pyinstaller==6.22.2` for deterministic Windows release executable packaging.
* **SBOM Manifest Parity**: Regenerated CycloneDX v1.5 `sbom.json` and SPDX v2.3 `sbom.spdx.json` aligned to version `1.2.12`.
* **Automated Manifest Consistency**: Added `tests/test_release_manifest_consistency.py` asserting strict synchronization across application code, FastAPI metadata, README, CHANGELOG, SBOM manifests, and release checksums.

---

### 🔐 Verified Release Artifacts & SHA-256 Checksums
```text
c902ac6f4d44eea802511f77a65bea968c5a4fb3557a2e9fb3af6e91d9879d27  SOC_Alert_Analyzer.exe
```
* **Binary Size**: 54,110,131 bytes
* **Local SHA-256 Verification**:
  ```powershell
  Get-FileHash -Algorithm SHA256 dist\SOC_Alert_Analyzer.exe
  # or
  certutil -hashfile dist\SOC_Alert_Analyzer.exe SHA256
  ```

**Full Changelog**: https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/compare/v1.2.11...v1.2.12
