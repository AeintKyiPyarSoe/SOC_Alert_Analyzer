# Release Notes — SOC Alert Analyzer v1.2.16

**Release Tag:** [v1.2.16](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases/tag/v1.2.16)  
**Release Date:** October 25, 2026  
**Authoritative Binary SHA-256 (GitHub Actions Runner):** `5e848dab2a3e3a97575a88b989cc2ebd48f5fffe0ef566f480f2319d9a2aadd2`  
**Standalone EXE Size (Runner):** 25,289,272 bytes (Windows Server 2022 / Python 3.12)  
**Separate Local Build SHA-256 (not the published release artifact):** `4ad117695e55744d7181f6adc3364f5d3564473a8d4f154adcff0edede30692e`  
**Separate Local Build EXE Size:** 56,709,018 bytes (Windows 11 / Python 3.13)  
**Test Suite Status:** 354 collected, 354 passed, 0 skipped, 0 failed (100% pass rate)  
**Browser Testing:** 10/10 genuine Playwright Chromium browser scenarios executed and passed with 0 skips  
**Security Scans:** Bandit AST SAST (0 issues), Flake8 (0 errors), Pip-Audit (0 vulnerabilities)  
**Detection Benchmarks:** 100% precision, 100% recall, 100% accuracy across all test benches  
**Supply Chain Security:** CycloneDX v1.5 `sbom.json`, SPDX v2.3 `sbom.spdx.json`, fully pinned `requirements.lock`  

---

## What's Changed in v1.2.16

### 🔄 Deterministic Lifecycle Lock Ownership & Concurrency Serialization
* **Deterministic Event-Loop Binding (`app/security/stream.py`)**: Replaced fragile private attribute inspection (`asyncio.Lock._loop`) with explicit tracking of the owner event loop (`self._owner_lifecycle_lock_loop`) protected by an atomic initialization mutex (`self._thread_lifecycle_init_lock`).
* **Lock Permanence**: Guaranteed that exactly one stable lifecycle lock exists per active owner loop; eliminates erroneous lock recreation during uncontended calls.
* **Safe Cross-Thread Submission**: Synchronous wrappers (`start_simulation_sync`, `stop_simulation_sync`, `shutdown_sync`) route coroutines onto the designated owner loop via `asyncio.run_coroutine_threadsafe` without deadlock or invalid references.
* **Lifecycle State Isolation**: Enforced complete separation between Host Monitoring and Simulation drill state transitions.
* **Concurrency Regression Suite**: Expanded `tests/test_monitoring_concurrency.py` with 10 deterministic concurrency tests verifying mutual exclusion, rapid toggling, and loop shutdown resilience.

### ⏱️ Strict Cancellation Timeout & Quiescence Tracking
* **Explicit Cancellation Status**: Introduced `TaskCancellationResult` enum (`TERMINATED`, `TIMED_OUT`, `ALREADY_COMPLETED`, `FAILED`) in `ThreatStreamManager._cancel_and_await_task()`.
* **Atomic Worker Accounting (`app/security/host_sensor.py`)**: Replaced binary flags with atomic integer worker counters (`_active_auto_workers`, `_active_manual_workers`) protected by a thread lock.
* **Quiescence Verification**: Host sensor reports `PAUSED` only after active automatic audit workers verify full quiescence; timeouts transition cleanly to `PAUSING_TIMED_OUT` rather than masking in-flight worker activity.
* **Single-Transaction Boundary**: Protected SQLite transaction commit boundaries in `_ingest_events` and incident correlation with automatic rollback upon mid-audit cancellation.
* **Lifecycle Regression Suite**: Added 12 regression tests to `tests/test_monitoring_lifecycle.py` verifying process enumeration pause, network inspection pause, event-log collection pause, and transaction safety.

### 🛡️ Packaged Executable Real Log Redaction Verification (Test N)
* **Direct Binary Log Inspection**: Extended `scripts/test_exe_websocket_integration.py` with Test N, inspecting captured stdout and stderr streams of `dist/SOC_Alert_Analyzer.exe`.
* **Zero Credential Leakage**: Proved ephemeral WebSocket connection tickets (`ticket_1`, `ticket_2`, `ticket_k`), invalid tickets, and API secrets are never emitted in plaintext and are strictly sanitized (`ticket=[REDACTED]`).
* **Process Tree Lifecycle**: Enabled tree-based process cleanup (`taskkill /F /T /PID` on Windows) to prevent pipe deadlocks and orphaned processes across integration runs.

### 📦 Dependency Locking, Audit Integrity & SBOM Standardization
* **Vulnerability-Free Lockfile**: Audited `requirements.lock` with `pip-audit`, verifying zero known vulnerabilities across 28 direct and transitive packages.
* **Automated SBOM Resolution (`scripts/generate_sbom.py`)**: Eliminated hardcoded version fallbacks and `latest` tags; versions are derived directly from installed distributions.
* **Standardized Formats**: Regenerated CycloneDX v1.5 `sbom.json` (28 components) and SPDX v2.3 `sbom.spdx.json`.
* **CI Audit Enforcement**: Updated `.github/workflows/ci.yml` and `.github/workflows/release-exe.yml` to enforce `pip-audit -r requirements.lock`.

### 🔬 Independently Sourced Detection Provenance & Transparent Scope
* **Curated Provenance Metadata**: Enriched `sample_data/independent_telemetry/independent_telemetry_dataset.json` with provenance fields (`curated_sigma`, `mitre_car`, `atomic_red_team`, `held_out_telemetry`).
* **Transparent Evaluation Reporting**: Updated `EndpointAttackEvaluator.run_benchmark()` to record provenance breakdown, dataset size, and explicit scope and limitations disclaimers in `docs/independent_telemetry_evaluation_report.json`.

### 🌐 Timezone-Safe Datetime Comparison
* **UTC Normalization Helper (`app/security/correlator.py`)**: Added `_to_utc()` to guarantee timestamp comparisons and clustering operate on consistent UTC-aware datetimes, preventing SQLite offset-naive vs. offset-aware comparison errors.

---

### 🔐 Verified Release Artifacts & SHA-256 Checksums

#### Official GitHub Release Asset (Windows Server 2022 / Python 3.12 runner)
```text
5e848dab2a3e3a97575a88b989cc2ebd48f5fffe0ef566f480f2319d9a2aadd2  SOC_Alert_Analyzer.exe
```
* **Official Binary Size**: 25,289,272 bytes
* **Official Verification Command**:
  ```powershell
  python scripts/verify_release_checksum.py --verify dist/SHA256SUMS.txt
  ```

#### Standalone Windows Executable (Local Build: Windows 11 / Python 3.13)
```text
4ad117695e55744d7181f6adc3364f5d3564473a8d4f154adcff0edede30692e  SOC_Alert_Analyzer.exe
```
* **Local Binary Size**: 56,709,018 bytes

**Full Changelog**: https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/compare/v1.2.15...v1.2.16
