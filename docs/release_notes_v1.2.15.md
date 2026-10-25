# Release Notes — SOC Alert Analyzer v1.2.15

**Release Tag:** [v1.2.15](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases/tag/v1.2.15)  
**Release Date:** October 25, 2026  
**Authoritative Binary SHA-256 (Windows x64 Executable):** `18fdf1bcb5eb09fcd8b21a35ebe3e7c8eaf337b2219c6f70edab5c79436ca13c`  
**Standalone EXE Size:** 54,131,022 bytes  
**Test Suite Status:** 335 collected, 335 passed, 0 skipped, 0 failed (100% pass rate)  
**Browser Testing:** 10/10 genuine Playwright Chromium browser scenarios executed and passed with 0 skips  
**Security Scans:** Bandit AST SAST (0 issues), Flake8 (0 errors), Pip-Audit (0 vulnerabilities)  
**Detection Benchmarks:** 100% precision, 100% recall, 100% accuracy across all test benches  
**Supply Chain Security:** CycloneDX v1.5 `sbom.json`, SPDX v2.3 `sbom.spdx.json`, fully pinned `requirements.lock`  

---

## What's Changed in v1.2.15

### 🔐 Security Access Log Redaction & Credential Sanitization
* **Centralized Sanitization Engine (`app/security/logging_filter.py`)**: Intercepts log records across standard Uvicorn access, application, and error loggers to scrub sensitive parameters:
  * Redacts ephemeral WebSocket tickets (`?ticket=wst_...`) to `?ticket=[REDACTED]`.
  * Redacts HTTP Authorization headers and Bearer tokens to `Bearer [REDACTED]`.
  * Sanitizes API keys, session tokens, passwords, and secrets across query parameters and formatted log messages.
  * Sanitizes session cookies (`soc_session=...`) to `soc_session=[REDACTED]`.
* **Telemetry Preservation**: Safely preserves non-sensitive operational telemetry—including client IP, endpoint path, HTTP method, response status code, and latency.
* **Launcher & Server Integration**: Configured secure Uvicorn log configurations across standalone launcher (`launcher.py`), Uvicorn server processes, and FastAPI startup lifespans.
* **Comprehensive Test Suite**: Added `tests/test_security_logging.py` covering ticket redaction during handshakes, rejected connections, and nested logging arguments.

### ⚡ Monitoring Concurrency Hardening & Sensor Quiescence
* **Owner-Bound Lifecycle Mutex (`app/security/stream.py`)**: Bound lifecycle mutex (`_get_owner_lock`) to the owner application loop, eliminating deadlocks during rapid concurrent start/pause cycles across asynchronous contexts and secondary threads.
* **Scan Cancellation Tokens (`app/security/host_sensor.py`)**: Introduced generation-tracked cancellation tokens (`scan_generation`, `_cancel_event`) in `HostSecuritySensor`.
* **Zero Orphaned Findings on Pause**: Mid-audit cancellations cleanly roll back active SQLite transactions with zero uncommitted findings persisted to the database.
* **Sensor Quiescence Assurance**: Added `wait_quiescence` to ensure background audit worker threads reach full completion before lifecycle transition states conclude.
* **Concurrency Regression Suite**: Added `tests/test_monitoring_concurrency.py` verifying race-free toggling, cross-thread synchronous wrappers, and mid-audit rollbacks.

### 🚀 Static Asset Content Hash Fingerprinting & HTTP Cache Invalidation
* **Deterministic Asset Fingerprints (`app/main.py`)**: Generated 12-character SHA-256 content hashes for static assets (`styles.css`, `app.js`), automatically invalidated on file modifications.
* **Jinja2 Template Helper**: Injected `{{ versioned_static('...') }}` into `app/templates/base.html` appending `?v=<hash>` to force instantaneous browser cache updates upon application release.
* **Hardened Cache-Control Headers**:
  * Set `Cache-Control: no-cache, must-revalidate` on all HTML document view endpoints.
  * Set `Cache-Control: no-store, private` on sensitive telemetry API endpoints.
* **Conditional Request Verification**: Verified unchanged static assets return HTTP 304 Not Modified when client supplies matching `If-None-Match` (ETag) or `If-Modified-Since` headers (`tests/test_static_cache_invalidation.py`).

### 📡 WebSocket Historical Ingestion Summary Notifications
* **Import Summary Broadcast (`app/api/routes.py`)**: Broadly broadcasts structured `IMPORT_SUMMARY` notifications over WebSocket upon log file uploads, informing connected analysts in real time of imported alert counts, created incidents, and overall database metrics.

### 🎭 Playwright Browser Automation Test Hardening
* **Event-Pump Alignment (`tests/test_browser_monitoring_ui.py`)**: Integrated `page.wait_for_timeout` to ensure Playwright's synchronous event loop dispatches intercepted routes cleanly.
* **Genuine Keyboard Interactivity**: Verified keyboard focus and Enter key activation on the Host Sensor toggle button, verifying in-flight button lock and ARIA busy attribute state.

### 📦 Software Supply Chain & BOM Synchronization
* **CycloneDX v1.5 (`sbom.json`)** & **SPDX v2.3 (`sbom.spdx.json`)**: Synchronized application metadata, package versions, and package URLs matching version `1.2.15`.
* **Manifest Synchronization**: Verified 100% consistency across `app.__version__`, `settings.VERSION`, `FastAPI.version`, `README.md`, `CHANGELOG.md`, and SBOMs.

---


---

### 🔐 Verified Release Artifacts & SHA-256 Checksum

`	ext
18fdf1bcb5eb09fcd8b21a35ebe3e7c8eaf337b2219c6f70edab5c79436ca13c  SOC_Alert_Analyzer.exe
`
* **Binary Size**: 54,131,022 bytes
* **Verification Command**:
  `powershell
  python scripts/verify_release_checksum.py --verify dist/SHA256SUMS.txt
  `

**Full Changelog**: https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/compare/v1.2.14...v1.2.15
