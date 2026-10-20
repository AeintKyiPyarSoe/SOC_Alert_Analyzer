# SOC Alert Analyzer 🛡️

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-211%20passed-brightgreen.svg?style=flat&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![Coverage](https://img.shields.io/badge/coverage-86%25%20(Linux)%20%7C%2088%25%20(Windows)-brightgreen.svg?style=flat&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF.svg?style=flat&logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Security Scans](https://img.shields.io/badge/security%20scans-Bandit%20%7C%20Pip--Audit%20%7C%20Ruff-blueviolet.svg?style=flat&logo=shield)](SECURITY.md)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20v14-6F42C1.svg?style=flat)](https://attack.mitre.org/)
[![UI/UX](https://img.shields.io/badge/design%20system-Nicole’s%20Security%20Lab-A0EDC5.svg?style=flat&logoColor=black)](docs/UI_UX_specification.md)
[![Release](https://img.shields.io/badge/release-v1.2.6-orange.svg?style=flat&logo=windows)](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Less noise. More clarity.**  
> A defensive cybersecurity operations workbench, correlation engine, and real-time host intrusion detection system (EDR-Lite). Transforms raw multi-source security telemetry and behavioral anomalies into plain-language triage playbooks, explainable risk calculations, and actionable MITRE ATT&CK® mappings.

---

## 🎬 GIF Demo

![SOC Alert Analyzer Demo](docs/assets/demo.gif)

---

## 🌟 Key Capabilities & Defensive Engineering Enhancements

### 1. Robust Security Posture & Role-Based Access Control (RBAC)
* **Tiered Authorization**: Protects sensitive endpoints with role-based permissions (`ADMIN`, `ANALYST`, `VIEWER`).
  * `ADMIN`: Full system control, database clearing, alert deletion, configuration management.
  * `ANALYST`: Log ingestion, incident/alert status updates, live host audits, and simulation drills.
  * `VIEWER`: Read-only access to dashboards, alerts, incidents, and threat statistics.
* **Hardened Authentication-Disabled Mode**:
  * Insecure authentication-disabled mode is strictly restricted to verified local loopback connections (`127.0.0.1`, `::1`, `localhost`).
  * Non-local / remote IP connections attempting to access an auth-disabled server are immediately rejected with `HTTP 403 Forbidden`.
  * Arbitrary `Host` and `X-Forwarded-For` headers are strictly ignored as proof of local access to prevent proxy-header spoofing.
  * Startup configuration is validated: disabling authentication is explicitly prohibited in `ENVIRONMENT=production`, and requires an explicit `ALLOW_INSECURE_AUTH_DISABLED=true` flag in development.
* **Server-Side Session & CSRF Protection**:
  * **Opaque Session Tokens**: Privileged API keys are never stored in browser cookies or client JavaScript. Browser authentication uses cryptographically secure, opaque session cookies (`soc_session`) with `HttpOnly`, `SameSite=Lax`, and `Secure` attributes.
  * **Hashed Server Store**: Session identifiers are hashed using SHA-256 before storage in memory to eliminate plaintext credential exposure in server memory dumps.
  * **CSRF Defense**: State-changing browser operations (`POST`, `PATCH`, `DELETE`) require a cryptographically verified `X-CSRF-Token` header validated against the session store via constant-time comparison (`hmac.compare_digest`).
  * **Atomic Session Rotation**: Session identifiers are atomically rotated upon privilege changes to prevent session fixation.
  * **Bounded Memory Store**: Session storage, login rate limiters, and lockouts automatically prune expired entries and enforce capacity bounds to prevent memory exhaustion.
* **WebSocket Defense & Single-Use Handshake Tickets**:
  * `/ws/threats` eliminates long-lived keys in URL query strings, using browser session cookies or short-lived, single-use connection tickets (`POST /api/v1/auth/ws-ticket`).
  * Enforces strict Origin header validation against allowed schemes, hostnames, and ports. Rejects malformed origins with credentials, paths, query strings, or fragments, and rejects arbitrary localhost ports outside documented launcher bounds.
  * Implements stream-level data separation so unauthenticated, guest, or viewer clients never receive sensitive genuine host telemetry or live malicious process events.
* **Multi-Worker Execution Guard**:
  * Launcher enforces single-worker execution (`--workers 1`) to prevent split-brain session state and disjoint WebSocket connections across unshared worker process memories.
* **Data Protection & Sanitized Demonstration Mode**:
  * Unauthenticated viewers are strictly restricted to simulated demonstration alerts. Genuine host telemetry, raw system logs, and internal process lists require authenticated Analyst or Admin clearance.
* **Secrets Management**: Removed all hardcoded database credentials. Sensitive variables (`POSTGRES_PASSWORD`, `SECRET_KEY`, `ADMIN_API_KEY`, `ANALYST_API_KEY`) are dynamically loaded via environment variables and `.env`. In production mode, weak or default credentials cause immediate startup failure.
* **First-Run Desktop Security**: Standalone desktop installations auto-generate cryptographically secure random API keys saved in `%LOCALAPPDATA%\SOC_Alert_Analyzer\.auth_credentials` with restricted user-only permissions (`0o600`).
* **Container Hardening**: Docker container runs as an unprivileged, non-root user (`socuser:socgroup`). PostgreSQL ports are restricted to internal container networking and blocked from public host exposure.
* **Ingestion Guardrails & File Security**:
  * Chunked streaming read with hard byte limits (default: 25 MB) preventing memory exhaustion / denial of service.
  * Event volume capping (`MAX_EVENTS_PER_UPLOAD = 5000`) and batched database writes (`DB_BATCH_SIZE = 250`) protecting database connection pools.
  * Binary magic header validation (`MZ`, `ELF`, Mach-O, `PK`) rejecting malware or binaries disguised as text logs.
  * XML external entity (XXE) defense using `defusedxml` parser.
  * Path traversal sanitization stripping directory escape sequences (`../`, `..\`).
  * Resilient parsing handling malformed JSON, truncated XML, and invalid encodings with descriptive `HTTP 422` responses instead of unhandled exceptions.

### 2. Behavioral Host-Based Threat Detection (EDR-Lite)
Replaces naive substring keyword matching with contextual behavioral indicators:
* **Parent-Child Process Trees**:
  * Flags web servers (`w3wp.exe`, `nginx`, `httpd`) spawning shells (`cmd.exe`, `powershell.exe`, `sh`, `bash`) as suspected web shells (**MITRE T1505.003**).
  * Flags Office productivity software (`winword.exe`, `excel.exe`, `outlook.exe`) spawning script interpreters (**MITRE T1204.002** / **T1059.001**).
* **Process Masquerading**: Identifies critical Windows system binaries (`svchost.exe`, `lsass.exe`, `csrss.exe`) executing outside `%SystemRoot%\System32` (**MITRE T1036.005**).
* **Ransomware Defense Evasion**: Catches volume shadow copy deletion commands (`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`) (**MITRE T1490**).
* **Living-off-the-Land (LOLBin) Combinations**: Identifies Base64 encoded PowerShell executions combined with hidden window and download cradle flags (**MITRE T1059.001**), as well as remote payload downloads via `certutil` (**MITRE T1105**).
* **Credential Dumping & Host Defense Impairment**: Detects memory dumping attacks targeting LSASS (`procdump`, `comsvcs.dll minidump`, `sekurlsa`) (**MITRE T1003**) and firewall disablement via `netsh` (**MITRE T1562.001**).

### 3. Explainable Risk Scoring Engine
Calculates risk on a deterministic 0–100 scale across 4 severity tiers:
* **LOW** (0–24) | **MEDIUM** (25–49) | **HIGH** (50–74) | **CRITICAL** (75–100)
* Incorporates baseline event severity, tool rule levels (Wazuh 0–15, Suricata 1–4), frequency multipliers, signature confidence, asset exposure, privilege context, and false-positive dampeners.
* Clamped strictly between 0 and 100 with safe handling of missing, empty, or out-of-bounds parameters (including NaN and Inf confidence inputs).

---

## 📊 Detection Evaluation Benchmark

The behavioral detection engine is empirically evaluated using both development baseline scenarios and a dedicated held-out benchmark:

* **Evaluation Benchmark Scope**: 50 curated process execution scenarios (25 malicious attack patterns, 25 difficult benign developer/sysadmin workflows).
* **Held-Out Benchmark (30 Scenarios)**:
  * **Precision**: **1.00 (100%)**
  * **Recall (Sensitivity)**: **1.00 (100%)**
  * **F1 Score**: **1.00 (100%)**
  * **False Positive Rate (FPR)**: **0.00 (0.0%)**
  * **Accuracy**: **1.00 (100%)**
* **Standalone Evaluation Runner**: Run `python scripts/evaluate_detection.py` for reproducible metrics and confusion matrices.
* Full methodology, scenario listings, and operational boundaries are documented in [`docs/detection_evaluation.md`](docs/detection_evaluation.md).

---

## 🚀 Quick Start

### Option A: Standalone Windows Executable (Zero Dependencies)

1. Download `SOC_Alert_Analyzer.exe` and `SHA256SUMS.txt` from [Releases](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases).
2. Verify the SHA-256 checksum:
   ```powershell
   Get-FileHash .\SOC_Alert_Analyzer.exe -Algorithm SHA256
   ```
3. Run the executable. It starts the defensive server on local loopback, runs an initial baseline audit, and automatically opens your default browser at `http://127.0.0.1:8000`.

### Option B: Docker Compose (Hardened Multi-Container)

```bash
# 1. Clone repository
git clone https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer.git
cd SOC_Alert_Analyzer

# 2. Configure environment
cp .env.example .env

# 3. Build and launch containers
docker compose up -d --build
```
Navigate to `http://localhost:8000`.

### Option C: Local Python Development

```bash
# 1. Clone repository
git clone https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer.git
cd SOC_Alert_Analyzer

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# 3. Configure environment
cp .env.example .env

# 4. Install dependencies
pip install -r requirements.txt

# 5. Launch application
python launcher.py
```
Open your browser to `http://127.0.0.1:8000`.

---

## 🧪 Automated Testing & Quality Verification

The repository maintains an automated pytest test suite (**203 passing tests**, 100% pass rate, 88% code coverage) verifying all defensive security, parsing, session management, CSRF defense, correlation, and risk calculation logic:

```powershell
python -m pytest -v --cov=app --cov-report=term-missing
```

```text
tests/detection_eval/test_eval_held_out_benchmark.py::test_held_out_behavioral_evaluation_benchmark PASSED
tests/detection_eval/test_eval_held_out_benchmark.py::test_held_out_ambiguous_and_duplicate_handling PASSED
tests/detection_eval/test_eval_host_behavioral.py::test_behavioral_detection_evaluation_metrics PASSED
tests/detection_eval/test_eval_host_behavioral.py::test_eval_false_positive_edge_cases_and_suppression PASSED
tests/test_api.py::test_html_views PASSED
tests/test_auth_disabled_security.py::test_is_local_client_unit PASSED
tests/test_auth_disabled_security.py::test_auth_disabled_mode_rejects_non_local_client PASSED
tests/test_auth_disabled_security.py::test_auth_disabled_mode_does_not_trust_forwarded_headers PASSED
tests/test_auth_disabled_security.py::test_auth_disabled_mode_allows_verified_local PASSED
tests/test_auth_disabled_security.py::test_auth_disabled_startup_rejected_in_production PASSED
tests/test_auth_disabled_security.py::test_auth_disabled_startup_requires_explicit_opt_in_dev PASSED
tests/test_auth_endpoints.py::test_login_success_admin_sets_secure_session_and_csrf_cookie PASSED
tests/test_auth_endpoints.py::test_csrf_protection_on_state_changing_requests PASSED
tests/test_origin_cors_validation.py::test_origin_validation_positive_allowed PASSED
tests/test_origin_cors_validation.py::test_origin_validation_negative_untrusted_domains PASSED
tests/test_origin_cors_validation.py::test_origin_validation_negative_arbitrary_localhost_ports PASSED
tests/test_origin_cors_validation.py::test_origin_validation_negative_malformed_origins PASSED
tests/test_session_lifecycle.py::test_session_lifecycle_create_get_revoke PASSED
tests/test_session_lifecycle.py::test_atomic_session_rotation PASSED
tests/test_session_lifecycle.py::test_login_rate_limiting_and_pruning PASSED
tests/test_session_lifecycle.py::test_websocket_ticket_lifecycle_and_replay_defense PASSED
tests/test_detection_resilience.py::test_risk_engine_nan_inf_handling PASSED
tests/test_detection_resilience.py::test_suricata_parser_anti_false_positive PASSED
tests/test_detection_resilience.py::test_mitre_mapper_anti_false_positive PASSED
tests/test_detection_resilience.py::test_correlator_out_of_order_clustering PASSED
tests/test_stream_websocket.py::test_websocket_origin_validation_unit_tests PASSED
tests/test_stream_websocket.py::test_websocket_broadcast_filters_real_threats_from_demo_clients PASSED
tests/test_upload_security.py::test_upload_binary_executable_rejected PASSED
tests/test_upload_security.py::test_upload_path_traversal_filename_sanitized PASSED
============================ 203 passed in 30.96s =============================
```

### Continuous Integration (GitHub Actions)
* Multi-platform test matrix (Ubuntu & Windows across Python 3.11, 3.12, 3.13).
* Automated code quality and syntax checks using `flake8` and `ruff`.
* Code test coverage reporting via `pytest-cov`.
* Automated dependency vulnerability scanning with `pip-audit`.
* AST static application security testing using `bandit`.

---

## 📂 Repository Structure

```text
├── .github/
│   ├── ISSUE_TEMPLATE/       # Structured bug report & security issue forms
│   ├── workflows/
│   │   ├── ci.yml            # Multi-OS test, coverage & security audit pipeline
│   │   └── release-exe.yml   # Automated Windows EXE build, smoke test & release pipeline
│   └── pull_request_template.md # Defensive engineering review checklist
├── alembic/                  # Database migration scripts and schema versioning
├── app/
│   ├── api/
│   │   └── routes.py         # REST endpoints with RBAC & SQL aggregation
│   ├── database/
│   │   └── connection.py     # SQLAlchemy engine, session & auto-migration
│   ├── models/
│   │   ├── alert.py          # Alert ORM model with composite indexes
│   │   └── incident.py       # Incident & IncidentAlert junction models
│   ├── parsers/              # Windows Event, Wazuh, Suricata, Web, Linux parsers
│   ├── schemas/              # Pydantic request/response validation schemas
│   ├── security/
│   │   ├── auth.py           # API key authentication & RBAC dependency
│   │   ├── correlator.py     # Incident correlation & cross-upload merge engine
│   │   ├── host_sensor.py    # Native host security sensor & behavioral EDR-Lite
│   │   ├── ip_utils.py       # Robust IPv4/IPv6 address classification
│   │   ├── mitre_mapper.py   # MITRE ATT&CK technique mapping
│   │   ├── normalizer.py     # Multi-format normalizer & timestamp validator
│   │   ├── remediation.py    # Plain-language triage guidance playbooks
│   │   ├── risk_engine.py    # Explainable 0-100 risk scoring engine
│   │   ├── session.py        # Cryptographic session manager & CSRF defense
│   │   ├── simulator.py      # Demonstration live threat stream generator
│   │   ├── stream.py         # Thread-safe WebSocket threat stream manager
│   │   └── upload_security.py# Memory-safe chunked upload & validation handler
│   ├── static/               # Nicole’s Security Lab CSS visual tokens & app.js
│   └── templates/            # Jinja2 dashboard, alerts, incidents, and investigation views
├── docs/                     # Specifications, requirements, and architecture docs
├── sample_data/              # Realistic Wazuh, Suricata, and Linux log samples
├── scripts/                  # Detection evaluation & utility automation scripts
├── tests/                    # 211 automated pytest tests covering all subsystems (86% on Linux, 88% on Windows, >=85% CI floor)
├── .env.example              # Environment variables template
├── docker-compose.yml        # Multi-container hardened setup
├── Dockerfile                # Non-root container build file
├── launcher.py               # One-click browser & Uvicorn launcher
├── SOC_Alert_Analyzer.spec   # PyInstaller standalone executable specification
├── CHANGELOG.md              # Historical version release notes
├── CONTRIBUTING.md           # Defensive contribution guidelines
├── SECURITY.md               # Security policy & vulnerability reporting
└── README.md
```

---

## ⚠️ Limitations & Defensive Operational Boundaries

1. **Scope as an EDR-Lite Workbench (Not a Commercial EDR Replacement)**:
   * The host sensor functions as a user-space behavioral auditor leveraging `psutil` and OS event logs.
   * **Not a Kernel Driver**: Unlike enterprise EDR/XDR agents (e.g., CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint), SOC Alert Analyzer does not install a kernel driver (ELAM), hook low-level Windows kernel API calls, or perform in-memory DLL injection tracing.
   * **User Privilege Limitations**: When executed under an unprivileged user account, process inspections are limited to processes owned by the current user. To inspect system-wide processes or privileged Windows Security Event Log channels (EID 4625, 4688), execute the application as an Administrator.
   * **Sysmon Co-existence**: This application does not replace Microsoft Windows Sysmon. For complete enterprise telemetry, configure Sysmon on endpoints and forward XML/JSON logs into SOC Alert Analyzer.
   * **Detection Benchmark**: For reproducible test benchmarks, confusion matrices, and empirical validation on curated scenarios, see [Detection Evaluation & Quality Benchmark](docs/detection_evaluation.md).
2. **Correlation Scope (Not a Petabyte-Scale Enterprise SIEM)**:
   * The correlation engine uses a configurable sliding time window (`CORRELATION_WINDOW_SECONDS = 300` by default) to aggregate burst activity into incidents.
   * It is optimized for local workstation triage, tier-1 SOC analysis, and demonstration drills. It is not designed to replace distributed Big Data SIEM architectures (e.g., Splunk Enterprise, Elastic Security, Microsoft Sentinel) handling tens of thousands of continuous events per second across multi-thousand endpoint fleets.
3. **Log Format Ingestion Boundaries**:
   * Supported formats include JSON (Wazuh, Suricata EVE), CSV, Apache/Nginx combined access logs, Syslog BSD/RFC 5424, and Windows Event XML/JSON.
   * Proprietary binary event logs (`.evtx`) must be converted to XML or JSON prior to ingestion.
4. **Standalone Packaging & Antivirus Heuristics**:
   * Single-file Windows executables generated via PyInstaller bundle a self-extracting Python runtime. Heuristic antivirus scanners without vendor signatures may occasionally issue generic "Unknown Publisher" or "Heur.BZC" warnings.
   * Always verify the authentic SHA-256 hash against the officially published [`SHA256SUMS.txt`](dist/SHA256SUMS.txt).
5. **Strictly Defensive Application**:
   * This project is strictly engineered for defensive blue-team operations, incident response, student training, and log correlation. It does not contain offensive weaponization, automated exploit delivery, or lateral movement tooling.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
