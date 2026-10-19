# SOC Alert Analyzer 🛡️

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-81%20passed-brightgreen.svg?style=flat&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF.svg?style=flat&logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Security Audited](https://img.shields.io/badge/security-RBAC%20%26%20Bandit%20Verified-blueviolet.svg?style=flat&logo=shield)](docs/acceptance_criteria.md)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20v14-6F42C1.svg?style=flat)](https://attack.mitre.org/)
[![UI/UX](https://img.shields.io/badge/design%20system-Nicole’s%20Security%20Lab-A0EDC5.svg?style=flat&logoColor=black)](docs/UI_UX_specification.md)
[![Release](https://img.shields.io/badge/release-v1.2.0-orange.svg?style=flat&logo=windows)](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases)
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
* **Browser Session Authentication**:
  * Implements secure `HttpOnly`, `SameSite=Lax` session cookie authentication (`/api/v1/auth/login`, `/api/v1/auth/logout`, `/api/v1/auth/me`).
  * **Zero Privileged Secrets in Frontend**: API keys and master secrets are never injected into client-side JavaScript or HTML templates.
  * **Interactive Auth Modal**: Users can securely authenticate or switch roles directly from the interface by clicking Nicole's avatar or via the settings dialog.
  * **WebSocket Protection**: `/ws/threats` validates incoming handshake session cookies or ticket query tokens, closing unauthorized connections with policy violation code `1008`.
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
* **Living-off-the-Land (LOLBin) Combinations**: Identifies Base64 encoded PowerShell executions combined with hidden window and download cradle flags (**MITRE T1059.001**).
* **Network Listener Exposure**: Scans wildcard interfaces (`0.0.0.0`) for high-risk ports (FTP 21, Telnet 23, Metasploit default 4444, Backdoors 1337, WinRM 5985, RDP 3389) (**MITRE T1046**).

### 3. Incident Correlation Engine Refactor
* **Unlinked-Only Query Processing**: Uses SQL outer joins (`Alert` left outer joined with `IncidentAlert`) to correlate only new, unassigned alerts, eliminating full-table memory loading.
* **Cross-Upload Incident Merging**: Consolidates related alerts across distinct ingestion batches into existing open incidents if matching entity signature and time proximity.
* **Duplicate Prevention**: Enforces database junction indexes and atomic state validation to prevent redundant incidents.

### 4. Accurate IP Network Classification
* Dedicated `IPClassifier` accurately distinguishes:
  * **Private Networks**: RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 6598 Carrier-Grade NAT (`100.64.0.0/10`), and IPv6 Unique Local (`fc00::/7`).
  * **Loopback & Link-Local**: `127.0.0.0/8`, `::1`, `169.254.0.0/16`, `fe80::/10`.
  * **Public Internet**: Globally routable IP addresses.
* Prevents false exposure penalties on internal corporate network traffic and local loopback developer services.

### 5. Multi-Format Timestamp Normalization
* Ingests ISO 8601, RFC 2822, Syslog BSD (`Oct 20 01:30:39`), Apache/Nginx Combined Log format, and Unix Epoch timestamps.
* Explicitly tags invalid, malformed, or missing timestamps (`is_valid_timestamp: false`) with warning tags instead of silently masking them with current time.

### 6. Real-Time Telemetry Separation & WebSocket Stream
* Categorizes alerts by telemetry origin:
  * `HOST_TELEMETRY`: Genuine local hardware and process detections.
  * `HISTORICAL_LOG`: Ingested log files (Wazuh, Suricata, Windows Event Viewer, Linux auth).
  * `SIMULATED_DEMO`: Real-time synthesized threat feed for live training.
  * `SECURITY_DRILL`: Controlled SOC evaluation drills.
* Bidirectional WebSocket (`/ws/threats`) featuring keepalive ping/pong, thread-safe broadcast locking, and graceful disconnection cleanup.

### 7. Database Performance & SQL Aggregation
* Replaced in-memory Python loops with SQL group-by queries (`COUNT`, `GROUP BY severity`, `GROUP BY status`).
* Multi-column database indexes on `(status, timestamp)`, `(severity, timestamp)`, and `(telemetry_origin, timestamp)`.
* Enforced pagination limits across API and catalog views.

---

## 🧮 Explainable Risk Scoring Engine

The risk score is computed on a transparent **0–100 scale** using an explainable formula:

$$\text{Risk Score} = \text{clamp}\Big(\text{Base} + \text{FreqMod} + \text{ConfMod} + \text{ExposureMod} + \text{PrivMod} - \text{FPDampener},\, 0,\, 100\Big)$$

```text
┌───────────────────────────┬────────────────────────────────────────────────────────┐
│ Factor                    │ Description & Calibration                              │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ Base Severity (15–80)     │ Baseline calibrated by MITRE ATT&CK tactic impact:    │
│                           │ • Successful Logon: 15                                │
│                           │ • Network Scan / Port Probe: 35                        │
│                           │ • Failed Authentication / Brute Force: 45              │
│                           │ • Suspicious Process / LOLBin: 60-65                   │
│                           │ • Masqueraded Process / Persistence: 70                │
│                           │ • Exploit Attempt / SQLi / Defender Alert: 75-80       │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ Tool Level Escalation     │ Scales Wazuh rule level (≥12 -> 70, ≥8 -> 50, ≥5 -> 35)│
│                           │ and Suricata severity (1 -> 65, 2 -> 45, 3 -> 25)      │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ Frequency Modifier (0–30) │ Burst volume escalation:                               │
│                           │ • 1 event: +0        • 2-4 events: +5                  │
│                           │ • 5-9 events: +10    • 10-29 events: +20               │
│                           │ • ≥30 repeated events: +30                             │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ Confidence Modifier (+10) │ +10 when signature matches verified CVE/exploit IOC    │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ Network Exposure (+5)     │ +5 for public internet routable IP; +0 for RFC 1918    │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ Privilege Modifier (+10)  │ +10 if targeted account is root, admin, or SYSTEM      │
├───────────────────────────┼────────────────────────────────────────────────────────┤
│ False-Positive Dampener   │ -20 dampener applied to verified benign maintenance    │
└───────────────────────────┴────────────────────────────────────────────────────────┘
```

### Severity Tiers
* **0–24 (LOW)**: Routine administrative activity, single benign failure, informative telemetry.
* **25–49 (MEDIUM)**: Single failed logins, network discovery probes, standard firewall blocks.
* **50–74 (HIGH)**: Persistent brute force bursts, LOLBin flags, service creation, privilege escalation.
* **75–100 (CRITICAL)**: Active web shells, ransomware shadow deletion, malware execution, verified exploits.

---

## 🎯 Realistic Detection Scenarios & MITRE ATT&CK® Mapping

| Scenario | Attack Type | MITRE ATT&CK Technique | Telemetry Triggers & Logic | Defensive Verification / Playbook |
| :--- | :--- | :--- | :--- | :--- |
| **1. Web Shell Execution** | Persistence / Execution | `T1505.003` Server Software Component: Web Shell | Parent-child lineage: `w3wp.exe`, `nginx`, `httpd` spawning `cmd.exe` or `powershell.exe` | Isolate web server, inspect `.aspx`/`.php` upload directories, dump process memory |
| **2. Phishing Macro Execution** | Initial Access / Execution | `T1204.002` User Execution: Malicious File | Parent-child lineage: `winword.exe`, `excel.exe`, `outlook.exe` spawning script hosts (`cscript`, `powershell`) | Quarantine endpoint, extract email attachment, block sender domain at mail gateway |
| **3. LOLBin PowerShell Cradle** | Defense Evasion / Execution | `T1059.001` Command and Scripting: PowerShell | Parameter heuristic: Base64 `-enc` + `-w hidden` + `downloadstring` cradle | Terminate PID, inspect PowerShell ScriptBlock logs (EID 4104), block remote IP |
| **4. Ransomware Backup Purge** | Impact / Inhibit Recovery | `T1490` Inhibit System Recovery | Command execution: `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin` | Trigger emergency host isolation, revoke administrative token, verify offline backups |
| **5. Process Masquerading** | Defense Evasion | `T1036.005` Masquerading: Match Legitimate Name | Binary path validation: System binaries (`svchost.exe`, `lsass.exe`) running outside `%SystemRoot%\System32` | Kill anomalous process, compute binary SHA-256 hash, query VirusTotal IOC database |
| **6. Inbound Brute Force** | Credential Access | `T1110.001` Brute Force: Password Guessing | Burst correlation: ≥5 failed authentication events (EID 4625 / Linux PAM) within 300s window | Add source IP to firewall drop list, check for subsequent successful logon (EID 4624) |
| **7. Wildcard Port Exposure** | Discovery / Backdoor | `T1046` Network Service Discovery | Socket inspection: High-risk listening ports (FTP 21, Telnet 23, 4444, 1337, 3389) bound to `0.0.0.0` | Identify listener process via `netstat -ano`, close unauthorized service, re-apply firewall |

---

## 🔐 Role-Based Access Control (RBAC) Matrix

| Endpoint | Method | Required Role | Description |
| :--- | :---: | :---: | :--- |
| `/api/v1/auth/me` | `GET` | Any | Inspect authenticated role profile |
| `/api/v1/alerts` | `GET` | `VIEWER` | Browse normalized alerts catalog |
| `/api/v1/incidents` | `GET` | `VIEWER` | Browse correlated incidents list |
| `/api/v1/dashboard/stats` | `GET` | `VIEWER` | Retrieve KPI metrics and counts |
| `/api/v1/host/status` | `GET` | `VIEWER` | Inspect host hardware and OS posture |
| `/api/v1/alerts/upload` | `POST` | `ANALYST` | Ingest and correlate telemetry logs |
| `/api/v1/sample-data/load/{type}` | `POST` | `ANALYST` | Ingest demonstration attack datasets |
| `/api/v1/alerts/{id}/status` | `PATCH` | `ANALYST` | Transition alert triage status |
| `/api/v1/incidents/{id}/status`| `PATCH` | `ANALYST` | Transition incident triage status |
| `/api/v1/host/audit` | `POST` | `ANALYST` | Trigger immediate host security scan |
| `/api/v1/host/drill` | `POST` | `ANALYST` | Dispatch controlled triage drill |
| `/api/v1/stream/toggle` | `POST` | `ANALYST` | Pause or enable live threat feed |
| `/api/v1/alerts/{id}` | `DELETE`| `ADMIN` | Permanently delete individual alert |
| `/api/v1/alerts/clear` | `POST` | `ADMIN` | Clear all alerts and re-scan host baseline |

---

## 🏗️ System Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      Protected Host System                             │
 │  ├── Active Running Processes (psutil parent-child tree inspection)    │
 │  ├── Network Listeners (0.0.0.0 high-risk port scanning)              │
 │  ├── Windows Firewall Profiles / Linux UFW Status                     │
 │  └── Windows Security Event Logs (4625, 4688, 7045) & Linux auth.log   │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ Live Telemetry
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                       FastAPI Defensive Engine                         │
 │  ├── Authentication & RBAC Guard (X-API-Key / Bearer / Session)        │
 │  ├── Secure Ingestion Guard (Chunked streaming, magic bytes, sanitize) │
 │  ├── Telemetry Normalizer (Multi-format timestamp, IPClassifier)       │
 │  ├── Incident Correlation Engine (Unlinked SQL filter, cross-merge)   │
 │  ├── Explainable Risk Scoring Engine (Confidence, privilege, context)  │
 │  └── Thread-Safe Threat Stream Manager (WebSocket /ws/threats)         │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Nicole’s Security Lab UI/UX                        │
 │  ├── 4 Severity Overview Cards with Real-Time Progress Bars            │
 │  ├── Live Alert Queue (Search, multi-source filters, priority sort)    │
 │  ├── Plain-Language Triage Playbooks with Step-by-Step Checklists      │
 │  └── MITRE ATT&CK Enterprise References & Advisory Links              │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Deployment & Installation Modes

SOC Alert Analyzer supports three distinct deployment profiles tailored for different operational needs:

### Comparison of Deployment Models

| Feature / Capability | Standalone Windows Executable (.exe) | Docker Compose Deployment | Source / Python Virtualenv |
| :--- | :--- | :--- | :--- |
| **Primary Use Case** | Local analyst workstation / Host EDR audit | Multi-analyst team SIEM / Centralized SOC | Codebase customization & development |
| **Supported OS** | Windows 10, 11, Server 2019/2022 (x64) | Linux (Ubuntu, Debian, RHEL), macOS, Windows | Linux, macOS, Windows |
| **Local Host Telemetry** | Full native `psutil` & Windows Event Log audit | Container-scoped metrics (isolated by Docker) | Full native host access |
| **Database Engine** | Embedded SQLite with WAL mode | PostgreSQL 16 on internal bridge network | SQLite (default) or external PostgreSQL |
| **Default Network Binding**| `127.0.0.1:8000` (Strict Loopback Only) | Port 8000 (Bridge internal `soc_internal_net`)| Configurable (default `127.0.0.1:8000`) |
| **Secrets Management** | Auto-generated on 1st run in `%LOCALAPPDATA%` | Enforced non-default environment variables | `.env` or system environment variables |

---

### Option 1: Standalone Windows Executable (`.exe`)

The fastest way to run on a clean Windows workstation with **zero Python or compiler installation required**:

1. Download **`SOC_Alert_Analyzer.exe`** and **`SHA256SUMS.txt`** from [Releases](https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/releases).
2. Verify the release checksum in PowerShell:
   ```powershell
   python -c "import hashlib; print(hashlib.sha256(open('SOC_Alert_Analyzer.exe', 'rb').read()).hexdigest())"
   ```
3. Double-click **`SOC_Alert_Analyzer.exe`** or run from PowerShell:
   ```powershell
   .\SOC_Alert_Analyzer.exe
   ```
4. **Security & Data Isolation**:
   * **Safe Local Storage**: Databases, logs, and authentication keys are written to `%LOCALAPPDATA%\SOC_Alert_Analyzer`, ensuring persistent storage that never resides in temporary unpack directories (`_MEIxxxxxx`).
   * **First-Run Random Credentials**: On initial execution, unique random administrative and analyst API keys are automatically generated and saved to `%LOCALAPPDATA%\SOC_Alert_Analyzer\.auth_credentials` with user-only permissions (`0o600`).
   * **Network Safety**: Binds to `127.0.0.1` by default to prevent exposing the triage console to untrusted networks.
5. **Antivirus Heuristic Notes**:
   Because the executable is packaged using PyInstaller without an enterprise code-signing certificate, certain consumer antivirus solutions may display generic heuristic or SmartScreen warnings (e.g., "Unknown Publisher" or "Heur.BZC"). This is expected behavior for unsigned Python-compiled binaries. You can verify the authentic SHA-256 hash against `SHA256SUMS.txt` or compile directly from source.

---

### Option 2: Docker Compose (Production Hardened)

Recommended for team deployments and central log aggregation:

```bash
# 1. Clone repository
git clone https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer.git
cd SOC_Alert_Analyzer

# 2. Configure production environment secrets (mandatory)
cp .env.example .env
# Edit .env and set secure values for POSTGRES_PASSWORD, SECRET_KEY, and ADMIN_API_KEY

# 3. Launch isolated container stack
docker compose up --build -d
```
* PostgreSQL is isolated on internal docker bridge network `soc_internal_net` and is **not exposed** to host ports.
* The web application runs as an unprivileged, non-root user (`socuser:socgroup`).
* In production mode, the application aborts startup immediately if default passwords or keys are detected.

---

### Option 3: Run from Source (Python Development)

```powershell
# 1. Clone repository
git clone https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer.git
cd SOC_Alert_Analyzer

# 2. Set up environment variables
copy .env.example .env

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch application
python launcher.py
```
Open your browser to `http://127.0.0.1:8000`.

---

## 🧪 Automated Testing & Quality Verification

The repository maintains **81 automated pytest test cases** verifying all defensive security logic:

```powershell
python -m pytest -v
```

```text
tests/test_api.py::test_html_views PASSED
tests/test_auth_rbac.py::test_unauthenticated_requests_fail_on_sensitive_endpoints PASSED
tests/test_auth_rbac.py::test_invalid_api_key_rejected PASSED
tests/test_auth_rbac.py::test_analyst_role_permissions PASSED
tests/test_correlator_refactor.py::test_correlator_merges_across_multiple_uploads PASSED
tests/test_correlator_refactor.py::test_correlator_skips_when_no_unlinked_alerts PASSED
tests/test_database_performance.py::test_sql_aggregation_dashboard_stats PASSED
tests/test_database_performance.py::test_alerts_pagination PASSED
tests/test_host_sensor_behavioral.py::test_behavioral_web_shell_parent_child PASSED
tests/test_host_sensor_behavioral.py::test_behavioral_maldoc_parent_child PASSED
tests/test_host_sensor_behavioral.py::test_behavioral_ransomware_shadow_deletion PASSED
tests/test_host_sensor_behavioral.py::test_behavioral_masquerading_system_binary PASSED
tests/test_ip_classification.py::test_ip_classifier_private_ips PASSED
tests/test_ip_classification.py::test_ip_classifier_public_ips PASSED
tests/test_normalizer.py::test_normalize_invalid_fields PASSED
tests/test_normalizer.py::test_normalize_multi_format_timestamps PASSED
tests/test_risk_engine.py::test_privilege_context_and_confidence_modifiers PASSED
tests/test_risk_engine.py::test_false_positive_dampener PASSED
tests/test_stream_websocket.py::test_websocket_broadcast_with_origin_tag PASSED
tests/test_upload_security.py::test_upload_binary_executable_rejected PASSED
tests/test_upload_security.py::test_upload_oversized_payload_rejected PASSED
tests/test_upload_security.py::test_upload_path_traversal_filename_sanitized PASSED
============================= 70 passed in 11.2s =============================
```

### Continuous Integration (GitHub Actions)
* Multi-platform test matrix (Ubuntu & Windows across Python 3.11, 3.12, 3.13).
* Automated code quality checks using `flake8`.
* Automated dependency vulnerability scanning with `pip-audit`.
* AST static application security testing using `bandit`.

---

## 📂 Repository Structure

```text
├── .github/
│   └── workflows/
│       ├── ci.yml            # Multi-OS test & security audit pipeline
│       └── release-exe.yml   # Automated Windows EXE build, smoke test & release pipeline
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
│   │   ├── simulator.py      # Demonstration live threat stream generator
│   │   ├── stream.py         # Thread-safe WebSocket threat stream manager
│   │   └── upload_security.py# Memory-safe chunked upload & validation handler
│   ├── static/               # Nicole’s Security Lab CSS visual tokens & app.js
│   └── templates/            # Jinja2 dashboard, alerts, incidents, and investigation views
├── docs/                     # Specifications, requirements, and architecture docs
├── sample_data/              # Realistic Wazuh, Suricata, and Linux log samples
├── tests/                    # 81 automated pytest tests covering all subsystems
├── .env.example              # Environment variables template
├── docker-compose.yml        # Multi-container hardened setup
├── Dockerfile                # Non-root container build file
├── launcher.py               # One-click browser & Uvicorn launcher
├── SOC_Alert_Analyzer.spec   # PyInstaller standalone executable specification
└── README.md
```

---

## ⚠️ Limitations & Defensive Operational Boundaries

1. **Host Sensor Scope & User Permissions**: The host sensor functions as an EDR-Lite behavioral auditor via `psutil` and OS event logs. When executed without elevated administrator privileges, process inspection is limited to processes owned by the current user account, and access to privileged security event channels (e.g. Windows Security EID 4625/4688) may be restricted by Windows OS access control. For complete host-wide behavioral visibility, run the terminal or application as an Administrator. In production enterprise deployments, pair with kernel-level sensors (e.g. Sysmon, eBPF, CrowdStrike, or Wazuh Agent).
2. **Correlation Window**: By default, the correlation window is set to 300 seconds (5 minutes). Extended low-and-slow adversary campaigns spanning hours or days should be tuned via `CORRELATION_WINDOW_SECONDS` or queried using historical SIEM search.
3. **Log Formats**: While generic CSV, JSON, Apache, Syslog, Suricata, and Windows XML/JSON logs are natively parsed, custom binary event logs (`.evtx`) should be exported to XML or JSON before ingestion.
4. **Standalone Packaging & Antivirus Heuristics**: Standalone single-file executables created by PyInstaller bundle Python and shared C libraries into a self-extracting archive. Machine learning antivirus engines without vendor signatures may occasionally flag newly generated binaries with generic warnings. Release integrity should always be verified against the published SHA-256 checksum in `SHA256SUMS.txt`.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
