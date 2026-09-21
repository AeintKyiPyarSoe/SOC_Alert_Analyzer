# Software Requirements Specification (SRS)
## SOC Alert Analyzer

---

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification (SRS) document details the complete functional and non-functional requirements for the **SOC Alert Analyzer** (Phase 1 / MVP). It defines the behavioral characteristics, system interfaces, security rules, and architectural constraints necessary to build a defensive cybersecurity web application tailored for non-expert device owners and junior SOC analysts.

### 1.2 Scope of the Product
The SOC Alert Analyzer ingests raw, disparate security telemetry (Wazuh JSON, Suricata EVE JSON, and Linux authentication logs), normalizes the heterogeneous data into a unified canonical schema, computes an explainable 0–100 risk score, links detections to the MITRE ATT&CK knowledge base, correlates isolated alerts into high-level incidents, and displays findings in an intuitive, jargon-free investigation dashboard.

### 1.3 Definitions, Acronyms, and Abbreviations
- **SIEM**: Security Information and Event Management
- **IDS**: Intrusion Detection System
- **SOC**: Security Operations Center
- **MITRE ATT&CK**: Adversarial Tactics, Techniques, and Common Knowledge framework
- **EVE**: Extensible Event Format (Suricata JSON logging)
- **JSON**: JavaScript Object Notation
- **CRUD**: Create, Read, Update, Delete
- **MVP**: Minimum Viable Product
- **FQDN**: Fully Qualified Domain Name
- **TTP**: Tactics, Techniques, and Procedures

### 1.4 References
- [SOC_Alert_Analyzer_Project.md](file:///C:/Siam%20BSc%20IT/VibeCode/SOC_Alert_Analyzer/SOC_Alert_Analyzer_Project.md)
- [project_charter.md](file:///C:/Siam%20BSc%20IT/VibeCode/SOC_Alert_Analyzer/docs/project_charter.md)
- MITRE ATT&CK Enterprise Matrix v14
- RFC 5424 (The Syslog Protocol)

---

## 2. Overall Description

### 2.1 Product Perspective
SOC Alert Analyzer operates as a standalone web application comprised of a Python FastAPI backend, PostgreSQL relational database, and server-rendered HTML5/Jinja2 responsive UI. The system functions as a lightweight defensive triage workbench, decoupling log parsing from specialized SIEM infrastructures to provide immediate, actionable risk clarity.

```text
[Wazuh JSON / Suricata JSON / Linux Auth Logs]
                     │
                     ▼
       ┌───────────────────────────┐
       │   Ingestion & Parsers     │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │ Canonical Normalizer      │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │ Risk Scoring Engine       │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │ MITRE ATT&CK Mapper       │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │ Incident Correlator       │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │ PostgreSQL Storage Layer  │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │ Fast UI (Dashboard/Triage)│
       └───────────────────────────┘
```

### 2.2 User Classes and Characteristics
1. **End-User / Device Owner (Primary Persona)**:
   - Possesses basic IT proficiency; unfamiliar with SIEM rule IDs, packet headers, or regex signatures.
   - Requires plain-language summaries ("Someone repeatedly tried to log into your computer") and guided defensive checklists.
2. **Junior SOC Analyst / Student (Secondary Persona)**:
   - Possesses foundational security knowledge; needs quick event correlation, MITRE ATT&CK mapping, and structured triage state tracking.
3. **System Administrator**:
   - Manages application deployment, database maintenance, and container runtime.

### 2.3 Operating Environment
- **Server Runtime**: Python 3.11+ on Linux / Windows / macOS
- **Containerization**: Docker Engine 24+ and Docker Compose v2+
- **Database**: PostgreSQL 15+
- **Client Browsers**: Google Chrome, Mozilla Firefox, Microsoft Edge, Safari (latest 2 versions)

### 2.4 Design and Implementation Constraints
- **File Upload Limits**: Maximum file size of 50 MB per log upload for MVP.
- **Rule-Based Scoring**: Risk algorithms must remain deterministic, transparent, and explainable (no black-box ML in MVP).
- **Zero Heavy Build Tooling**: Jinja2 server-side templates with lightweight vanilla JavaScript and modern CSS to allow instant setup without Node.js/npm dependencies.

---

## 3. Specific Functional Requirements

### 3.1 Module 1: Alert Ingestion & Parsing (AIP)

- **FR-AIP-01: Multi-Format File Upload**
  - The system SHALL provide a web-based upload mechanism supporting `.json`, `.log`, and `.txt` files.
- **FR-AIP-02: Wazuh JSON Parser**
  - The system SHALL parse Wazuh alert structures, extracting timestamp, rule ID, rule level, rule description, source IP (`data.srcip`), destination IP, and authentication metadata.
- **FR-AIP-03: Suricata EVE JSON Parser**
  - The system SHALL parse Suricata EVE JSON records (`event_type: "alert"`), extracting timestamp, alert signature, signature ID, severity, source IP, source port, destination IP, and destination port.
- **FR-AIP-04: Linux Authentication Log Parser**
  - The system SHALL parse standard `/var/log/auth.log` line entries using structured regex extraction for `sshd` failed passwords, accepted logins, invalid users, and sudo execution.
- **FR-AIP-05: Validation & Error Handling**
  - The system SHALL reject malformed files, report specific line-level parsing warnings, and continue processing valid rows without crashing.

---

### 3.2 Module 2: Canonical Normalization (CAN)

- **FR-CAN-01: Standardized Data Model**
  - The system SHALL transform all parsed events into the canonical `Alert` model with fields: `id`, `timestamp`, `source_type`, `event_type`, `description`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `username`, `severity`, `risk_score`, `mitre_technique`, and `status`.
- **FR-CAN-02: Timestamp Standardization**
  - The system SHALL normalize all event timestamps to ISO 8601 UTC format (`YYYY-MM-DDTHH:MM:SSZ`).
- **FR-CAN-03: IP & Port Sanitization**
  - The system SHALL validate IPv4/IPv6 formats and ensure port numbers reside within valid bounds (1–65535). Missing network fields must default to `NULL`.

---

### 3.3 Module 3: Explainable Risk Scoring Engine (RSE)

- **FR-RSE-01: Quantitative Risk Calculation**
  - The system SHALL compute an integer risk score between 0 and 100 based on:
    $$\text{Risk Score} = \min(100, \text{Base Severity} + \text{Frequency Modifier} + \text{Confidence Modifier} + \text{Asset Importance})$$
- **FR-RSE-02: Four-Tier Severity Classification**
  - The system SHALL categorize the final score into one of four distinct severity bands:
    - **0 – 24**: LOW (Informational / benign anomaly)
    - **25 – 49**: MEDIUM (Suspicious policy deviation)
    - **50 – 74**: HIGH (Active probing or probable intrusion)
    - **75 – 100**: CRITICAL (High-confidence compromise / aggressive attack)
- **FR-RSE-03: Scoring Explanations**
  - The system SHALL store and display the breakdown of contributing factors so users understand why a score was assigned.

---

### 3.4 Module 4: MITRE ATT&CK Mapping (MAM)

- **FR-MAM-01: Technique Cross-Referencing**
  - The system SHALL match recognized event types to corresponding MITRE ATT&CK techniques:
    | Event Classification | MITRE ID | Technique Name | Tactic |
    | :--- | :--- | :--- | :--- |
    | SSH / Auth Brute Force | `T1110` | Brute Force | Credential Access |
    | Network Scanning / Probing | `T1046` | Network Service Discovery | Discovery |
    | PowerShell Execution | `T1059.001` | Command and Scripting Interpreter: PowerShell | Execution |
    | Lateral SSH Activity | `T1021.004` | Remote Services: SSH | Lateral Movement |
    | Account Password Guessing | `T1110.001` | Password Guessing | Credential Access |
- **FR-MAM-02: Contextual Hyperlinking**
  - The system SHALL render clickable external references linking directly to the official MITRE ATT&CK knowledge base (e.g., `https://attack.mitre.org/techniques/T1110/`).

---

### 3.5 Module 5: Incident Correlation Engine (ICE)

- **FR-ICE-01: Temporal Window Aggregation**
  - The system SHALL group repeated alerts occurring within a configurable sliding window (default: 5 minutes / 300 seconds) into a unified `Incident`.
- **FR-ICE-02: Multi-Attribute Matching**
  - Grouping criteria SHALL require matching on:
    1. Identical Source IP (`source_ip`)
    2. Identical Destination Target (`destination_ip`)
    3. Identical or Related Event Classification (`event_type`)
- **FR-ICE-03: Incident Metric Synthesis**
  - Each generated incident SHALL summarize: total alert count, time span (`first_seen` to `last_seen`), aggregated highest risk score, and primary MITRE technique.

---

### 3.6 Module 6: Plain-Language Investigation & Playbooks (INV)

- **FR-INV-01: Non-Technical Narrative Generation**
  - The system SHALL display plain-language translations for alerts answering four core questions:
    1. *What happened?* (e.g., "Someone repeatedly tried to log into your computer.")
    2. *Why is this suspicious?* (e.g., "37 failed login attempts were recorded within 5 minutes.")
    3. *Where did it come from?* (Source IP, internal vs. external identification)
    4. *What should I do?* (Actionable checklist)
- **FR-INV-02: Actionable Defensive Playbook**
  - For each alert category, the system SHALL furnish pre-configured, step-by-step remediation advice (e.g., "Verify source device", "Change password", "Disable password-based SSH").
- **FR-INV-03: Raw Log Transparency**
  - The system SHALL preserve an expandable technical modal containing original raw log strings for audit and student inspection.

---

### 3.7 Module 7: Alert & Incident Lifecycle Management (ALM)

- **FR-ALM-01: State Transitions**
  - Users SHALL be able to update an alert/incident status through defined states:
    $$\text{OPEN} \longrightarrow \text{INVESTIGATING} \longrightarrow \text{RESOLVED}$$
    $$\text{OPEN} \longrightarrow \text{FALSE POSITIVE}$$
- **FR-ALM-02: Status Persistence**
  - All status updates SHALL be recorded in the PostgreSQL database with an audit timestamp.

---

### 3.8 Module 8: Web Dashboard & Visual Triage (DVT)

- **FR-DVT-01: Severity KPI Cards**
  - The dashboard SHALL display real-time counts for Critical, High, Medium, and Low severity alerts.
- **FR-DVT-02: Status Tally Widgets**
  - The dashboard SHALL present totals for Open, Investigating, and Resolved items.
- **FR-DVT-03: Recent Alerts Feed**
  - The dashboard SHALL render the most recent alerts sorted in reverse-chronological order with color-coded severity badges.
- **FR-DVT-04: Multi-Parameter Filtering**
  - Users SHALL be able to filter alerts by source type, severity level, status, and search by IP address or username.

---

## 4. Non-Functional Requirements (NFR)

### 4.1 Performance Requirements
- **NFR-PERF-01**: Log files containing up to 10,000 records SHALL be ingested, parsed, and normalized within 5 seconds.
- **NFR-PERF-02**: Web page render and REST API response times for dashboard metrics SHALL not exceed 500 milliseconds under standard local loads.

### 4.2 Reliability & Fault Tolerance
- **NFR-REL-01**: Ingestion of a malformed log entry SHALL NOT corrupt valid entries or crash the ingestion service.
- **NFR-REL-02**: The database SHALL enforce foreign key integrity and transactional rollbacks on incomplete batch commits.

### 4.3 Usability & Accessibility
- **NFR-USA-01**: The UI SHALL maintain visual hierarchy where critical actions and severity badges are recognizable within 3 seconds of page load.
- **NFR-USA-02**: Plain-language descriptions SHALL contain zero unexplained acronyms in the primary view.

### 4.4 Security Requirements
- **NFR-SEC-01**: File uploads SHALL validate MIME types and reject executable file extensions (`.exe`, `.sh`, `.bat`).
- **NFR-SEC-02**: All user inputs in search and filter fields SHALL be sanitized against SQL injection and Cross-Site Scripting (XSS).
- **NFR-SEC-03**: Secure HTTP headers (e.g., Content-Security-Policy, X-Frame-Options) SHALL be configured across all FastAPI responses.

### 4.5 Portability & Deployment
- **NFR-PORT-01**: The application stack SHALL be fully deployable on any host with Docker and Docker Compose via a single command (`docker-compose up --build`).

---

## 5. System Interfaces & REST API Endpoints

| Method | Endpoint | Description | Request Body / Parameters | Response Status |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/alerts/upload` | Upload log file for processing | `multipart/form-data` (file, source_type) | `201 Created` |
| `GET` | `/api/v1/alerts` | List normalized alerts | Query: `severity`, `status`, `limit`, `offset` | `200 OK` |
| `GET` | `/api/v1/alerts/{id}` | Retrieve specific alert details | Path parameter: `id` | `200 OK` |
| `PATCH` | `/api/v1/alerts/{id}/status` | Update alert lifecycle state | JSON: `{"status": "RESOLVED"}` | `200 OK` |
| `GET` | `/api/v1/incidents` | List correlated incidents | Query: `status`, `limit` | `200 OK` |
| `GET` | `/api/v1/incidents/{id}` | Retrieve incident details & alerts | Path parameter: `id` | `200 OK` |
| `GET` | `/api/v1/dashboard/stats` | Aggregated dashboard KPI numbers | None | `200 OK` |
