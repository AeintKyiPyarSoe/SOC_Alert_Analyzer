# System Acceptance Criteria
## SOC Alert Analyzer

---

## 1. Overview & Verification Strategy

This document establishes the formal acceptance criteria for the **SOC Alert Analyzer** (Phase 1 / MVP). These criteria serve as the testing baseline for Quality Assurance (QA), user acceptance testing (UAT), and system sign-off.

Each feature includes:
1. **User Story**: Persona, motivation, and expected outcome.
2. **Acceptance Criteria (Gherkin BDD format)**: `Given - When - Then` scenarios detailing expected system behavior.
3. **Verification Checklist**: Concrete validation conditions required for release readiness.

---

## 2. Feature-by-Feature Acceptance Criteria

### 2.1 Feature 1: Alert Import & Log Parsing

#### User Story
> As a **device owner**, I want to upload security log files from Wazuh, Suricata, or Linux so that my system's security telemetry can be analyzed without manual command-line configuration.

#### Acceptance Scenarios

##### Scenario 1.1: Valid Wazuh JSON Alert Upload
- **Given** an authenticated or local user is on the log import interface,
- **When** the user uploads a valid Wazuh JSON file containing alert entries (e.g., Rule 5710, Level 10),
- **Then** the file is parsed with status `201 Created`,
- **And** the parsed alerts appear in the database and dashboard within 5 seconds.

##### Scenario 1.2: Valid Suricata EVE JSON Upload
- **Given** an alert file containing valid Suricata EVE records (`"event_type": "alert"`),
- **When** the user submits the file via the upload endpoint,
- **Then** the system successfully extracts timestamp, signature, severity, IP endpoints, and port numbers.

##### Scenario 1.3: Valid Linux Authentication Log Upload
- **Given** a standard `/var/log/auth.log` text file with failed/accepted SSH logins,
- **When** the file is uploaded,
- **Then** the regex parser extracts timestamps, usernames, process names, and remote source IPs.

##### Scenario 1.4: Corrupt or Invalid File Rejection
- **Given** a non-security file (e.g., an arbitrary binary or invalid JSON format),
- **When** the user uploads the file,
- **Then** the system rejects the file with HTTP `422 Unprocessable Entity` or `400 Bad Request`,
- **And** displays an error message informing the user of the invalid format without server crash.

#### Verification Checklist
- [ ] Accepts `.json`, `.log`, and `.txt` extensions.
- [ ] Successfully processes Wazuh JSON alerts.
- [ ] Successfully processes Suricata EVE JSON events.
- [ ] Successfully processes Linux `auth.log` text records.
- [ ] Rejects files larger than 50 MB with a friendly warning.
- [ ] Displays parsed record count summary upon completion.

---

### 2.2 Feature 2: Alert Normalization

#### User Story
> As a **junior analyst**, I want all security alerts transformed into a consistent data model so that I can analyze events uniformly regardless of the original security tool.

#### Acceptance Scenarios

##### Scenario 2.1: Canonical Field Population
- **Given** raw event data from any supported log provider,
- **When** the normalization pipeline processes the log record,
- **Then** the resulting `Alert` object contains populated attributes:
  - `timestamp` in standardized UTC ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`)
  - `source_type` (`Wazuh`, `Suricata`, or `Linux_Auth`)
  - `event_type` (e.g., `ssh_authentication_failure`, `port_scan`)
  - `source_ip` and `destination_ip` (valid IP format or `NULL`)
  - `severity` mapped to standardized levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `status` initialized to `OPEN`.

##### Scenario 2.2: Missing Optional Fields Handling
- **Given** a log event lacking port or username details,
- **When** the normalization pipeline executes,
- **Then** optional fields default to `NULL` without throwing a schema exception.

#### Verification Checklist
- [ ] All timestamps parsed into ISO 8601 UTC.
- [ ] Source and destination IP strings validated.
- [ ] Standardized internal `Alert` schema strictly enforced via Pydantic model.
- [ ] Source tools identified correctly in `source_type`.

---

### 2.3 Feature 3: Severity & Risk Scoring Engine

#### User Story
> As a **non-expert user**, I want an explainable risk score (0–100) and clear color badge so that I immediately know how dangerous an event is.

#### Acceptance Scenarios

##### Scenario 3.1: Rule-Based Score Calculation
- **Given** an alert with known base severity and repeated failed login count,
- **When** the risk engine evaluates the event,
- **Then** it calculates an integer score bounded between `0` and `100`.

##### Scenario 3.2: Risk Tier Assignment
- **Given** calculated risk scores,
- **When** the tier mapper categorizes the score,
- **Then** it applies the following exact rubric:
  | Score Range | Severity Tier | Visual Badge |
  | :--- | :--- | :--- |
  | **0 – 24** | LOW | 🟢 Green |
  | **25 – 49** | MEDIUM | 🟡 Yellow |
  | **50 – 74** | HIGH | 🟠 Orange |
  | **75 – 100** | CRITICAL | 🔴 Red |

##### Scenario 3.3: High-Frequency Event Escalation
- **Given** an alert indicating 30+ SSH authentication failures within 5 minutes,
- **When** the risk engine processes the frequency modifier,
- **Then** the risk score escalates into the `CRITICAL` band (score $\ge 75$).

#### Verification Checklist
- [ ] Scoring logic is deterministic and reproducible.
- [ ] Scores are strictly clamped between 0 and 100.
- [ ] Visual color badges match the rubric across all UI views.
- [ ] Transparent explanation factors (Base + Frequency + Confidence) are stored with the alert.

---

### 2.4 Feature 4: MITRE ATT&CK Mapping

#### User Story
> As a **security student**, I want alerts mapped to the MITRE ATT&CK framework so that I can study real-world adversary tactics and techniques.

#### Acceptance Scenarios

##### Scenario 4.1: Known Signature Mapping
- **Given** an alert representing repeated SSH password failures,
- **When** the MITRE mapper inspects the `event_type`,
- **Then** it assigns `mitre_technique: "T1110"` with technique name `"Brute Force"`.

##### Scenario 4.2: Network Reconnaissance Mapping
- **Given** a Suricata port scan alert,
- **When** processed by the mapper,
- **Then** it assigns `mitre_technique: "T1046"` with technique name `"Network Service Discovery"`.

##### Scenario 4.3: Interactive Technique Hyperlink
- **Given** an alert displaying a MITRE technique ID in the UI,
- **When** the user clicks the technique badge,
- **Then** the browser opens the official MITRE ATT&CK documentation page (e.g., `https://attack.mitre.org/techniques/T1110/`) in a new tab.

#### Verification Checklist
- [ ] SSH brute force correctly maps to `T1110`.
- [ ] Port scan / reconnaissance correctly maps to `T1046`.
- [ ] Suspicious PowerShell commands map to `T1059.001`.
- [ ] Lateral SSH connection attempts map to `T1021.004`.
- [ ] Unmapped / generic events gracefully display `N/A` without errors.

---

### 2.5 Feature 5: Alert Correlation & Incident Grouping

#### User Story
> As a **system owner**, I want repetitive, related alerts grouped into a single incident so that my dashboard is not flooded with dozens of identical alerts.

#### Acceptance Scenarios

##### Scenario 5.1: Grouping by Entity and Time Window
- **Given** 37 failed SSH authentication alerts from IP `192.168.1.45` targeting `192.168.1.10` within a 5-minute span,
- **When** the correlation engine executes,
- **Then** it groups all 37 alerts into a single `Incident` record titled `"SSH Brute Force Incident"`,
- **And** links each alert ID via the `incident_alerts` relationship.

##### Scenario 5.2: Incident Metrics Aggregation
- **Given** an aggregated incident,
- **When** inspected in the API or UI,
- **Then** it reflects:
  - Total alert count (`37`)
  - Temporal span (`first_seen` to `last_seen`)
  - Overall incident risk score equal to the maximum or compound score of member alerts.

#### Verification Checklist
- [ ] Alerts with identical Source IP, Target IP, and Event Type within 5 minutes are grouped.
- [ ] Incident creation does not duplicate existing active incident groups.
- [ ] Relationship table `incident_alerts` maintains referential integrity.

---

### 2.6 Feature 6: Beginner-Friendly Investigation View

#### User Story
> As a **non-expert user**, I want an investigation page written in plain English so that I understand what happened and what defensive steps I must take.

#### Acceptance Scenarios

##### Scenario 6.1: Core Question Presentation
- **Given** a user opens an alert or incident investigation view,
- **When** the page renders,
- **Then** it prominently answers the four core questions in plain language:
  1. **What happened?** (e.g., *"Someone repeatedly attempted to log into your computer using SSH."*)
  2. **Why is this suspicious?** (e.g., *"37 failed login attempts were detected from the same source within 5 minutes."*)
  3. **Where did it come from?** (Source IP address and host context)
  4. **What should I do?** (Actionable checklist of defensive tasks)

##### Scenario 6.2: Actionable Defensive Playbook Checklist
- **Given** a brute-force incident investigation view,
- **When** the user navigates to the recommended actions section,
- **Then** it provides interactive checkboxes for:
  - Check whether the source device is known.
  - Review recent SSH login activity.
  - Change the affected account password.
  - Disable password-based SSH authentication.

##### Scenario 6.3: Technical Transparency Drawer
- **Given** a junior analyst or student reviewing an investigation,
- **When** they click "View Raw Security Telemetry",
- **Then** an expandable drawer reveals the original raw JSON / syslog string.

#### Verification Checklist
- [ ] Non-technical narratives contain zero unclarified jargon.
- [ ] Specific defensive action steps are rendered for each major event type.
- [ ] Raw logs are available on demand without cluttering the primary view.

---

### 2.7 Feature 7: Alert & Incident Lifecycle State Management

#### User Story
> As an **analyst or user**, I want to update the status of an alert to track whether it is open, being investigated, or resolved.

#### Acceptance Scenarios

##### Scenario 7.1: Lifecycle State Progression
- **Given** an alert in state `OPEN`,
- **When** the user clicks "Start Investigation",
- **Then** the alert status updates to `INVESTIGATING`,
- **And** the updated state persists across page refreshes.

##### Scenario 7.2: Incident Resolution
- **Given** an alert or incident under investigation,
- **When** the user clicks "Mark as Resolved",
- **Then** the status transitions to `RESOLVED`,
- **And** dashboard KPI cards decrement the open incident count.

##### Scenario 7.3: False Positive Marking
- **Given** an alert triggered by legitimate administrative testing,
- **When** the user marks the alert as `FALSE POSITIVE`,
- **Then** the alert is archived from active risk metrics.

#### Verification Checklist
- [ ] Status transitions obey the state machine (`OPEN` → `INVESTIGATING` → `RESOLVED` / `FALSE POSITIVE`).
- [ ] Status updates emit audit timestamps.
- [ ] Immediate UI state update without requiring full-page reload.

---

### 2.8 Feature 8: Security Dashboard & Visual Triage

#### User Story
> As a **user**, I want an overview dashboard displaying high-level threat metrics and recent alerts so that I can assess my device's security at a glance.

#### Acceptance Scenarios

##### Scenario 8.1: Summary KPI Card Accuracy
- **Given** a database containing 3 Critical, 12 High, 27 Medium, and 94 Low alerts,
- **When** the user loads the dashboard,
- **Then** the KPI metric cards display matching numbers with corresponding severity color indicators.

##### Scenario 8.2: Reverse-Chronological Alert Feed
- **Given** stored alerts,
- **When** viewing the recent alerts widget,
- **Then** alerts are sorted by `timestamp` descending (most recent first).

##### Scenario 8.3: Search and Filter Controls
- **Given** a list of alerts,
- **When** the user filters by Severity=`CRITICAL` or searches by IP=`192.168.1.45`,
- **Then** the table updates instantly to display only matching records.

#### Verification Checklist
- [ ] KPI cards match database count queries.
- [ ] Severity badges render with proper color contrast.
- [ ] Search and filter parameters operate concurrently.

---

### 2.9 Feature 9: Containerized Deployment & Portability

#### User Story
> As a **developer or evaluator**, I want to start the application with a single command so that I can run and test the complete stack without complex environment setup.

#### Acceptance Scenarios

##### Scenario 9.1: Single-Command Initialization
- **Given** a host environment with Docker and Docker Compose installed,
- **When** the user runs `docker-compose up --build`,
- **Then** both the PostgreSQL container and the FastAPI application container initialize and pass health checks within 60 seconds.

##### Scenario 9.2: Web Accessibility
- **Given** running containers,
- **When** the user opens `http://localhost:8000` in a web browser,
- **Then** the SOC Alert Analyzer dashboard loads successfully.

#### Verification Checklist
- [ ] `docker-compose.yml` launches both database and web application services.
- [ ] Database automatically runs migrations/tables on initial startup.
- [ ] Persistent Docker volume configured for PostgreSQL data.

---

## 3. The Golden UX Acceptance Metric

The ultimate user acceptance criterion for the SOC Alert Analyzer project is:

> **"Can a user with little or no cybersecurity knowledge understand what happened, determine how serious it is, and know what action to take next without ever looking at the raw security log?"**

### Test Protocol
1. Present a test subject (non-expert user) with an investigation screen for a simulated brute-force or port-scan incident.
2. Provide no prior explanation of SIEM rules or technical IDS logs.
3. Prompt the user:
   - *What do you believe happened to this computer?*
   - *Is this low, medium, or severe?*
   - *What are two things you should do to fix or investigate it?*
4. **Pass Criteria**: The user correctly identifies the nature of the event, perceives the threat severity, and selects at least two correct defensive playbook tasks within 60 seconds.
