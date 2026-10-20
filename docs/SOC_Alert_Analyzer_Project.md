# SOC Alert Analyzer

## 1. Project Overview

**SOC Alert Analyzer** is a Python-based defensive cybersecurity web application that helps individuals with limited cybersecurity knowledge understand suspicious activity on their devices.

The application processes security events from sources such as **Wazuh, Suricata, and Linux authentication logs**, converts technical events into a common format, calculates risk, maps detections to **MITRE ATT&CK** techniques, groups related events, and presents the results in a simple investigation interface.

### Main Goal

> Transform complex security alerts into understandable, actionable information so that non-expert users can understand what happened, how serious it is, and what they should do next.

---

## 2. Problem Statement

Security tools such as Wazuh and Suricata generate detailed alerts that are useful for security professionals but can be difficult for ordinary users to understand.

For example:

```text
Rule ID: 5710
Level: 10
srcip: 192.168.1.45
event: authentication_failed
```

A beginner may not know whether this means their device is being attacked.

SOC Alert Analyzer translates the technical event into something like:

```text
🔴 HIGH RISK

Someone repeatedly tried to log into your computer.

37 failed SSH login attempts were detected.

Possible threat:
Brute Force

Source:
192.168.1.45

MITRE ATT&CK:
T1110 - Brute Force

Recommended actions:
✓ Check whether the source device is known
✓ Review SSH login activity
✓ Change the affected account password
```

---

## 3. Target Users

### Primary User

Individuals who:

- Have basic computer knowledge
- Have limited cybersecurity knowledge
- Want to monitor their devices
- Want to understand suspicious activity
- Do not understand raw SIEM/IDS alerts

### Secondary User

Beginner cybersecurity students and junior SOC analysts who want a simplified investigation interface.

---

# 4. Design Thinking Process

## 4.1 Empathize

Understand how non-expert users react to security alerts.

### User Questions

- What does the alert mean?
- Is my device being attacked?
- How serious is it?
- Where did the activity come from?
- Is the source device mine?
- What should I do?
- Has the problem already been resolved?

### User Pain Point

> Users receive technical security alerts but often cannot understand their meaning, severity, or the appropriate response.

---

## 4.2 Define

### Problem Statement

> Individuals with limited cybersecurity knowledge need a simple way to understand security alerts because existing security monitoring tools often present technical information without sufficient explanation or guidance.

### How Might We?

> How might we transform complex security alerts into simple, understandable, and actionable information?

---

## 4.3 Ideate

Potential solutions:

1. Normalize alerts from different security sources.
2. Calculate a unified risk score.
3. Explain alerts using simple language.
4. Map alerts to MITRE ATT&CK.
5. Group related alerts.
6. Provide investigation details.
7. Recommend defensive actions.
8. Allow users to mark alerts as resolved.

---

# 5. MVP Scope

The MVP should focus on the smallest version that demonstrates the core cybersecurity value.

## MVP Feature 1: Alert Import

Allow users to upload security alert files.

### Supported MVP Sources

- Wazuh JSON alerts
- Suricata EVE JSON
- Linux authentication logs

### Example

```text
Upload Alert File
       ↓
Parse File
       ↓
Validate Event
       ↓
Normalize Event
```

For the MVP, file upload is preferable to building live integrations first.

---

# 6. MVP Feature 2: Alert Normalization

Different security tools use different formats.

The application converts them into a common internal structure.

### Normalized Alert

```text
Alert
├── id
├── timestamp
├── source_type
├── event_type
├── description
├── source_ip
├── destination_ip
├── source_port
├── destination_port
├── username
├── severity
├── risk_score
├── mitre_technique
└── status
```

Example:

```json
{
  "source_type": "Wazuh",
  "event_type": "ssh_authentication_failure",
  "source_ip": "192.168.1.45",
  "destination_ip": "192.168.1.10",
  "severity": "HIGH",
  "risk_score": 78,
  "mitre_technique": "T1110",
  "status": "Open"
}
```

---

# 7. MVP Feature 3: Severity / Risk Scoring

The application calculates its own risk score instead of simply displaying the original Wazuh or Suricata severity.

### Example Factors

```text
Base Severity
     +
Event Frequency
     +
Attack Confidence
     +
Asset Importance
     +
Related Events
     ↓
Risk Score
```

### MVP Risk Levels

| Score | Level |
|---:|---|
| 0–24 | 🟢 LOW |
| 25–49 | 🟡 MEDIUM |
| 50–74 | 🟠 HIGH |
| 75–100 | 🔴 CRITICAL |

Example:

```text
37 failed SSH attempts
        +
Known brute-force signature
        +
Repeated activity
        ↓
Risk Score: 78
        ↓
🔴 CRITICAL
```

The scoring system should be rule-based and explainable in the MVP.

---

# 8. MVP Feature 4: MITRE ATT&CK Mapping

The system maps recognized security events to MITRE ATT&CK techniques.

### Example

```text
SSH Brute Force
      ↓
T1110
Brute Force
```

Possible MVP mappings:

| Event | MITRE ATT&CK |
|---|---|
| SSH brute force | T1110 |
| Password guessing | T1110 |
| Network scanning | T1046 |
| Suspicious PowerShell | T1059.001 |
| SSH activity | T1021.004 |

The MVP can initially use a local Python rule/mapping database.

---

# 9. MVP Feature 5: Alert Correlation

Group repeated or related events into a single security incident.

### Before Correlation

```text
10:01 Failed SSH login
10:01 Failed SSH login
10:02 Failed SSH login
10:02 Failed SSH login
10:03 Failed SSH login
...
```

### After Correlation

```text
🔴 SSH BRUTE FORCE INCIDENT

Source: 192.168.1.45
Target: 192.168.1.10

37 failed attempts
Duration: 5 minutes

MITRE:
T1110 - Brute Force

Risk:
78 / 100
```

For the MVP, correlation can be based on:

- Same source IP
- Same destination
- Same event type
- Short time window

---

# 10. MVP Feature 6: Beginner-Friendly Investigation View

Users should be able to click an alert and understand it without knowing cybersecurity terminology.

## Investigation Page

```text
SSH BRUTE FORCE ATTEMPT

🔴 CRITICAL

What happened?

Someone repeatedly attempted to log into your
computer using SSH.

Why is this suspicious?

37 failed login attempts were detected from
the same source within 5 minutes.

Source:
192.168.1.45

Target:
192.168.1.10

MITRE ATT&CK:
T1110 - Brute Force

Risk Score:
78 / 100

Recommended Actions:

✓ Check whether the source device is known
✓ Review recent SSH login activity
✓ Change the affected password
✓ Disable password-based SSH authentication

[Mark Resolved]
```

---

# 11. MVP Feature 7: Alert Status

Users can manage the state of an alert.

### Statuses

```text
OPEN
 ↓
INVESTIGATING
 ↓
RESOLVED
```

Optional:

```text
FALSE POSITIVE
```

This introduces a basic SOC investigation workflow.

---

# 12. MVP Feature 8: Dashboard

The dashboard provides a quick security overview.

```text
┌─────────────────────────────────────────────┐
│              SOC ALERT ANALYZER             │
├─────────────────────────────────────────────┤
│                                             │
│ 🔴 CRITICAL       3                         │
│ 🟠 HIGH          12                         │
│ 🟡 MEDIUM        27                         │
│ 🟢 LOW           94                         │
│                                             │
├─────────────────────────────────────────────┤
│ Recent Alerts                               │
│                                             │
│ 🔴 SSH Brute Force          78  CRITICAL    │
│ 🟠 Port Scan               61  HIGH        │
│ 🟡 Failed Login            32  MEDIUM      │
│ 🟢 File Change             12  LOW         │
│                                             │
└─────────────────────────────────────────────┘
```

### Dashboard MVP Components

- Alert counts by severity
- Recent alerts
- Highest-risk alerts
- Open/investigating/resolved counts
- Basic time-based alert chart

---

# 13. MVP User Flow

```text
                    START
                      │
                      ↓
              Upload Alert File
                      │
                      ↓
                Parse Events
                      │
                      ↓
             Normalize Events
                      │
                      ↓
              Calculate Risk
                      │
                      ↓
              MITRE Mapping
                      │
                      ↓
             Correlate Events
                      │
                      ↓
                Dashboard
                      │
              ┌───────┴───────┐
              ↓               ↓
          View Alert       Filter Alerts
              │
              ↓
        Investigate Alert
              │
              ↓
       Recommended Actions
              │
              ↓
        Mark as Resolved
```

---

# 14. MVP Technical Architecture

```text
┌─────────────────────────────────────────────┐
│                  WEB UI                     │
│         Dashboard / Alerts / Details        │
└──────────────────────┬──────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────┐
│                FastAPI                      │
│              REST API                      │
└──────────────────────┬──────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────┐
│            Security Processing              │
│                                             │
│  Parser → Normalizer → Risk Engine          │
│                     ↓                       │
│              MITRE Mapper                   │
│                     ↓                       │
│              Correlator                     │
└──────────────────────┬──────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────┐
│                PostgreSQL                   │
│                                             │
│ Alerts / Events / Incidents / Devices       │
└─────────────────────────────────────────────┘

              ↑
              │
       Input Security Data

       Wazuh JSON
       Suricata EVE JSON
       Linux Auth Logs
```

---

# 15. Recommended MVP Technology Stack

## Backend

- Python
- FastAPI
- Pydantic
- SQLAlchemy

## Database

- PostgreSQL

## Frontend

For the MVP:

- HTML
- CSS
- JavaScript
- Jinja2

A React frontend can be added later if desired.

## Security Data

- Wazuh
- Suricata
- Linux authentication logs

## Deployment

- Docker
- Docker Compose

---

# 16. MVP Database Design

### `alerts`

```text
id
timestamp
source_type
event_type
description
source_ip
destination_ip
source_port
destination_port
username
severity
risk_score
mitre_technique
status
created_at
```

### `incidents`

```text
id
title
description
risk_score
mitre_technique
status
first_seen
last_seen
created_at
```

### `incident_alerts`

```text
incident_id
alert_id
```

This allows multiple alerts to belong to one incident.

---

# 17. MVP Python Modules

Suggested project structure:

```text
soc-alert-analyzer/
│
├── app/
│   ├── main.py
│   │
│   ├── api/
│   │   └── routes.py
│   │
│   ├── parsers/
│   │   ├── wazuh.py
│   │   ├── suricata.py
│   │   └── linux_auth.py
│   │
│   ├── security/
│   │   ├── normalizer.py
│   │   ├── risk_engine.py
│   │   ├── mitre_mapper.py
│   │   └── correlator.py
│   │
│   ├── models/
│   │   ├── alert.py
│   │   └── incident.py
│   │
│   ├── database/
│   │   └── connection.py
│   │
│   └── templates/
│       ├── dashboard.html
│       ├── alerts.html
│       └── investigation.html
│
├── tests/
│
├── sample_data/
│   ├── wazuh/
│   ├── suricata/
│   └── linux/
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

---

# 18. What Is NOT in the MVP

Keep these for later versions so the project does not become enormous.

### Version 2+

- Real-time Wazuh API integration
- Real-time Suricata monitoring
- Automatic IP reputation lookup
- VirusTotal integration
- GeoIP
- Email/Telegram notifications
- Windows Event Logs
- Machine-learning anomaly detection
- Automatic response/blocking
- Threat intelligence feeds
- Multi-user authentication
- Cloud deployment
- AI-generated investigation summaries

The MVP should first prove that the **core detection → prioritization → explanation → investigation workflow works**.

---

# 19. Future Development

## Phase 1: MVP

```text
File Upload
     ↓
Parsing
     ↓
Normalization
     ↓
Risk Scoring
     ↓
MITRE Mapping
     ↓
Correlation
     ↓
Dashboard
     ↓
Investigation
```

## Phase 2: Advanced SOC Features

```text
Real-time Wazuh
       +
Real-time Suricata
       ↓
Live Alert Stream
       ↓
Threat Intelligence
       ↓
Advanced Correlation
       ↓
Incident Management
```

## Phase 3: Intelligent Analysis

```text
Security Events
      ↓
Feature Extraction
      ↓
Anomaly Detection
      ↓
ML Risk Prediction
      ↓
Behavior Analysis
      ↓
Advanced Investigation
```

---

# 20. Success Criteria

The MVP is successful if a user can:

- Upload a Wazuh, Suricata, or Linux authentication log.
- See the event converted into a normalized alert.
- Understand what happened.
- See a calculated risk score.
- See the severity level.
- See the related MITRE ATT&CK technique.
- See related events grouped together.
- Open an investigation page.
- Understand why the event is suspicious.
- Receive basic recommended defensive actions.
- Mark the alert as resolved.

### Main UX Success Question

> **Can a user with little cybersecurity knowledge understand what happened and what they should do next without looking at the raw security log?**

---

# 21. Portfolio Value

This project demonstrates practical knowledge in:

```text
Python
   +
Cybersecurity
   +
SIEM
   +
IDS
   +
Log Analysis
   +
Security Detection
   +
MITRE ATT&CK
   +
Risk Scoring
   +
Event Correlation
   +
REST APIs
   +
Database Design
   +
Web Development
   +
Docker
```

It is particularly relevant to **SOC Analyst / Security Analyst** roles because the project demonstrates the workflow of turning raw security telemetry into prioritized incidents and actionable investigation information.

---

# 22. Final Project Concept

> **SOC Alert Analyzer is a defensive cybersecurity platform that simplifies security monitoring for users with limited cybersecurity knowledge. It processes Wazuh, Suricata, and Linux authentication events, normalizes security data, calculates explainable risk scores, maps detections to MITRE ATT&CK techniques, correlates related events, and provides a beginner-friendly investigation workflow with recommended defensive actions.**

The key product philosophy is:

```text
RAW SECURITY DATA
        ↓
WHAT HAPPENED?
        ↓
WHY DOES IT MATTER?
        ↓
HOW SERIOUS IS IT?
        ↓
IS IT RELATED TO OTHER EVENTS?
        ↓
WHAT SHOULD I DO?
```

**That is the core of SOC Alert Analyzer.**
