# SOC Alert Analyzer — MITRE ATT&CK Threat Mapping Report

> **Report Generated (UTC):** `2026-10-24T17:35:29.174039+00:00`
> **Framework:** MITRE ATT&CK® Enterprise Matrix v14

---

## 1. Executive Summary

| Metric | Value | Status / Description |
| :--- | :--- | :--- |
| **Total Security Alerts** | `9` | Security events evaluated |
| **Mapped to MITRE ATT&CK** | `9` | Direct technique attribution |
| **ATT&CK Coverage Rate** | `100.0%` | Defensive classification coverage |
| **Distinct Tactics Triggered** | `8` | Attack phases identified |
| **Distinct Techniques Observed** | `9` | Unique adversary techniques |
| **Highest Observed Severity** | **`CRITICAL`** | Prioritized escalation urgency |

---

## 2. Adversary Tactic Distribution

| Tactic | ID | Alert Count | Share (%) | Peak Severity | Observed Techniques |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | `TA0001` | **1** | 11.1% | `CRITICAL` | [T1190](https://attack.mitre.org/techniques/T1190/) |
| **Execution** | `TA0002` | **1** | 11.1% | `HIGH` | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Persistence** | `TA0003` | **2** | 22.2% | `CRITICAL` | [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| **Privilege Escalation** | `TA0004` | **1** | 11.1% | `MEDIUM` | [T1548](https://attack.mitre.org/techniques/T1548/) |
| **Defense Evasion** | `TA0005` | **1** | 11.1% | `CRITICAL` | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) |
| **Credential Access** | `TA0006` | **1** | 11.1% | `CRITICAL` | [T1003](https://attack.mitre.org/techniques/T1003/) |
| **Discovery** | `TA0007` | **1** | 11.1% | `MEDIUM` | [T1046](https://attack.mitre.org/techniques/T1046/) |
| **Command and Control** | `TA0011` | **1** | 11.1% | `HIGH` | [T1071](https://attack.mitre.org/techniques/T1071/) |

---

## 3. Top Observed Adversary Techniques

| Technique ID | Technique Name | Primary Tactic | Alert Count | Peak Severity | MITRE Link |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `T1046` | **Network Service Discovery** | Discovery | **1** | `MEDIUM` | [Link](https://attack.mitre.org/techniques/T1046/) |
| `T1190` | **Exploit Public-Facing Application** | Initial Access | **1** | `CRITICAL` | [Link](https://attack.mitre.org/techniques/T1190/) |
| `T1505.003` | **Server Software Component: Web Shell** | Persistence | **1** | `CRITICAL` | [Link](https://attack.mitre.org/techniques/T1505/003/) |
| `T1059.001` | **Command and Scripting Interpreter: PowerShell** | Execution | **1** | `HIGH` | [Link](https://attack.mitre.org/techniques/T1059/001/) |
| `T1547.001` | **Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder** | Persistence | **1** | `HIGH` | [Link](https://attack.mitre.org/techniques/T1547/001/) |
| `T1548` | **Abuse Elevation Control Mechanism** | Privilege Escalation | **1** | `MEDIUM` | [Link](https://attack.mitre.org/techniques/T1548/) |
| `T1070.001` | **Indicator Removal: Clear Windows Event Logs** | Defense Evasion | **1** | `CRITICAL` | [Link](https://attack.mitre.org/techniques/T1070/001/) |
| `T1003` | **OS Credential Dumping** | Credential Access | **1** | `CRITICAL` | [Link](https://attack.mitre.org/techniques/T1003/) |
| `T1071` | **Application Layer Protocol** | Command and Control | **1** | `HIGH` | [Link](https://attack.mitre.org/techniques/T1071/) |

---

## 4. Detailed Tactic Breakdown & Telemetry Evidence

### Initial Access (TA0001)
> _Adversaries gain an initial foothold into your environment._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 1 | High: 0 | Med: 0 | Low: 0
- **Recommended Mitigation:** Immediately patch exposed public-facing applications (CVEs, Web Services); deploy Web Application Firewalls (WAF); enforce MFA on all external login interfaces.

#### Techniques Observed:
- **[T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)** (`CRITICAL` — 1 alerts)
  - _Description:_ Adversaries may attempt to exploit vulnerabilities in Internet-facing software or web services (e.g. SQLi, Path Traversal).
  - _Involved Assets / Endpoints:_ `10.0.1.15`, `198.51.100.120`
  - _Sample Telemetry:_ `SQL Injection attempt detected in HTTP parameter id=1 UNION SELECT null,username,password FROM users--`

### Execution (TA0002)
> _Adversaries run malicious code on targeted local or remote hosts._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 0 | High: 1 | Med: 0 | Low: 0
- **Recommended Mitigation:** Restrict scripting interpreters via PowerShell Constrained Language Mode and AppLocker/WDAC; enable PowerShell Script Block Logging (Event ID 4104).

#### Techniques Observed:
- **[T1059.001: Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)** (`HIGH` — 1 alerts)
  - _Description:_ Adversaries may abuse PowerShell commands and scripts for code execution and lateral movement.
  - _Involved Assets / Endpoints:_ `10.0.1.15`, `198.51.100.120`
  - _Sample Telemetry:_ `Suspicious PowerShell execution with encoded script block downloading remote payload`

### Persistence (TA0003)
> _Adversaries maintain their foothold across restarts and changed credentials._

- **Total Alerts:** 2 (22.2% of mapped alerts)
- **Severity Distribution:** Critical: 1 | High: 1 | Med: 0 | Low: 0
- **Recommended Mitigation:** Continuously monitor and audit Windows Task Scheduler, Startup folder run keys, system services, and Linux cron directories for unauthorized autostart entries.

#### Techniques Observed:
- **[T1505.003: Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)** (`CRITICAL` — 1 alerts)
  - _Description:_ Adversaries may place or probe for web shells on servers to establish persistent access.
  - _Involved Assets / Endpoints:_ `10.0.1.15`, `198.51.100.120`
  - _Sample Telemetry:_ `Web shell upload probe targeting /uploads/cmd.php with code execution payloads`
- **[T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)** (`HIGH` — 1 alerts)
  - _Description:_ Adversaries may achieve persistence by adding a program to the Startup folder or registry run keys.
  - _Involved Assets / Endpoints:_ `10.0.1.15`
  - _Sample Telemetry:_ `Persistence established: Startup registry run key modified for unsigned payload`

### Privilege Escalation (TA0004)
> _Adversaries gain higher-level permissions, such as root or SYSTEM._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 0 | High: 0 | Med: 1 | Low: 0
- **Recommended Mitigation:** Enforce Least Privilege Access; audit sudoers permissions; restrict local Administrators security group membership; inspect UAC bypass attempts.

#### Techniques Observed:
- **[T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)** (`MEDIUM` — 1 alerts)
  - _Description:_ Adversaries may circumvent mechanisms designed to control elevation of privileges (such as sudo or UAC).
  - _Involved Assets / Endpoints:_ `10.0.1.15`
  - _Sample Telemetry:_ `Unusual sudo privilege escalation: User svc_web spawned root shell via /bin/bash`

### Defense Evasion (TA0005)
> _Adversaries attempt to avoid detection throughout their compromise._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 1 | High: 0 | Med: 0 | Low: 0
- **Recommended Mitigation:** Stream event and security logs to an off-site, immutable SIEM immediately; trigger high-priority alerts on Windows Event 1102 (audit log cleared) and disabled firewalls.

#### Techniques Observed:
- **[T1070.001: Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)** (`CRITICAL` — 1 alerts)
  - _Description:_ Adversaries may clear Windows Event Logs to hide intrusion activity and forensic evidence.
  - _Involved Assets / Endpoints:_ `10.0.1.15`
  - _Sample Telemetry:_ `Defense Evasion: Security audit log cleared by adversary session`

### Credential Access (TA0006)
> _Adversaries steal credentials such as usernames and password hashes._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 1 | High: 0 | Med: 0 | Low: 0
- **Recommended Mitigation:** Enable Windows Credential Guard to isolate LSASS memory; enforce strong password policies and rate-limiting against brute force; rotate high-privilege credentials.

#### Techniques Observed:
- **[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)** (`CRITICAL` — 1 alerts)
  - _Description:_ Adversaries may attempt to dump credentials to obtain account login and credential material.
  - _Involved Assets / Endpoints:_ `10.0.1.15`
  - _Sample Telemetry:_ `OS Credential Dumping: Mimikatz memory injection detected targeting LSASS process`

### Discovery (TA0007)
> _Adversaries observe and enumerate your internal environment and network posture._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 0 | High: 0 | Med: 1 | Low: 0
- **Recommended Mitigation:** Segment internal corporate subnets to prevent lateral reconnaissance sweeps; alert on rapid sequential internal port scans.

#### Techniques Observed:
- **[T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/)** (`MEDIUM` — 1 alerts)
  - _Description:_ Adversaries may attempt to enumerate network services, open ports, and active hosts across the environment.
  - _Involved Assets / Endpoints:_ `10.0.1.15`, `198.51.100.120`
  - _Sample Telemetry:_ `Port scan detected from untrusted external IP sweep targeting edge firewall`

### Command and Control (TA0011)
> _Adversaries communicate with systems under their control across the perimeter._

- **Total Alerts:** 1 (11.1% of mapped alerts)
- **Severity Distribution:** Critical: 0 | High: 1 | Med: 0 | Low: 0
- **Recommended Mitigation:** Inspect outbound perimeter traffic; enforce DNS sinkholing for dynamic/fast-flux domains; alert on long-lived connections to untrusted foreign IPs.

#### Techniques Observed:
- **[T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)** (`HIGH` — 1 alerts)
  - _Description:_ Adversaries may communicate using application layer protocols to avoid detection or network filtering.
  - _Involved Assets / Endpoints:_ `10.0.1.15`, `203.0.113.88`
  - _Sample Telemetry:_ `Suspicious outbound connection detected to known Command and Control (C2) server`

---

## 5. Enterprise ATT&CK Matrix Overview

| Tactic | Status | Alerts | Active Techniques |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** (`TA0043`) | `Inactive` | 0 | None observed |
| **Resource Development** (`TA0042`) | `Inactive` | 0 | None observed |
| **Initial Access** (`TA0001`) | `ACTIVE (FLAGGED)` | 1 | Exploit Public-Facing Application |
| **Execution** (`TA0002`) | `ACTIVE (FLAGGED)` | 1 | Command and Scripting Interpreter: PowerShell |
| **Persistence** (`TA0003`) | `ACTIVE (FLAGGED)` | 2 | Server Software Component: Web Shell, Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **Privilege Escalation** (`TA0004`) | `ACTIVE (FLAGGED)` | 1 | Abuse Elevation Control Mechanism |
| **Defense Evasion** (`TA0005`) | `ACTIVE (FLAGGED)` | 1 | Indicator Removal: Clear Windows Event Logs |
| **Credential Access** (`TA0006`) | `ACTIVE (FLAGGED)` | 1 | OS Credential Dumping |
| **Discovery** (`TA0007`) | `ACTIVE (FLAGGED)` | 1 | Network Service Discovery |
| **Lateral Movement** (`TA0008`) | `Inactive` | 0 | None observed |
| **Collection** (`TA0009`) | `Inactive` | 0 | None observed |
| **Command and Control** (`TA0011`) | `ACTIVE (FLAGGED)` | 1 | Application Layer Protocol |
| **Exfiltration** (`TA0010`) | `Inactive` | 0 | None observed |
| **Impact** (`TA0040`) | `Inactive` | 0 | None observed |

---

## 6. Defensive Action Items

1. **Prioritize Critical & High Severity Techniques:** Address active Initial Access and Privilege Escalation triggers immediately.
2. **Validate SIEM Logging Pipeline:** Ensure logs from all endpoints and network perimeter sensors are streaming continuously.
3. **Execute Playbook Containment:** Follow the recommended remediation guidance outlined for each triggered tactic.
