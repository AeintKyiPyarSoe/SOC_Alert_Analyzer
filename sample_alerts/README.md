# Sample SIEM Alerts Telemetry Datasets

This directory contains mock SIEM JSON exports designed for security analysts, incident responders, and evaluators to test **SOC Alert Analyzer** immediately **without requiring external SIEM integrations, cloud connectors, or live API keys**.

---

## Included Datasets

| File | SIEM / Telemetry Source | Simulated Threat Scenarios | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- |
| `wazuh_alerts.json` | Wazuh HIDS / SIEM JSON | SSH Brute Force, File Integrity Monitoring (`/etc/shadow`), Unauthorized Sudo Execution, Rootkit Masquerading | **T1110** (Brute Force)<br>**T1548** (Privilege Escalation)<br>**T1565** (Data Manipulation)<br>**T1036** (Masquerading) |
| `suricata_eve.json` | Suricata NIDS EVE JSON | External Nmap Scan Sweep, Apache Struts Remote Code Execution (CVE-2017-5638), Fast-Flux C2 Beacon, DNS Amplification DoS | **T1046** (Network Discovery)<br>**T1190** (Exploit Public-Facing App)<br>**T1071** (Command and Control)<br>**T1498** (Denial of Service) |
| `windows_security_events.json` | Windows Security Event Log & Defender JSON | Event 4625 (Logon Brute Force), Event 4688 (PowerShell Download Cradle), Event 7045 (Malicious Service Installed), Event 4698 (Scheduled Task), Event 1102 (Log Cleared), Defender 1116 (Mimikatz) | **T1110** (Brute Force)<br>**T1059.001** (PowerShell)<br>**T1543.003** (Windows Service)<br>**T1053.005** (Scheduled Task)<br>**T1070.001** (Clear Logs)<br>**T1003** (Credential Dumping) |
| `siem_multi_stage_incident.json` | Unified SIEM Incident Correlation Export | Full cyber kill-chain attack progression: Port Scan → SQL Injection → Web Shell → PowerShell Cradle → Registry Persistence → Sudo Elevation → Audit Log Cleared → Mimikatz → C2 Beacon | **T1046**, **T1190**, **T1505.003**, **T1059.001**, **T1547.001**, **T1548**, **T1070.001**, **T1003**, **T1071** |

---

## How to Test Immediately (Zero API Keys Needed)

### Method 1: Web Interface Drag-and-Drop
1. Start the application:
   ```bash
   python launcher.py
   ```
   *(or run with Docker: `docker compose up -d`)*
2. In your browser, open [http://localhost:8000/upload](http://localhost:8000/upload).
3. Drag and drop any `.json` file from `sample_alerts/` into the upload box.
4. Click **Ingest & Analyze Telemetry →**.
5. The analyzer immediately normalizes the events, calculates urgency scores, correlates related alerts into multi-stage incidents, and maps tactics to the **MITRE ATT&CK Matrix**.

### Method 2: Command-Line / cURL API Ingestion
To ingest telemetry via the REST API using an analyst key:
```bash
# Upload Wazuh sample alerts
curl -X POST "http://localhost:8000/api/v1/alerts/upload" \
  -H "X-API-Key: analyst_sample_key" \
  -F "file=@sample_alerts/wazuh_alerts.json"

# Upload Windows Security Events
curl -X POST "http://localhost:8000/api/v1/alerts/upload" \
  -H "X-API-Key: analyst_sample_key" \
  -F "file=@sample_alerts/windows_security_events.json"
```

### Method 3: One-Click Quick Ingestion API
Load datasets instantly via internal quick-load endpoints:
```bash
curl -X POST "http://localhost:8000/api/v1/sample-data/load/wazuh" -H "X-API-Key: analyst_sample_key"
curl -X POST "http://localhost:8000/api/v1/sample-data/load/suricata" -H "X-API-Key: analyst_sample_key"
curl -X POST "http://localhost:8000/api/v1/sample-data/load/windows" -H "X-API-Key: analyst_sample_key"
```

### Method 4: Automated MITRE ATT&CK Summary Generation
Generate a comprehensive MITRE ATT&CK breakdown report directly from the sample data:
```bash
python scripts/generate_mitre_report.py --input sample_alerts/siem_multi_stage_incident.json
```
