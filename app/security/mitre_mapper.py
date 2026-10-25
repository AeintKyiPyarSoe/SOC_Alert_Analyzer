import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

# Canonical MITRE ATT&CK Enterprise mappings
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "url": "https://attack.mitre.org/techniques/T1003/"
    },
    "T1003.001": {
        "id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access and dump credentials from the Local Security Authority Subsystem Service (LSASS) process memory.",
        "url": "https://attack.mitre.org/techniques/T1003/001/"
    },
    "T1021.002": {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may leverage SMB/Windows administrative shares (such as C$ or ADMIN$) to move laterally within an environment.",
        "url": "https://attack.mitre.org/techniques/T1021/002/"
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection and network filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/004/"
    },
    "T1218": {
        "id": "T1218",
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversaries may bypass process and signature-based defenses by proxying execution of malicious code with signed or trusted binaries.",
        "url": "https://attack.mitre.org/techniques/T1218/"
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "An adversary may rely upon a user opening a malicious file or attachment to achieve execution.",
        "url": "https://attack.mitre.org/techniques/T1204/002/"
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or remove built-in operating system recovery mechanisms, such as Volume Shadow Copies.",
        "url": "https://attack.mitre.org/techniques/T1490/"
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": "Adversaries may match or approximate legitimate binary names or directory paths to evade defenses.",
        "url": "https://attack.mitre.org/techniques/T1036/005/"
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt password guessing or password spraying against accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may systematically guess passwords to gain unauthorized access to target accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to enumerate network services, open ports, and active hosts across the environment.",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for code execution and lateral movement.",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": "Adversaries may log into remote systems using Secure Shell (SSH) with compromised credentials.",
        "url": "https://attack.mitre.org/techniques/T1021/004/"
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Lateral Movement.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1543.003": {
        "id": "T1543.003",
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence or privilege escalation.",
        "url": "https://attack.mitre.org/techniques/T1543/003/"
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Execution / Persistence",
        "description": "Adversaries may abuse the Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence.",
        "url": "https://attack.mitre.org/techniques/T1053/005/"
    },
    "T1136.001": {
        "id": "T1136.001",
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a local account to maintain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1136/001/"
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may manipulate accounts to maintain access or escalate privileges, such as adding users to local administrator groups.",
        "url": "https://attack.mitre.org/techniques/T1098/"
    },
    "T1070.001": {
        "id": "T1070.001",
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide intrusion activity and forensic evidence.",
        "url": "https://attack.mitre.org/techniques/T1070/001/"
    },
    "T1036": {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to manipulate the way their code or processes appear to look legitimate (e.g. svchost in temp directories).",
        "url": "https://attack.mitre.org/techniques/T1036/"
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may achieve persistence by adding a program to the Startup folder or registry run keys.",
        "url": "https://attack.mitre.org/techniques/T1547/001/"
    },
    "T1562.001": {
        "id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable security software or firewalls to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1562/001/"
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection or network filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    "T1496": {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, such as cryptocurrency mining.",
        "url": "https://attack.mitre.org/techniques/T1496/"
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevation of privileges (such as sudo or UAC).",
        "url": "https://attack.mitre.org/techniques/T1548/"
    },
    "T1565": {
        "id": "T1565",
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may manipulate files, processes, or configurations to compromise system integrity.",
        "url": "https://attack.mitre.org/techniques/T1565/"
    },
    "T1498": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may conduct network denial of service attacks to degrade service availability.",
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software or web services (e.g. SQLi, Path Traversal).",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "T1505.003": {
        "id": "T1505.003",
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may place or probe for web shells on servers to establish persistent access.",
        "url": "https://attack.mitre.org/techniques/T1505/003/"
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans against target infrastructure to gather information for targeting.",
        "url": "https://attack.mitre.org/techniques/T1595/"
    }
}

# Standard MITRE ATT&CK Enterprise Tactics in canonical Kill Chain order
MITRE_TACTICS: Dict[str, Dict[str, Any]] = {
    "Reconnaissance": {
        "id": "TA0043",
        "order": 1,
        "description": "Adversaries gather information to plan future target operations."
    },
    "Resource Development": {
        "id": "TA0042",
        "order": 2,
        "description": "Adversaries establish infrastructure, accounts, and tools to support operations."
    },
    "Initial Access": {
        "id": "TA0001",
        "order": 3,
        "description": "Adversaries gain an initial foothold into your environment."
    },
    "Execution": {
        "id": "TA0002",
        "order": 4,
        "description": "Adversaries run malicious code on targeted local or remote hosts."
    },
    "Persistence": {
        "id": "TA0003",
        "order": 5,
        "description": "Adversaries maintain their foothold across restarts and changed credentials."
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "order": 6,
        "description": "Adversaries gain higher-level permissions, such as root or SYSTEM."
    },
    "Defense Evasion": {
        "id": "TA0005",
        "order": 7,
        "description": "Adversaries attempt to avoid detection throughout their compromise."
    },
    "Credential Access": {
        "id": "TA0006",
        "order": 8,
        "description": "Adversaries steal credentials such as usernames and password hashes."
    },
    "Discovery": {
        "id": "TA0007",
        "order": 9,
        "description": "Adversaries observe and enumerate your internal environment and network posture."
    },
    "Lateral Movement": {
        "id": "TA0008",
        "order": 10,
        "description": "Adversaries traverse and extend control across connected systems on your network."
    },
    "Collection": {
        "id": "TA0009",
        "order": 11,
        "description": "Adversaries gather data of interest to fulfill their objectives."
    },
    "Command and Control": {
        "id": "TA0011",
        "order": 12,
        "description": "Adversaries communicate with systems under their control across the perimeter."
    },
    "Exfiltration": {
        "id": "TA0010",
        "order": 13,
        "description": "Adversaries steal and transfer sensitive data out of your environment."
    },
    "Impact": {
        "id": "TA0040",
        "order": 14,
        "description": "Adversaries manipulate, interrupt, or destroy systems and operational processes."
    }
}

TACTIC_RECOMMENDATIONS: Dict[str, str] = {
    "Reconnaissance": "Audit external attack surface and open ports; enforce rate-limiting on perimeter ingress firewalls; monitor automated vulnerability scanning signatures.",
    "Initial Access": "Immediately patch exposed public-facing applications (CVEs, Web Services); deploy Web Application Firewalls (WAF); enforce MFA on all external login interfaces.",
    "Execution": "Restrict scripting interpreters via PowerShell Constrained Language Mode and AppLocker/WDAC; enable PowerShell Script Block Logging (Event ID 4104).",
    "Persistence": "Continuously monitor and audit Windows Task Scheduler, Startup folder run keys, system services, and Linux cron directories for unauthorized autostart entries.",
    "Privilege Escalation": "Enforce Least Privilege Access; audit sudoers permissions; restrict local Administrators security group membership; inspect UAC bypass attempts.",
    "Defense Evasion": "Stream event and security logs to an off-site, immutable SIEM immediately; trigger high-priority alerts on Windows Event 1102 (audit log cleared) and disabled firewalls.",
    "Credential Access": "Enable Windows Credential Guard to isolate LSASS memory; enforce strong password policies and rate-limiting against brute force; rotate high-privilege credentials.",
    "Discovery": "Segment internal corporate subnets to prevent lateral reconnaissance sweeps; alert on rapid sequential internal port scans.",
    "Lateral Movement": "Disable legacy protocols (SMBv1, NTLMv1); require MFA and jump hosts for administrative RDP/SSH access; monitor inter-subnet traffic anomalies.",
    "Command and Control": "Inspect outbound perimeter traffic; enforce DNS sinkholing for dynamic/fast-flux domains; alert on long-lived connections to untrusted foreign IPs.",
    "Impact": "Maintain encrypted, immutable offline backups; test disaster recovery procedures regularly; deploy endpoint protection to block Volume Shadow Copy deletion."
}

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


class MitreMapper:
    """
    Defensible mapping of security telemetry events to MITRE ATT&CK techniques.
    Avoids attributing techniques based on weak, ambiguous keyword substrings.
    Represents uncertain or non-attack events with None.
    Generates actionable ATT&CK matrices and structured threat summaries.
    """

    @staticmethod
    def map_event(event_type: Optional[str], description: str = "") -> Optional[str]:
        event = str(event_type or "").strip().lower()
        desc = str(description or "").strip().lower()

        # Credential dumping / Mimikatz / LSASS
        if "lsass" in desc or "sysmon_process_access" in event:
            return "T1003.001"
        if "credential_dumping" in event or "mimikatz" in desc or "credential dumping" in desc:
            return "T1003"

        # Ingress tool transfer / LOLBINs
        if "certutil" in desc and ("-urlcache" in desc or "http" in desc or "split" in desc):
            return "T1105"
        if "regsvr32" in desc:
            return "T1218.010"
        if "mshta" in desc or "rundll32" in desc:
            return "T1218"
        if "msbuild" in desc:
            return "T1127.001"

        # Lateral movement: SMB / Windows Admin Shares
        if "windows_network_share" in event or ":445" in desc or "ipc$" in desc or "admin$" in desc:
            return "T1021.002"

        # DNS C2 Query / Tunneling
        if "sysmon_suspicious_dns" in event or ("dns" in desc and ("dynu" in desc or "c2" in desc or "beacon" in desc or "duckdns" in desc or "ngrok" in desc or "tunnel" in desc)):
            return "T1071.004"

        # Brute force / Auth failure / Credential Access
        if "password guessing" in desc or "password spray" in desc or "0xc000006d" in desc or "0xc000006a" in desc:
            return "T1110.001"
        if "ssh_authentication_failure" in event or "ssh_invalid_user" in event or "windows_failed_logon" in event:
            return "T1110"
        if bool(re.search(r"\bbrute\b", desc)) or "failed login" in desc or "failed password" in desc or "failed logon" in desc:
            return "T1110"

        # SSH activity / lateral movement
        if "ssh_login_successful" in event or "ssh_activity" in event:
            return "T1021.004"

        # Valid Accounts / Windows Logon
        if "windows_successful_logon" in event:
            if any(w in desc for w in ("interactive", "normal", "routine", "unlock", "badge", "benign")):
                return None
            return "T1078"

        # Privilege escalation / Account manipulation
        if "windows_privilege_escalation" in event or "administrators group" in desc:
            return "T1098"
        if "windows_account_created" in event:
            return "T1136.001"

        # Persistence: Services & Tasks & Startup
        if "persistence_startup_created" in event or "sysmon_registry_event" in event or "currentversion\\run" in desc or "startup folder" in desc or "autostart" in desc or "registry value set" in desc:
            return "T1547.001"
        if "windows_service_installed" in event or "service installed" in desc:
            return "T1543.003"
        if "windows_scheduled_task" in event or "scheduled task" in desc:
            return "T1053.005"

        # Defense Evasion: Log cleared & Security control tampering & Recovery inhibition & Masquerading
        if "windows_log_cleared" in event or "log cleared" in desc or "audit log cleared" in desc:
            return "T1070.001"
        if ("host_firewall_disabled" in event or "firewall is disabled" in desc or "firewall disabled" in desc or
            "advfirewall" in desc or ("firewall" in desc and ("state off" in desc or "disable" in desc or "-enabled false" in desc)) or
            "set-mppreference" in desc or "disablerealtime" in desc or "exclusionpath" in desc or "tamperprotection" in desc or
            "windefend" in desc):
            return "T1562.001"
        if "shadowcopy delete" in desc or "delete shadows" in desc or "wbadmin delete" in desc or ("wmic" in desc and "shadowcopy" in desc):
            return "T1490"
        if "masqueraded_process" in event or "masquerad" in desc:
            return "T1036"

        # Network discovery / Active Scan (requires explicit scan context, distinct from passive listening port posture)
        if "network_scan" in event or "port_scan" in event:
            return "T1046"
        if ("port scan" in desc or "network scan" in desc or "ip sweep" in desc or
                "port sweep" in desc or
                bool(re.search(r"\b(syn|fin|xmas|ack)\s+scan\b", desc))):
            return "T1046"

        # Command & Control / Suspicious outbound
        if ("sysmon_suspicious_network" in event or "suspicious_outbound_connection" in event or
            "suspicious outbound" in desc or ":4444" in desc or ":1337" in desc):
            return "T1071"

        # Strip parent process annotation so parent process info doesn't falsely categorize child binaries
        desc_no_parent = re.sub(r"\(parent:\s*[^)]+\)", "", desc, flags=re.IGNORECASE)

        # Script execution / PowerShell
        if ("powershell" in desc_no_parent or "powershell" in event or "script_block" in event or
            "pwsh" in desc_no_parent):
            return "T1059.001"
        if "windows_suspicious_process" in event or "sysmon_suspicious_process" in event or "suspicious_process" in event or "suspicious_command" in event:
            return "T1059"

        # Web Attacks
        if "web_sql_injection" in event or "sql injection" in desc:
            return "T1190"
        if "web_path_traversal" in event or "directory traversal" in desc or "path traversal" in desc or "lfi" in desc:
            return "T1190"
        if "web_xss_attempt" in event or "cross-site scripting" in desc:
            return "T1190"
        if "web_shell_probe" in event or "web shell" in desc:
            return "T1505.003"
        if "web_scanner_activity" in event or "vulnerability scanner" in desc or "web_reconnaissance" in event:
            return "T1595"

        # Resource Hijacking / Mining
        if "cryptominer_detected" in event or "cryptomining" in desc or bool(re.search(r"\b(cryptominer|monero|stratum)\b", desc)):
            return "T1496"

        # Privilege escalation / sudo
        if "sudo_command_execution" in event or "sudo" in event or "rootcheck" in event:
            return "T1548"
        if "privilege escalation" in desc or "elevation of privilege" in desc or "uac bypass" in desc:
            return "T1548"

        # File integrity / Syscheck
        if "file_integrity" in event or "syscheck" in desc:
            return "T1565"

        # DoS / Flooding (word boundary matching to prevent false positives on 'paradox', 'shadows', 'msdos')
        if "denial_of_service" in event or bool(re.search(r"\bdos\b", desc)) or "denial of service" in desc or "flood" in desc:
            return "T1498"

        # Exploits (requires clear exploit or CVE context)
        if "exploit" in event or "exploit attempt" in desc or "exploited" in desc or bool(re.search(r"\bcve-\d{4}-\d+\b", desc)):
            return "T1190"

        # Firewall blocked traffic
        if "firewall_blocked_traffic" in event or "firewall dropped" in desc or "firewall blocked" in desc:
            return "T1046"

        return None

    @staticmethod
    def get_details(technique_id: Optional[str]) -> Optional[Dict[str, str]]:
        if not technique_id:
            return None
        return MITRE_TECHNIQUES.get(technique_id)

    @staticmethod
    def get_url(technique_id: Optional[str]) -> Optional[str]:
        details = MitreMapper.get_details(technique_id)
        if details:
            return details.get("url")
        if technique_id and technique_id.startswith("T"):
            clean_id = technique_id.replace(".", "/")
            return f"https://attack.mitre.org/techniques/{clean_id}/"
        return None

    @classmethod
    def get_primary_tactic(cls, technique_id: Optional[str]) -> Optional[str]:
        """Resolves the primary canonical MITRE ATT&CK tactic for a given technique ID."""
        details = cls.get_details(technique_id)
        if not details:
            return None
        tactic_field = details.get("tactic", "")
        for part in [p.strip() for p in tactic_field.split("/")]:
            if part in MITRE_TACTICS:
                return part
        return tactic_field.split("/")[0].strip() if tactic_field else None

    @classmethod
    def generate_summary_report(cls, alerts: List[Any]) -> Dict[str, Any]:
        """
        Processes a list of alert models or dictionaries and produces an automated
        MITRE ATT&CK summary report mapping alerts to tactics, techniques, and heatmaps.
        """
        total_alerts = len(alerts)
        mapped_alerts = 0
        unmapped_alerts = 0

        # Data structures for aggregation
        tactics_data: Dict[str, Dict[str, Any]] = {}
        techniques_data: Dict[str, Dict[str, Any]] = {}
        highest_global_severity = "LOW"
        highest_global_rank = 0

        for a in alerts:
            # Extract attributes flexibly from SQLAlchemy model or dictionary
            if isinstance(a, dict):
                tech_id = a.get("mitre_technique")
                event_type = a.get("event_type")
                desc = a.get("description", "")
                sev = str(a.get("severity", "LOW")).upper()
                src_ip = a.get("source_ip")
                dst_ip = a.get("destination_ip")
            else:
                tech_id = getattr(a, "mitre_technique", None)
                event_type = getattr(a, "event_type", None)
                desc = getattr(a, "description", "") or ""
                sev = str(getattr(a, "severity", "LOW") or "LOW").upper()
                src_ip = getattr(a, "source_ip", None)
                dst_ip = getattr(a, "destination_ip", None)

            if not tech_id:
                tech_id = cls.map_event(event_type, desc)

            sev_rank = SEVERITY_ORDER.get(sev, 1)
            if sev_rank > highest_global_rank:
                highest_global_rank = sev_rank
                highest_global_severity = sev

            if not tech_id:
                unmapped_alerts += 1
                continue

            details = cls.get_details(tech_id)
            if not details:
                unmapped_alerts += 1
                continue

            mapped_alerts += 1
            primary_tactic = cls.get_primary_tactic(tech_id) or "Execution"
            tech_name = details.get("name", tech_id)
            tech_url = cls.get_url(tech_id)

            # Initialize tactic record if new
            if primary_tactic not in tactics_data:
                t_meta = MITRE_TACTICS.get(primary_tactic, {
                    "id": "TA0000",
                    "order": 99,
                    "description": "General Adversary Activity"
                })
                tactics_data[primary_tactic] = {
                    "tactic": primary_tactic,
                    "tactic_id": t_meta["id"],
                    "order": t_meta["order"],
                    "description": t_meta["description"],
                    "alert_count": 0,
                    "highest_severity": sev,
                    "highest_rank": sev_rank,
                    "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    "techniques": {},
                    "recommendation": TACTIC_RECOMMENDATIONS.get(primary_tactic, "Audit security controls and monitor suspicious activity.")
                }

            # Update tactic counts
            t_rec = tactics_data[primary_tactic]
            t_rec["alert_count"] += 1
            t_rec["severity_breakdown"][sev] = t_rec["severity_breakdown"].get(sev, 0) + 1
            if sev_rank > t_rec["highest_rank"]:
                t_rec["highest_rank"] = sev_rank
                t_rec["highest_severity"] = sev

            # Update technique record within tactic
            if tech_id not in t_rec["techniques"]:
                t_rec["techniques"][tech_id] = {
                    "id": tech_id,
                    "name": tech_name,
                    "url": tech_url,
                    "description": details.get("description", ""),
                    "alert_count": 0,
                    "highest_severity": sev,
                    "highest_rank": sev_rank,
                    "sample_alerts": [],
                    "affected_entities": set()
                }

            tech_rec = t_rec["techniques"][tech_id]
            tech_rec["alert_count"] += 1
            if sev_rank > tech_rec["highest_rank"]:
                tech_rec["highest_rank"] = sev_rank
                tech_rec["highest_severity"] = sev
            if desc and len(tech_rec["sample_alerts"]) < 3 and desc not in tech_rec["sample_alerts"]:
                tech_rec["sample_alerts"].append(desc)
            if src_ip:
                tech_rec["affected_entities"].add(src_ip)
            if dst_ip:
                tech_rec["affected_entities"].add(dst_ip)

            # Update global techniques leaderboard
            if tech_id not in techniques_data:
                techniques_data[tech_id] = {
                    "id": tech_id,
                    "name": tech_name,
                    "tactic": primary_tactic,
                    "tactic_id": tactics_data[primary_tactic]["tactic_id"],
                    "url": tech_url,
                    "alert_count": 0,
                    "highest_severity": sev,
                    "highest_rank": sev_rank
                }
            techniques_data[tech_id]["alert_count"] += 1
            if sev_rank > techniques_data[tech_id]["highest_rank"]:
                techniques_data[tech_id]["highest_rank"] = sev_rank
                techniques_data[tech_id]["highest_severity"] = sev

        # Calculate coverage percentage
        coverage_pct = round((mapped_alerts / total_alerts * 100), 1) if total_alerts > 0 else 0.0

        # Sort tactics according to MITRE kill chain order
        sorted_tactics_list = []
        for t_name, t_val in sorted(tactics_data.items(), key=lambda item: item[1]["order"]):
            # Format techniques inside tactic
            formatted_techniques = []
            for tid, trec in sorted(t_val["techniques"].items(), key=lambda x: x[1]["alert_count"], reverse=True):
                formatted_techniques.append({
                    "id": trec["id"],
                    "name": trec["name"],
                    "url": trec["url"],
                    "description": trec["description"],
                    "alert_count": trec["alert_count"],
                    "highest_severity": trec["highest_severity"],
                    "sample_alerts": trec["sample_alerts"],
                    "affected_entities": sorted(list(trec["affected_entities"]))
                })

            share_pct = round((t_val["alert_count"] / mapped_alerts * 100), 1) if mapped_alerts > 0 else 0.0
            sorted_tactics_list.append({
                "tactic": t_val["tactic"],
                "tactic_id": t_val["tactic_id"],
                "order": t_val["order"],
                "description": t_val["description"],
                "alert_count": t_val["alert_count"],
                "percentage_of_mapped": share_pct,
                "highest_severity": t_val["highest_severity"],
                "severity_breakdown": t_val["severity_breakdown"],
                "recommendation": t_val["recommendation"],
                "techniques": formatted_techniques
            })

        # Top techniques leaderboard
        top_techniques = sorted(
            [
                {
                    "id": v["id"],
                    "name": v["name"],
                    "tactic": v["tactic"],
                    "tactic_id": v["tactic_id"],
                    "url": v["url"],
                    "alert_count": v["alert_count"],
                    "highest_severity": v["highest_severity"]
                }
                for v in techniques_data.values()
            ],
            key=lambda x: x["alert_count"],
            reverse=True
        )

        # Build Full ATT&CK Matrix Grid Representation across all 14 standard tactics
        matrix_grid = []
        for t_name, t_meta in sorted(MITRE_TACTICS.items(), key=lambda item: item[1]["order"]):
            active_tactic = tactics_data.get(t_name)
            if active_tactic:
                t_techniques = [
                    {
                        "id": trec["id"],
                        "name": trec["name"],
                        "url": trec["url"],
                        "alert_count": trec["alert_count"],
                        "highest_severity": trec["highest_severity"]
                    }
                    for trec in active_tactic["techniques"].values()
                ]
                matrix_grid.append({
                    "tactic": t_name,
                    "tactic_id": t_meta["id"],
                    "order": t_meta["order"],
                    "is_active": True,
                    "alert_count": active_tactic["alert_count"],
                    "highest_severity": active_tactic["highest_severity"],
                    "techniques": sorted(t_techniques, key=lambda x: x["alert_count"], reverse=True)
                })
            else:
                matrix_grid.append({
                    "tactic": t_name,
                    "tactic_id": t_meta["id"],
                    "order": t_meta["order"],
                    "is_active": False,
                    "alert_count": 0,
                    "highest_severity": None,
                    "techniques": []
                })

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_alerts": total_alerts,
            "mapped_alerts": mapped_alerts,
            "unmapped_alerts": unmapped_alerts,
            "coverage_percentage": coverage_pct,
            "highest_severity": highest_global_severity if mapped_alerts > 0 else "NONE",
            "tactics_count": len(sorted_tactics_list),
            "techniques_count": len(techniques_data),
            "tactics": sorted_tactics_list,
            "top_techniques": top_techniques[:10],
            "matrix_grid": matrix_grid
        }

    @classmethod
    def generate_markdown_report(cls, summary: Dict[str, Any]) -> str:
        """
        Renders the MITRE ATT&CK summary dictionary into publication-quality GitHub Flavored Markdown.
        """
        lines = []
        lines.append("# SOC Alert Analyzer — MITRE ATT&CK Threat Mapping Report")
        lines.append("")
        lines.append(f"> **Report Generated (UTC):** `{summary.get('generated_at', '')}`")
        lines.append(f"> **Framework:** MITRE ATT&CK® Enterprise Matrix v14")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append("| Metric | Value | Status / Description |")
        lines.append("| :--- | :--- | :--- |")
        lines.append(f"| **Total Security Alerts** | `{summary.get('total_alerts', 0)}` | Security events evaluated |")
        lines.append(f"| **Mapped to MITRE ATT&CK** | `{summary.get('mapped_alerts', 0)}` | Direct technique attribution |")
        lines.append(f"| **ATT&CK Coverage Rate** | `{summary.get('coverage_percentage', 0)}%` | Defensive classification coverage |")
        lines.append(f"| **Distinct Tactics Triggered** | `{summary.get('tactics_count', 0)}` | Attack phases identified |")
        lines.append(f"| **Distinct Techniques Observed** | `{summary.get('techniques_count', 0)}` | Unique adversary techniques |")
        lines.append(f"| **Highest Observed Severity** | **`{summary.get('highest_severity', 'NONE')}`** | Prioritized escalation urgency |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 2. Tactic Distribution Table
        lines.append("## 2. Adversary Tactic Distribution")
        lines.append("")
        if not summary.get("tactics"):
            lines.append("_No alerts in this evaluation matched MITRE ATT&CK techniques._")
            lines.append("")
        else:
            lines.append("| Tactic | ID | Alert Count | Share (%) | Peak Severity | Observed Techniques |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for t in summary["tactics"]:
                tech_list = ", ".join([f"[{x['id']}]({x['url']})" for x in t["techniques"]])
                lines.append(
                    f"| **{t['tactic']}** | `{t['tactic_id']}` | **{t['alert_count']}** | "
                    f"{t['percentage_of_mapped']}% | `{t['highest_severity']}` | {tech_list} |"
                )
            lines.append("")

        lines.append("---")
        lines.append("")

        # 3. Top Techniques
        lines.append("## 3. Top Observed Adversary Techniques")
        lines.append("")
        if not summary.get("top_techniques"):
            lines.append("_No techniques detected._")
            lines.append("")
        else:
            lines.append("| Technique ID | Technique Name | Primary Tactic | Alert Count | Peak Severity | MITRE Link |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for tt in summary["top_techniques"]:
                lines.append(
                    f"| `{tt['id']}` | **{tt['name']}** | {tt['tactic']} | "
                    f"**{tt['alert_count']}** | `{tt['highest_severity']}` | [Link]({tt['url']}) |"
                )
            lines.append("")

        lines.append("---")
        lines.append("")

        # 4. Deep-Dive per Tactic with Evidence
        lines.append("## 4. Detailed Tactic Breakdown & Telemetry Evidence")
        lines.append("")
        for t in summary.get("tactics", []):
            lines.append(f"### {t['tactic']} ({t['tactic_id']})")
            lines.append(f"> _{t['description']}_")
            lines.append("")
            lines.append(f"- **Total Alerts:** {t['alert_count']} ({t['percentage_of_mapped']}% of mapped alerts)")
            lines.append(f"- **Severity Distribution:** Critical: {t['severity_breakdown']['CRITICAL']} | High: {t['severity_breakdown']['HIGH']} | Med: {t['severity_breakdown']['MEDIUM']} | Low: {t['severity_breakdown']['LOW']}")
            lines.append(f"- **Recommended Mitigation:** {t['recommendation']}")
            lines.append("")
            lines.append("#### Techniques Observed:")
            for tech in t["techniques"]:
                entities_str = ", ".join([f"`{e}`" for e in tech["affected_entities"][:5]]) or "Host Local"
                lines.append(f"- **[{tech['id']}: {tech['name']}]({tech['url']})** (`{tech['highest_severity']}` — {tech['alert_count']} alerts)")
                lines.append(f"  - _Description:_ {tech['description']}")
                lines.append(f"  - _Involved Assets / Endpoints:_ {entities_str}")
                if tech.get("sample_alerts"):
                    lines.append(f"  - _Sample Telemetry:_ `{tech['sample_alerts'][0]}`")
            lines.append("")

        lines.append("---")
        lines.append("")

        # 5. MITRE ATT&CK Enterprise Matrix Navigator Overview
        lines.append("## 5. Enterprise ATT&CK Matrix Overview")
        lines.append("")
        lines.append("| Tactic | Status | Alerts | Active Techniques |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for col in summary.get("matrix_grid", []):
            status_tag = "ACTIVE (FLAGGED)" if col["is_active"] else "Inactive"
            tech_names = ", ".join([x["name"] for x in col["techniques"]]) if col["techniques"] else "None observed"
            lines.append(f"| **{col['tactic']}** (`{col['tactic_id']}`) | `{status_tag}` | {col['alert_count']} | {tech_names} |")

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 6. Defensive Action Items")
        lines.append("")
        lines.append("1. **Prioritize Critical & High Severity Techniques:** Address active Initial Access and Privilege Escalation triggers immediately.")
        lines.append("2. **Validate SIEM Logging Pipeline:** Ensure logs from all endpoints and network perimeter sensors are streaming continuously.")
        lines.append("3. **Execute Playbook Containment:** Follow the recommended remediation guidance outlined for each triggered tactic.")
        lines.append("")

        return "\n".join(lines)

    @classmethod
    def generate_text_summary(cls, summary: Dict[str, Any]) -> str:
        """
        Renders an ASCII text summary for CLI terminals and log streams.
        """
        border = "=" * 78
        sep = "-" * 78
        lines = [
            border,
            "  SOC ALERT ANALYZER — MITRE ATT&CK THREAT SUMMARY REPORT",
            border,
            f"  Generated At        : {summary.get('generated_at', 'N/A')}",
            f"  Total Alerts        : {summary.get('total_alerts', 0)}",
            f"  Mapped Alerts       : {summary.get('mapped_alerts', 0)} ({summary.get('coverage_percentage', 0)}% coverage)",
            f"  Tactics Triggered   : {summary.get('tactics_count', 0)}",
            f"  Techniques Observed : {summary.get('techniques_count', 0)}",
            f"  Peak Severity       : {summary.get('highest_severity', 'NONE')}",
            sep,
            "  TACTIC DISTRIBUTION:",
            sep
        ]

        for t in summary.get("tactics", []):
            lines.append(
                f"  [{t['tactic_id']}] {t['tactic']:<22} : {t['alert_count']:>3} alerts ({t['percentage_of_mapped']:>5.1f}%) | "
                f"Max: {t['highest_severity']:<8} | {len(t['techniques'])} techniques"
            )

        lines.extend([
            sep,
            "  TOP TECHNIQUES:",
            sep
        ])
        for tt in summary.get("top_techniques", [])[:5]:
            lines.append(
                f"  {tt['id']:<10} {tt['name']:<32} | {tt['tactic']:<20} | {tt['alert_count']:>3} alerts [{tt['highest_severity']}]"
            )

        lines.append(border)
        return "\n".join(lines)
