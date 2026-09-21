from typing import Optional, Dict, Any

# Canonical MITRE ATT&CK Enterprise mappings
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
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

class MitreMapper:
    """Maps security events to MITRE ATT&CK techniques."""

    @staticmethod
    def map_event(event_type: str, description: str = "") -> Optional[str]:
        event = event_type.lower()
        desc = description.lower()

        # Brute force / Auth failure
        if "ssh_authentication_failure" in event or "ssh_invalid_user" in event or "windows_failed_logon" in event:
            return "T1110"
        if "brute" in desc or "failed login" in desc or "failed password" in desc or "failed logon" in desc:
            return "T1110"
        if "password guessing" in desc:
            return "T1110.001"

        # SSH activity / lateral movement
        if "ssh_login_successful" in event or "ssh_activity" in event:
            return "T1021.004"

        # Valid Accounts / Windows Logon
        if "windows_successful_logon" in event:
            return "T1078"

        # Privilege escalation / Account manipulation
        if "windows_privilege_escalation" in event or "administrators group" in desc:
            return "T1098"
        if "windows_account_created" in event:
            return "T1136.001"

        # Persistence: Services & Tasks & Startup
        if "persistence_startup_created" in event or "startup" in desc:
            return "T1547.001"
        if "windows_service_installed" in event or "service installed" in desc:
            return "T1543.003"
        if "windows_scheduled_task" in event or "scheduled task" in desc:
            return "T1053.005"

        # Defense Evasion: Log cleared & Firewall disabled & Masquerading
        if "windows_log_cleared" in event or "log cleared" in desc or "audit log" in desc:
            return "T1070.001"
        if "host_firewall_disabled" in event or "firewall is disabled" in desc:
            return "T1562.001"
        if "masqueraded_process" in event or "masquerad" in desc:
            return "T1036"

        # Network discovery / Scan / Open ports
        if "network_scan" in event or "port_scan" in event or "insecure_listening_port" in event:
            return "T1046"
        if "scan" in desc or "sweep" in desc or "listening port" in desc:
            return "T1046"

        # Command & Control / Suspicious outbound
        if "suspicious_outbound_connection" in event or "outbound connection" in desc:
            return "T1071"

        # Script execution / PowerShell
        if "powershell" in desc or "powershell" in event or "script_block" in event:
            return "T1059.001"
        if "windows_suspicious_process" in event or "suspicious_process" in event or "suspicious_command" in event:
            return "T1059"

        # Web Attacks
        if "web_sql_injection" in event or "sql injection" in desc:
            return "T1190"
        if "web_path_traversal" in event or "directory traversal" in desc or "lfi" in desc:
            return "T1190"
        if "web_xss_attempt" in event or "cross-site scripting" in desc:
            return "T1190"
        if "web_shell_probe" in event or "web shell" in desc:
            return "T1505.003"
        if "web_scanner_activity" in event or "vulnerability scanner" in desc or "web_reconnaissance" in event:
            return "T1595"

        # Resource Hijacking / Mining
        if "cryptominer_detected" in event or "miner" in desc or "cryptomining" in desc:
            return "T1496"

        # SSH activity / lateral movement
        if "ssh_activity" in event:
            return "T1021.004"

        # Privilege escalation / sudo
        if "sudo" in event or "rootcheck" in event or "privilege" in desc:
            return "T1548"

        # File integrity / Syscheck
        if "file_integrity" in event or "syscheck" in desc:
            return "T1565"

        # DoS / Flooding
        if "denial_of_service" in event or "dos" in desc or "flood" in desc:
            return "T1498"

        # Exploits
        if "exploit" in event or "exploit" in desc:
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
