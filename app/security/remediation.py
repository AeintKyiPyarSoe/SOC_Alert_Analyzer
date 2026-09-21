from typing import Dict, List, Any

# Knowledge base of beginner-friendly narratives and action playbooks
EXPLANATION_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "ssh_authentication_failure": {
        "title": "SSH Authentication Failure / Brute Force Attempt",
        "what_happened": "Someone repeatedly attempted to log into your computer or server using the Secure Shell (SSH) remote login service.",
        "why_suspicious": "Multiple failed attempts in a short duration typically indicate an automated password-guessing robot (brute force attack) trying common usernames and passwords.",
        "recommended_actions": [
            "Check whether the source IP address is known to you or your organization.",
            "Review recent SSH login logs to verify if any attempts succeeded.",
            "Enforce strong, random passwords on all administrative accounts.",
            "Disable password-based SSH authentication and use cryptographic SSH keys instead.",
            "Consider changing the default SSH port (22) or using fail2ban to automatically block attackers."
        ]
    },
    "windows_failed_logon": {
        "title": "Windows Authentication Failure (Event ID 4625)",
        "what_happened": "A logon attempt to this Windows computer failed due to a bad password, unknown username, or account restriction.",
        "why_suspicious": "Repeated failed logons from the same IP address or targeting administrative accounts (Administrator, Guest) indicates brute-force or credential spraying attacks.",
        "recommended_actions": [
            "Review the target username and source network address in the raw event.",
            "Verify if the attempt came from an internal workstation or an external network.",
            "Enforce Account Lockout Policy (e.g. lock account after 5 invalid attempts).",
            "Enable Multi-Factor Authentication (MFA) on remote desktop and administrative portals.",
            "If an external IP is identified, block it immediately in Windows Firewall."
        ]
    },
    "ssh_invalid_user": {
        "title": "SSH Login Attempt with Non-Existent Username",
        "what_happened": "An unknown remote device tried to log into your machine using account usernames that do not exist (e.g., 'test', 'admin', 'oracle').",
        "why_suspicious": "Attackers run automated dictionary scans across internet IP ranges probing for default or poorly secured services.",
        "recommended_actions": [
            "Verify that default accounts (like 'admin' or 'guest') remain disabled.",
            "Check your firewall settings to restrict SSH port 22 access to known trusted IP addresses.",
            "Ensure root login via SSH is disabled (`PermitRootLogin no`)."
        ]
    },
    "insecure_listening_port": {
        "title": "Insecure or High-Risk Listening Port Exposed",
        "what_happened": "A local process is listening on all network interfaces (0.0.0.0 or ::) on an insecure, unencrypted, or dangerous port.",
        "why_suspicious": "Exposing unencrypted services (e.g., Telnet 23, FTP 21) or known backdoor ports allows external devices on the network to probe or exploit local applications.",
        "recommended_actions": [
            "Identify the process name and PID hosting this listening port.",
            "If the service is not required for daily business, stop the service and disable auto-start.",
            "Bind the service to 127.0.0.1 (localhost only) if remote network access is unnecessary.",
            "Configure Windows Firewall or iptables to block inbound connections on this port from untrusted subnets."
        ]
    },
    "suspicious_outbound_connection": {
        "title": "Suspicious Outbound Network Connection (Potential C2)",
        "what_happened": "A local process established an outbound network connection to a public or remote IP on an unusual port.",
        "why_suspicious": "Malware, reverse shells, and Command & Control (C2) agents regularly initiate outbound connections to remote attacker-controlled infrastructure.",
        "recommended_actions": [
            "Identify the binary initiating the connection and check its location on disk.",
            "Terminate the offending process immediately using Task Manager or `kill`.",
            "Look up the destination IP on threat intelligence databases (e.g., VirusTotal or AbuseIPDB).",
            "Check persistence mechanisms (Scheduled Tasks, Startup folder, Registry Run keys).",
            "Run a full anti-malware scan across the system."
        ]
    },
    "persistence_startup_created": {
        "title": "Suspicious File Dropped into Startup Folder (T1547.001)",
        "what_happened": "A new executable, script, or shortcut was detected in the Windows Startup directory.",
        "why_suspicious": "Placing payloads in the Startup folder is a classic persistence technique adversaries use to automatically execute malware upon every system boot.",
        "recommended_actions": [
            "Locate the newly created file in the Startup folder.",
            "Verify if this file belongs to software you intentionally installed.",
            "If unrecognized, delete or quarantine the file immediately.",
            "Check which process or installer created this file.",
            "Run a comprehensive anti-malware scan across the machine."
        ]
    },
    "host_firewall_disabled": {
        "title": "Host Firewall Protection Disabled",
        "what_happened": "The local system firewall (Windows Firewall or Linux ufw/iptables) was found to be turned OFF or disabled on one or more profiles.",
        "why_suspicious": "Adversaries frequently disable host firewalls as part of defense evasion to allow unrestricted network access and reverse shells.",
        "recommended_actions": [
            "Immediately turn the firewall back ON (`netsh advfirewall set allprofiles state on` on Windows, or `sudo ufw enable` on Linux).",
            "Investigate who or which program turned the firewall off.",
            "Review local firewall rules for unauthorized allow rules recently added."
        ]
    },
    "masqueraded_process": {
        "title": "Process Masquerading Detected (T1036)",
        "what_happened": "A process named like a critical Windows system binary (e.g., svchost.exe, lsass.exe, explorer.exe) is executing from an abnormal folder (like Temp or AppData).",
        "why_suspicious": "Legitimate Windows system processes execute strictly from `C:\\Windows\\System32`. Attackers name malware after legitimate processes to trick users and task managers.",
        "recommended_actions": [
            "Terminate the suspect process immediately.",
            "Inspect the file properties, digital signature, and hash of the executable.",
            "Isolate the executable into a quarantine location for forensic analysis.",
            "Check what created the file in that directory."
        ]
    },
    "cryptominer_detected": {
        "title": "Cryptocurrency Mining Behavior / High CPU Anomaly",
        "what_happened": "A process was detected with signature strings or sustained extreme CPU resource usage characteristic of unauthorized cryptomining.",
        "why_suspicious": "Cryptojacking malware abuses your device's computing hardware to generate cryptocurrency for attackers, causing performance degradation and overheating.",
        "recommended_actions": [
            "Inspect the process name and command line arguments.",
            "Terminate the miner process.",
            "Search disk for mining binaries (e.g. xmrig) and delete them.",
            "Check how the miner was installed (e.g. compromised browser extension, cracked software, or remote exploit)."
        ]
    },
    "windows_service_installed": {
        "title": "New Windows Service Installed (Event ID 7045)",
        "what_happened": "A new background Windows Service was registered and installed on this computer.",
        "why_suspicious": "Adversaries install malicious services to achieve persistent access and execute with high SYSTEM-level privileges across reboots.",
        "recommended_actions": [
            "Verify the service name and image path in the raw event log.",
            "Confirm whether this service was part of a recent legitimate software installation you performed.",
            "If unrecognized, stop and delete the service via PowerShell: `sc.exe delete <ServiceName>`.",
            "Inspect the target executable pointed to by the service image path."
        ]
    },
    "windows_scheduled_task": {
        "title": "New Scheduled Task Created (Event ID 4698)",
        "what_happened": "A new automated task was scheduled to run on this machine via Task Scheduler.",
        "why_suspicious": "Scheduled tasks are the top persistence mechanism used by ransomware and backdoors to re-execute automatically.",
        "recommended_actions": [
            "Open Task Scheduler (`taskschd.msc`) and find the newly created task.",
            "Inspect the task triggers, user account, and actions (what program it executes).",
            "Delete any unauthorized or suspicious tasks.",
            "Check for encoded PowerShell or VBScript commands in the task action."
        ]
    },
    "windows_log_cleared": {
        "title": "Security / System Event Log Cleared (Event ID 1102 / 104)",
        "what_happened": "An administrator or process explicitly cleared the Windows Event Log audit trail.",
        "why_suspicious": "Attackers routinely wipe event logs prior to disconnecting to destroy forensic evidence of their unauthorized access.",
        "recommended_actions": [
            "Identify the user account that cleared the audit log from the event details.",
            "Check whether this was an authorized administrative maintenance action.",
            "Assume the host may have experienced an intrusion and initiate full memory and filesystem forensics.",
            "Review centralized backups or external SIEM archives for logs recorded prior to the wipe."
        ]
    },
    "web_sql_injection": {
        "title": "SQL Injection Attack Attempt Detected",
        "what_happened": "Inbound HTTP request contained malicious SQL database query syntax (such as UNION SELECT, OR 1=1, or SQL comments).",
        "why_suspicious": "SQL injection attempts to manipulate database queries to extract sensitive credentials, bypass login forms, or steal proprietary data.",
        "recommended_actions": [
            "Identify the source IP address sending the SQL queries and block it at your web application firewall (WAF).",
            "Verify that your web application uses parameterized queries or Object-Relational Mapping (ORM).",
            "Review web application error logs to confirm whether the query was blocked or returned a database error."
        ]
    },
    "web_xss_attempt": {
        "title": "Cross-Site Scripting (XSS) Probe Detected",
        "what_happened": "An HTTP request included script tags or JavaScript execution payloads in URL parameters or form inputs.",
        "why_suspicious": "XSS vulnerabilities allow attackers to execute malicious scripts in victims' browsers, potentially hijacking user sessions and cookies.",
        "recommended_actions": [
            "Check whether the application properly encodes and sanitizes all user input before rendering in HTML.",
            "Enable Content Security Policy (CSP) HTTP headers on the web server.",
            "Verify session cookies have `HttpOnly` and `Secure` attributes enabled."
        ]
    },
    "web_path_traversal": {
        "title": "Directory Traversal / Local File Inclusion (LFI)",
        "what_happened": "An HTTP request attempted to step backwards through folder directories (`../../`) to access arbitrary system files (e.g. /etc/passwd or win.ini).",
        "why_suspicious": "Path traversal allows attackers to read sensitive configuration files, source code, and passwords outside the designated web root.",
        "recommended_actions": [
            "Validate and whitelist file input paths on the server side.",
            "Ensure the web server process runs with minimal non-root permissions.",
            "Block incoming requests containing `..` sequences at the reverse proxy or firewall."
        ]
    },
    "web_shell_probe": {
        "title": "Web Shell / Backdoor Endpoint Probe",
        "what_happened": "An external client probed URLs associated with common web backdoor shells (cmd.php, c99.php, eval-stdin) or unpatched management endpoints.",
        "why_suspicious": "Attackers look for leftover backdoors or automated exploit entry points to upload interactive command shells.",
        "recommended_actions": [
            "Scan the web root folder for unauthorized `.php`, `.jsp`, or script files.",
            "Ensure file upload directories do not allow script execution (disable PHP/script execution in upload folders).",
            "Review web server access logs for any 200 OK responses to unusual file requests."
        ]
    },
    "network_scan": {
        "title": "Network Port Scan Detected",
        "what_happened": "A remote device systematically checked multiple network ports on your computer to discover which services or applications are open and listening.",
        "why_suspicious": "Port scanning is the preliminary reconnaissance phase adversaries use before launching targeted exploitation attempts.",
        "recommended_actions": [
            "Identify the source IP address. If it is unfamiliar, block it at your perimeter firewall.",
            "Close any open network ports and stop listening services that are not strictly necessary.",
            "Ensure host firewall (e.g., `ufw` or Windows Firewall) is active and drops unsolicited inbound packets."
        ]
    },
    "suspicious_command": {
        "title": "Suspicious Script or Command Execution",
        "what_happened": "A script or command interpreter (such as PowerShell or Bash) was executed with suspicious flags, encoded parameters, or abnormal privilege requests.",
        "why_suspicious": "Adversaries often use encoded commands or hidden shell scripts to bypass antivirus tools and download malicious payloads.",
        "recommended_actions": [
            "Inspect the exact command line executed and verify who initiated it.",
            "Check if any files were recently downloaded to temp folders (`/tmp` or `%TEMP%`).",
            "Run a comprehensive anti-malware scan on the host system."
        ]
    },
    "exploit_attempt": {
        "title": "Known Vulnerability / Exploit Attempt",
        "what_happened": "Inbound network traffic matching a known software exploit signature or CVE vulnerability was detected against a local service.",
        "why_suspicious": "An attacker is sending specially crafted data packets designed to take advantage of known bugs to gain remote control.",
        "recommended_actions": [
            "Immediately apply available security patches for the targeted service.",
            "Isolate the affected host from the rest of the internal network while verifying integrity.",
            "Inspect running processes to ensure no malicious shell or backdoor was established."
        ]
    },
    "sudo_command_execution": {
        "title": "Administrative Command Execution (Sudo)",
        "what_happened": "A local user account requested administrative (root/superuser) privileges to run a sensitive system command.",
        "why_suspicious": "Unauthorized administrative escalation can allow an attacker or unauthorized user to alter system files or install malware.",
        "recommended_actions": [
            "Verify whether the user account had legitimate reason to run administrative commands.",
            "Check `/var/log/auth.log` for any unexpected user logins around the same time.",
            "Audit the `sudoers` configuration to ensure only trusted users have administrative rights."
        ]
    },
    "file_integrity_change": {
        "title": "Critical System File Modified",
        "what_happened": "A system file, binary, or core configuration setting was modified or replaced.",
        "why_suspicious": "Malware and attackers often replace system files or binaries to establish persistence or hide their presence.",
        "recommended_actions": [
            "Confirm if a recent scheduled system update or package installation occurred.",
            "Compare the file's current cryptographic hash against known clean package repository hashes.",
            "Restore the file from a known-good backup if modification was unauthorized."
        ]
    }
}

DEFAULT_EXPLANATION = {
    "title": "Suspicious Security Event",
    "what_happened": "A security monitoring tool flagged anomalous activity matching a security rule or threat signature.",
    "why_suspicious": "The recorded pattern deviates from normal baseline device operations.",
    "recommended_actions": [
        "Review the source IP and target destination details.",
        "Verify if any authorized administrative maintenance was taking place at that time.",
        "Check system health and active connections."
    ]
}

def get_remediation_guidance(event_type: str, description: str = "") -> Dict[str, Any]:
    """Retrieve plain-language explanation and recommended defensive playbook."""
    target = f"{event_type.lower()} {description.lower()}"
    for key, val in EXPLANATION_TEMPLATES.items():
        if key in target:
            return val
    return DEFAULT_EXPLANATION
