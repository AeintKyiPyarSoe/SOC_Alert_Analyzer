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
    },
    "web_shell": {
        "title": "Web Shell Process Spawning (MITRE T1505.003)",
        "what_happened": "A web server process (such as w3wp.exe, nginx, or httpd) spawned an interactive system command shell (cmd.exe, powershell.exe, sh, or bash).",
        "why_suspicious": "Web servers should never launch interactive command interpreters during normal request handling. This behavior is a high-confidence indicator of an uploaded web backdoor (web shell) providing unauthorized interactive server access.",
        "recommended_actions": [
            "Immediately quarantine or isolate the web server from the internal production network.",
            "Identify the parent web server worker process ID and terminate the spawned shell process.",
            "Search the web document root (e.g., /var/www, C:\\inetpub\\wwwroot) for recently written or modified scripts (.php, .aspx, .jsp).",
            "Collect volatile memory and web server access logs to identify the attacker's source IP and exploited upload vulnerability."
        ]
    },
    "shadow_deletion": {
        "title": "Ransomware Defense Evasion / Backup Snapshot Purge (MITRE T1490)",
        "what_happened": "An executable or command line attempted to delete Windows Volume Shadow Copies using utility commands like 'vssadmin delete shadows' or 'wmic shadowcopy delete'.",
        "why_suspicious": "Ransomware payloads systematically delete local Volume Shadow Copies immediately prior to encrypting user files to prevent administrators from restoring data without paying a ransom.",
        "recommended_actions": [
            "CRITICAL: Isolate the endpoint from the corporate network immediately (disconnect ethernet/disable Wi-Fi) to stop lateral spread.",
            "Terminate the executing process and identify parent process lineage.",
            "Verify offline immutable backups are intact and secure.",
            "Check for newly created ransom notes or rapid file renaming across local drives and network shares."
        ]
    },
    "ransomware": {
        "title": "Ransomware Attack Indicators Detected (MITRE T1486 / T1490)",
        "what_happened": "Host behavioral heuristics detected destructive actions characteristic of ransomware, such as volume shadow snapshot purge or high-entropy file encryption bursts.",
        "why_suspicious": "Ransomware operators systematically inhibit system recovery and encrypt sensitive files to extort the organization.",
        "recommended_actions": [
            "Trigger emergency host network isolation immediately to protect neighboring servers.",
            "Terminate the anomalous process and examine parent command line trees.",
            "Verify the integrity of active backups and snapshots.",
            "Contact incident response lead and forensic team for triage."
        ]
    },
    "lolbin": {
        "title": "Living-Off-The-Land Binary / Obfuscated Execution (MITRE T1059.001)",
        "what_happened": "PowerShell or another native administrative tool was executed with hidden window flags (-w hidden), Base64 encoded payload (-enc), or a remote web download cradle.",
        "why_suspicious": "Adversaries abuse legitimate, pre-installed Windows system tools (LOLBins) with obfuscation techniques to bypass traditional antivirus scanners and execute scripts directly in memory.",
        "recommended_actions": [
            "Inspect PowerShell ScriptBlock logging (Event ID 4104) to review the deobfuscated command text.",
            "Identify the originating user account and parent process that launched the tool.",
            "Terminate any lingering background interpreter processes.",
            "Block the destination IP or domain referenced in the download cradle at your perimeter firewall."
        ]
    },
    "brute_force": {
        "title": "High-Volume Credential Guessing / Brute Force Attack (MITRE T1110)",
        "what_happened": "A concentrated burst of failed authentication attempts was detected against user accounts from a remote or local source within a 5-minute sliding window.",
        "why_suspicious": "Automated adversary tools and botnets systematically cycle through dictionaries of common passwords to compromise exposed service accounts.",
        "recommended_actions": [
            "Review the targeted username accounts and verify whether any subsequent logon attempt succeeded.",
            "Add the attacking source IP address to your network perimeter blocklist or local firewall drop rules.",
            "Enforce an automated account lockout threshold and mandate multi-factor authentication (MFA).",
            "Rotate passwords for all targeted user accounts immediately."
        ]
    },
    "port_probe": {
        "title": "Network Reconnaissance / Port Scan (MITRE T1046)",
        "what_happened": "A remote host systematically probed multiple TCP/UDP ports on this machine within a short timeframe.",
        "why_suspicious": "Adversaries conduct automated port sweeps using scanners (such as Nmap, Masscan, or ZGrab) to discover exposed services, unpatched software versions, and open network entry points.",
        "recommended_actions": [
            "Inspect your firewall configuration to ensure all unused ports are filtered or closed.",
            "Check whether the source IP belongs to an internal authorized vulnerability scanner.",
            "If the IP is external or unapproved, block the offending IP address in your firewall.",
            "Confirm that sensitive management interfaces (SSH, RDP, WinRM) are restricted to VPN access only."
        ]
    },
    "sql_injection": {
        "title": "Web Application SQL Injection Attack (MITRE T1190)",
        "what_happened": "An inbound HTTP request contained malicious database syntax (e.g. UNION SELECT, OR 1=1, or SQL comment markers) designed to manipulate backend database queries.",
        "why_suspicious": "SQL Injection vulnerabilities allow unauthenticated attackers to dump database records, extract credentials, bypass logins, and in some database configurations execute operating system commands.",
        "recommended_actions": [
            "Inspect web application logs to determine if the query resulted in a successful HTTP 200 response with leaked data or an HTTP 500 error.",
            "Apply parameterized queries (prepared statements) in application code to neutralize SQL string concatenation.",
            "Deploy or update Web Application Firewall (WAF) rule sets to block SQL injection patterns.",
            "Audit database user permissions to ensure the web application connects with least-privilege access."
        ]
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS) Attack (MITRE T1059.007)",
        "what_happened": "Inbound HTTP request parameters contained script tags (<script>) or JavaScript event handlers designed to execute code in victim browsers.",
        "why_suspicious": "XSS attacks enable adversaries to steal session cookies, hijack analyst accounts, and perform unauthorized actions on behalf of authenticated users.",
        "recommended_actions": [
            "Ensure input sanitization and context-aware HTML entity encoding are applied on all rendered parameters.",
            "Verify that the `HttpOnly` and `SameSite` flags are configured on all session cookies to prevent theft via JavaScript.",
            "Implement a strict Content Security Policy (CSP) header prohibiting inline script execution."
        ]
    },
    "path_traversal": {
        "title": "Directory Path Traversal / File Inclusion (MITRE T1083)",
        "what_happened": "An HTTP request attempted directory traversal sequences ('../' or '..\\') to navigate outside the web root and access restricted local system files.",
        "why_suspicious": "Attackers attempt path traversal to read configuration files, application source code, and operating system credentials (such as /etc/passwd or SAM databases).",
        "recommended_actions": [
            "Ensure all user-supplied file path inputs are strictly sanitized and validated against an allowed whitelist.",
            "Restrict web server file read permissions so it cannot access files outside its root directory.",
            "Review web server logs to verify whether the server returned file contents (HTTP 200) or rejected the attempt (HTTP 400/403/404)."
        ]
    }
}

DEFAULT_EXPLANATION = {
    "title": "Host Behavioral Anomaly",
    "what_happened": "A security monitoring sensor flagged anomalous activity matching a security detection rule or threat pattern.",
    "why_suspicious": "The recorded pattern deviates from normal baseline operating system behavior and warrants defensive analyst inspection.",
    "recommended_actions": [
        "Review the source IP and target destination details in the Evidence tab.",
        "Verify whether any authorized administrative maintenance or scheduled software update was taking place at that time.",
        "Inspect active process parent-child relationships and associated network sockets.",
        "If unrecognized, isolate the host system and preserve memory forensics."
    ]
}

def get_remediation_guidance(event_type: str, description: str = "") -> Dict[str, Any]:
    """Retrieve plain-language explanation and recommended defensive playbook with dynamic synthesis."""
    target = f"{event_type.lower()} {description.lower()}"
    for key, val in EXPLANATION_TEMPLATES.items():
        if key in target:
            return val

    # Dynamic contextual narrative synthesis when no static template matches
    clean_title = event_type.replace("_", " ").title() if event_type else "Security Anomaly"
    desc_clean = description.strip() if description else ""
    if desc_clean and desc_clean.lower() not in ("security event detected", "security event", "security anomaly", "event"):
        narrative = f"{desc_clean}. This activity was captured by defensive sensors and flagged as an operational anomaly."
    else:
        narrative = f"A host defensive sensor intercepted an anomalous {clean_title} event deviation matching detection criteria."

    return {
        "title": f"Investigate: {clean_title}",
        "what_happened": narrative,
        "why_suspicious": f"The recorded telemetry signature for '{clean_title}' deviates from the established baseline and indicates possible unauthorized behavior.",
        "recommended_actions": [
            "Inspect the involved process name, executable binary path, and parent-child process tree.",
            "Review the source IP and destination network connection in the Evidence tab.",
            "Verify whether this activity corresponds to authorized software updates or scheduled system administration.",
            "If unauthorized, isolate the endpoint from the network and review forensic log history."
        ]
    }

