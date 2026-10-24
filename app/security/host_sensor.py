import os
import sys
import time
import socket
import logging
import platform
import subprocess
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set

import psutil
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, func

from app.config import settings
from app.database.connection import SessionLocal
from app.models.alert import Alert
from app.models.incident import Incident
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator
from app.security.stream import stream_manager
from app.security.ip_utils import IPClassifier

logger = logging.getLogger(__name__)

class HostSecuritySensor:
    """
    Real-World Native Host Security Sensor & Behavioral EDR-Lite Monitor.
    Runs locally on the host computer (Windows / Linux / macOS) to collect
    live security telemetry, detect suspicious process behavior and parent-child
    execution anomalies, inspect network listeners, audit firewall posture,
    and correlate host events directly to MITRE ATT&CK techniques.
    """

    # Insecure or high-risk listening ports
    HIGH_RISK_PORTS = {
        21: ("FTP", "Unencrypted File Transfer Protocol service exposed"),
        23: ("Telnet", "Insecure unencrypted remote management Telnet exposed"),
        4444: ("Metasploit Default", "High-risk default Metasploit/Cobalt Strike listener port"),
        1337: ("Backdoor/Elite", "Known default hacker backdoor listening port"),
        5985: ("WinRM HTTP", "Windows Remote Management unencrypted HTTP listener"),
        3389: ("RDP", "Remote Desktop Protocol listener exposed on wildcard interface"),
        445: ("SMB", "Server Message Block exposed to external interface"),
        8080: ("HTTP Proxy/Dev", "Unauthenticated development web server listening on all interfaces"),
        6667: ("IRC", "IRC protocol port commonly associated with botnets")
    }

    # Offensive / Security tool binary names (word boundary / exact match)
    OFFENSIVE_BINARIES: Set[str] = {
        "mimikatz.exe", "mimikatz", "chisel.exe", "chisel", "nmap.exe", "nmap",
        "masscan.exe", "masscan", "hydra.exe", "hydra", "socat", "responder.py",
        "bloodhound.exe", "bloodhound", "hashcat.exe", "hashcat", "cain.exe", "cain",
        "psexec.exe", "psexec", "xmrig.exe", "xmrig"
    }

    # High-risk parent-child execution chains
    OFFICE_PARENTS: Set[str] = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    WEB_PARENTS: Set[str] = {"w3wp.exe", "nginx.exe", "nginx", "httpd.exe", "httpd", "apache2"}
    SCRIPT_CHILDREN: Set[str] = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "sh", "bash"}

    # LOLBin behavioral indicators
    RANSOMWARE_DEFENSE_EVASION = [
        "vssadmin delete shadows", "wmic shadowcopy delete", "wbadmin delete catalog"
    ]
    CREDENTIAL_DUMPING_PATTERNS = [
        "procdump -ma lsass", "comsvcs.dll minidump", "sekurlsa"
    ]
    DISCOVERY_BURST_COMMANDS = [
        "whoami /priv", "net localgroup administrators", "quser", "ipconfig /all"
    ]

    # Process masquerading targets
    SYSTEM32_NAMES: Set[str] = {"svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe"}

    # Configurable process suppressions (e.g. approved maintenance scripts, backup agents)
    PROCESS_SUPPRESSIONS: Set[str] = set()

    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalizes Windows device prefixes, slashes, and casing for consistent threat analysis."""
        if not path:
            return ""
        cleaned = re.sub(r"^\\\?\?\\|^\\\\?\\", "", path)
        return os.path.normcase(os.path.normpath(cleaned)).lower()

    def __init__(self):
        self.os_type = platform.system()  # 'Windows', 'Linux', 'Darwin'
        self.hostname = platform.node()
        self.seen_signatures: Dict[str, datetime] = {}
        self.last_log_poll_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        try:
            self.known_pids: Set[int] = set(psutil.pids())
        except Exception:
            self.known_pids = set()
        self.known_startup_files: Set[str] = self._get_startup_files()

    def _is_signature_seen_recent(self, sig: str, max_age_seconds: Optional[int] = None) -> bool:
        """
        Check if signature was seen within recent sliding window, automatically
        pruning stale entries to prevent unbounded memory growth and handle recurrences.
        """
        now = datetime.now(timezone.utc)
        window = max_age_seconds if max_age_seconds is not None else getattr(settings, "DEDUP_WINDOW_SECONDS", 300)

        # Periodic pruning if signature cache grows
        if len(self.seen_signatures) > 3000:
            cutoff = now - timedelta(seconds=window)
            self.seen_signatures = {k: v for k, v in self.seen_signatures.items() if v >= cutoff}

        last_seen = self.seen_signatures.get(sig)
        if last_seen and (now - last_seen).total_seconds() < window:
            return True

        self.seen_signatures[sig] = now
        return False

    def _get_startup_files(self) -> Set[str]:
        """Returns set of file paths currently in Windows Startup folders."""
        files = set()
        if self.os_type == "Windows":
            paths = []
            appdata = os.environ.get("APPDATA")
            if appdata:
                paths.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
            progdata = os.environ.get("PROGRAMDATA")
            if progdata:
                paths.append(os.path.join(progdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
            for p in paths:
                if os.path.exists(p):
                    try:
                        for entry in os.listdir(p):
                            files.add(os.path.join(p, entry).lower())
                    except Exception:
                        pass
        return files

    def audit_startup_folder(self) -> List[Dict[str, Any]]:
        """Detects new files dropped into Windows Startup folder (Persistence - MITRE T1547.001)."""
        events = []
        if self.os_type != "Windows":
            return events

        current = self._get_startup_files()
        new_files = current - self.known_startup_files
        self.known_startup_files = current

        for f in new_files:
            sig = f"startup_{f}"
            if not self._is_signature_seen_recent(sig):
                fname = os.path.basename(f)
                events.append({
                    "source_type": "Host_Security_Sensor",
                    "telemetry_origin": "HOST_TELEMETRY",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "persistence_startup_created",
                    "mitre_technique": "T1547.001",
                    "description": f"Persistence threat: New startup item added: '{fname}' in Windows Startup directory",
                    "source_ip": "127.0.0.1",
                    "destination_ip": None,
                    "raw_log": f"New startup item path: {f}"
                })
        return events

    def _analyze_single_process(self, p: psutil.Process) -> List[Dict[str, Any]]:
        """Applies behavioral detection heuristics to a running process instance."""
        events = []
        try:
            pid = p.pid
            create_time = 0
            try:
                create_time = int(p.create_time())
            except Exception:
                pass
            name = (p.name() or '').lower()
            exe = self.normalize_path(p.exe() or '')
            cmdline_list = p.cmdline() or []
            cmdline = " ".join(cmdline_list).lower()
            username = p.username()

            # Check process suppressions
            if name in self.PROCESS_SUPPRESSIONS or exe in self.PROCESS_SUPPRESSIONS:
                return []

            # Retrieve parent process information for tree analysis
            parent_name = ""
            try:
                parent = p.parent()
                if parent:
                    parent_name = (parent.name() or '').lower()
            except Exception:
                pass

            # 1. Behavioral: Malicious Parent-Child Chains
            if parent_name in self.WEB_PARENTS and name in self.SCRIPT_CHILDREN:
                sig = f"webshell_{parent_name}_{name}_{pid}_{create_time}"
                if not self._is_signature_seen_recent(sig):
                    events.append({
                        "source_type": "Host_Process_Sensor",
                        "telemetry_origin": "HOST_TELEMETRY",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "web_shell_probe",
                        "mitre_technique": "T1505.003",
                        "description": f"Web Shell Execution: Web server '{parent_name}' spawned command interpreter '{name}' (PID: {pid})",
                        "source_ip": "127.0.0.1",
                        "destination_ip": None,
                        "username": username,
                        "raw_log": f"Parent: {parent_name} | PID: {pid} | Exe: {exe} | Cmd: {cmdline}"
                    })

            if parent_name in self.OFFICE_PARENTS and name in self.SCRIPT_CHILDREN:
                sig = f"maldoc_{parent_name}_{name}_{pid}_{create_time}"
                if not self._is_signature_seen_recent(sig):
                    events.append({
                        "source_type": "Host_Process_Sensor",
                        "telemetry_origin": "HOST_TELEMETRY",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "windows_suspicious_process",
                        "mitre_technique": "T1204.002",
                        "description": f"Malicious Document Execution: Office application '{parent_name}' spawned script host '{name}' (PID: {pid})",
                        "source_ip": "127.0.0.1",
                        "destination_ip": None,
                        "username": username,
                        "raw_log": f"Parent: {parent_name} | PID: {pid} | Exe: {exe} | Cmd: {cmdline}"
                    })

            # 2. Exact match on known offensive security tools
            if name in self.OFFENSIVE_BINARIES:
                sig = f"tool_{name}_{pid}_{create_time}"
                if not self._is_signature_seen_recent(sig):
                    events.append({
                        "source_type": "Host_Process_Sensor",
                        "telemetry_origin": "HOST_TELEMETRY",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "suspicious_process",
                        "mitre_technique": "T1059",
                        "description": f"Known offensive security tool executed: '{name}' (PID: {pid}) from '{exe}'",
                        "source_ip": "127.0.0.1",
                        "destination_ip": None,
                        "username": username,
                        "raw_log": f"PID: {pid} | Exe: {exe} | Cmd: {cmdline}"
                    })

            # 3. Behavioral LOLBins: Weighted PowerShell & script indicator evaluation
            if "powershell" in name or "pwsh" in name:
                lolbin_weight = 0
                if any(enc in cmdline for enc in ["-enc", "-encodedcommand"]):
                    lolbin_weight += 3
                if any(byp in cmdline for byp in ["bypass", "unrestricted"]):
                    lolbin_weight += 2
                if any(hid in cmdline for hid in ["-w hidden", "windowstyle hidden", "-nop"]):
                    lolbin_weight += 2
                if any(cradle in cmdline for cradle in ["downloadstring", "downloadfile", "iex", "invoke-expression", "net.webclient"]):
                    lolbin_weight += 3

                if lolbin_weight >= 3:
                    sig = f"ps_behavioral_{pid}_{create_time}"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Process_Sensor",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "powershell_script_block",
                            "mitre_technique": "T1059.001",
                            "description": f"Suspicious PowerShell execution: encoded or hidden cradle payload in PID {pid}",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "username": username,
                            "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                        })

            # 4. Behavioral: Ransomware Shadow Copy Deletion (T1490)
            cleaned_cmd = cmdline.replace(".exe", "")
            for kw in self.RANSOMWARE_DEFENSE_EVASION:
                if kw in cleaned_cmd:
                    sig = f"ransom_cmd_{kw}_{pid}_{create_time}"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Process_Sensor",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "windows_log_cleared",
                            "mitre_technique": "T1490",
                            "description": f"Inhibit System Recovery: Attempt to purge backup/shadow copies: '{kw}' (PID: {pid})",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "username": username,
                            "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                        })

            # 5. Process Masquerading check
            if name in self.SYSTEM32_NAMES:
                if exe and "system32" not in exe and "syswow64" not in exe:
                    sig = f"masq_{name}_{pid}_{create_time}"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Process_Sensor",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "masqueraded_process",
                            "mitre_technique": "T1036.005",
                            "description": f"Process masquerading detected: System binary '{name}' running outside System32: '{exe}'",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "username": username,
                            "raw_log": f"PID: {pid} | Exe: {exe}"
                        })

            # 6. Executables running out of temporary writable directories
            if exe and any(tmp in exe for tmp in ["\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/dev/shm"]):  # nosec B108
                if not any(ign in name for ign in ["update", "installer", "setup", "edge", "chrome", "code"]):
                    sig = f"tmp_exe_{pid}_{create_time}"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Process_Sensor",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "suspicious_process",
                            "mitre_technique": "T1036",
                            "description": f"Executable executing from temporary folder: '{name}' (Path: '{exe}', PID: {pid})",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "username": username,
                            "raw_log": f"PID: {pid} | Exe: {exe}"
                        })

            # 7. Behavioral: Memory / Credential Dumping Commands (T1003)
            for cred_pattern in self.CREDENTIAL_DUMPING_PATTERNS:
                if cred_pattern in cleaned_cmd or cred_pattern in cmdline or ("procdump" in name and "-ma" in cmdline):
                    sig = f"cred_dump_{cred_pattern}_{pid}_{create_time}"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Process_Sensor",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "windows_suspicious_process",
                            "mitre_technique": "T1003",
                            "description": f"Credential Access: Memory dumping activity matching '{cred_pattern}' (PID: {pid})",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "username": username,
                            "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                        })

            # 8. LOLBins: Ingress Tool Transfer via certutil (T1105)
            if "certutil" in name and ("-urlcache" in cmdline or "-split" in cmdline):
                sig = f"certutil_download_{pid}_{create_time}"
                if not self._is_signature_seen_recent(sig):
                    events.append({
                        "source_type": "Host_Process_Sensor",
                        "telemetry_origin": "HOST_TELEMETRY",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "suspicious_command",
                        "mitre_technique": "T1105",
                        "description": f"Ingress Tool Transfer: certutil downloading remote payload (PID: {pid})",
                        "source_ip": "127.0.0.1",
                        "destination_ip": None,
                        "username": username,
                        "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                    })

            # 9. Defense Evasion: Impair Defenses via netsh firewall disable (T1562.001)
            if "netsh" in name and "advfirewall" in cmdline and "state off" in cmdline:
                sig = f"netsh_fw_off_{pid}_{create_time}"
                if not self._is_signature_seen_recent(sig):
                    events.append({
                        "source_type": "Host_Process_Sensor",
                        "telemetry_origin": "HOST_TELEMETRY",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "host_firewall_disabled",
                        "mitre_technique": "T1562.001",
                        "description": f"Impair Defenses: Disabling host firewall via netsh (PID: {pid})",
                        "source_ip": "127.0.0.1",
                        "destination_ip": None,
                        "username": username,
                        "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.debug(f"Error analyzing process: {e}")

        return events

    def audit_new_processes(self) -> List[Dict[str, Any]]:
        """Fast differential process check - only analyzes newly launched PIDs."""
        try:
            current_pids = set(psutil.pids())
        except Exception:
            return []

        new_pids = current_pids - self.known_pids
        self.known_pids = current_pids

        if not new_pids:
            return []

        events = []
        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                events.extend(self._analyze_single_process(p))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                pass
        return events

    def audit_processes(self) -> List[Dict[str, Any]]:
        """Scans all running host processes for behavioral indicators and execution paths."""
        events = []
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
            try:
                events.extend(self._analyze_single_process(p))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Error auditing process list: {e}")
        return events

    def get_host_info(self) -> Dict[str, Any]:
        """Returns hardware and OS posture of the current machine."""
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        
        local_ips = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        local_ips.append(a.address)
        except Exception:
            pass

        return {
            "os": f"{self.os_type} {platform.release()}",
            "hostname": self.hostname,
            "architecture": platform.machine(),
            "cpu_usage_percent": cpu,
            "memory_usage_percent": mem.percent,
            "local_ips": local_ips,
            "process_count": len(psutil.pids()),
            "monitoring_active": stream_manager.host_monitoring_active
        }

    def is_firewall_enabled(self) -> Optional[bool]:
        """Returns True if the host firewall is enabled, False if disabled, None if indeterminate."""
        if self.os_type == "Windows":
            try:
                res = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                output = res.stdout or ""
                if "State                                 OFF" in output:
                    return False
                if "State                                 ON" in output:
                    return True
            except Exception:
                pass
        elif self.os_type == "Linux":
            try:
                res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=2)
                out = (res.stdout or "").lower()
                if "status: active" in out:
                    return True
                if "status: inactive" in out:
                    return False
            except Exception:
                pass
        return None

    def inspect_port_firewall_rule(self, port: int, protocol: str = "TCP") -> Dict[str, Any]:
        """
        Inspects specific local host firewall rules for the designated port and protocol.
        Returns rule_status ("FILTERED_RULE_FOUND", "ALLOW_RULE_FOUND", "UNKNOWN") and confidence.
        Passive check; falls back safely to UNKNOWN if permissions are insufficient.
        """
        if self.os_type == "Windows":
            try:
                res = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                output = res.stdout or ""
                port_str = str(port)
                if re.search(rf"LocalPort:\s*([0-9,\-\s]*\b{port_str}\b)", output, re.IGNORECASE):
                    return {"rule_status": "FILTERED_RULE_FOUND", "confidence": "HIGH", "detail": f"Firewall rule detected matching port {port}."}
            except Exception:
                pass
        elif self.os_type == "Linux":
            try:
                res = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=2)
                out = res.stdout or ""
                if f":{port} " in out or f"dpt:{port}" in out:
                    return {"rule_status": "FILTERED_RULE_FOUND", "confidence": "HIGH", "detail": f"iptables rule detected for port {port}."}
            except Exception:
                pass

        return {"rule_status": "UNKNOWN", "confidence": "LOW", "detail": "Specific firewall rule not found or indeterminate; relying on global firewall posture."}

    def assess_socket_reachability(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Distinguishes listening socket binding from confirmed network reachability.
        Evaluates interface assignments, routability, and firewall posture passively.
        Never executes active external network scans.
        """
        ip_clean = (ip or "").strip()
        is_loopback = ip_clean in ("127.0.0.1", "::1", "localhost")
        is_wildcard = ip_clean in ("0.0.0.0", "::", "")  # nosec B104

        # Discover active, UP host network interfaces
        active_interfaces: List[str] = []
        has_public_ip = False
        has_lan_ip = False

        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                iface_stat = stats.get(iface)
                if iface_stat and not iface_stat.isup:
                    continue
                for a in addr_list:
                    if a.family in (socket.AF_INET, getattr(socket, "AF_INET6", -1)):
                        addr_str = str(a.address).split("%")[0]
                        if not addr_str.startswith("127.") and addr_str not in ("::1", "localhost"):
                            active_interfaces.append(addr_str)
                            if IPClassifier.is_public_ip(addr_str):
                                has_public_ip = True
                            else:
                                has_lan_ip = True
        except Exception:
            pass

        # Inspect firewall posture & specific rule status
        fw_active = self.is_firewall_enabled()
        rule_info = self.inspect_port_firewall_rule(port)
        fw_rule_status = rule_info.get("rule_status", "UNKNOWN")

        if fw_active is False:
            fw_mitigation = "UNFILTERED_EXPOSED"
            fw_confidence = "HIGH"
        elif fw_active is True:
            if fw_rule_status == "FILTERED_RULE_FOUND":
                fw_mitigation = "FILTERED"
                fw_confidence = "HIGH"
            else:
                fw_mitigation = "FILTERED"  # Default global inbound filtering policy
                fw_confidence = "MEDIUM"
        else:
            fw_mitigation = "UNKNOWN"
            fw_confidence = "LOW"

        reachability_type = "INFERRED_PASSIVE"
        defensive_rec = f"Audit listening process and restrict binding to loopback (127.0.0.1) if network access is not required."

        if is_loopback:
            reachability = "LOOPBACK_ONLY"
            exposure_tier = "LOW"
            confidence = "HIGH"
            summary = f"Socket bound strictly to loopback ({ip_clean}:{port}). Inaccessible to external or local network hosts."
            defensive_rec = "No network action required; socket is isolated to local host."
        elif is_wildcard:
            if has_public_ip:
                reachability = "INTERNET_EXPOSED"
                exposure_tier = "CRITICAL" if fw_mitigation != "FILTERED" else "HIGH"
                confidence = "MEDIUM"
                summary = f"Socket bound to wildcard ({ip_clean}:{port}) with potential public interface exposure ({active_interfaces}). Inferred reachability (passive); Firewall: {fw_mitigation}."
                defensive_rec = f"Verify whether port {port} must be exposed. Apply perimeter/host firewall block rules or bind strictly to a private management interface."
            elif has_lan_ip:
                reachability = "LAN_ACCESSIBLE"
                exposure_tier = "HIGH" if fw_mitigation != "FILTERED" else "MEDIUM"
                confidence = "HIGH" if fw_confidence != "LOW" else "MEDIUM"
                summary = f"Socket bound to wildcard ({ip_clean}:{port}) accessible to local subnet via {active_interfaces}. Firewall: {fw_mitigation}."
                defensive_rec = f"Restrict port {port} access to authorized administrative subnets via local firewall rule."
            else:
                reachability = "HOST_ISOLATED"
                exposure_tier = "LOW"
                confidence = "HIGH"
                summary = f"Socket bound to wildcard ({ip_clean}:{port}) but no active non-loopback network interfaces detected."
                defensive_rec = "No immediate network risk detected; host has no active network adapters."
        else:
            if IPClassifier.is_public_ip(ip_clean):
                reachability = "INTERNET_EXPOSED"
                exposure_tier = "CRITICAL" if fw_mitigation != "FILTERED" else "HIGH"
                confidence = "MEDIUM"
                summary = f"Socket bound directly to public IP ({ip_clean}:{port}). Potential internet-routable reachability (passive assessment). Firewall: {fw_mitigation}."
                defensive_rec = f"Ensure perimeter firewalls and local rules explicitly restrict port {port} to authorized source IPs."
            elif not is_loopback:
                reachability = "LAN_ACCESSIBLE"
                exposure_tier = "HIGH" if fw_mitigation != "FILTERED" else "MEDIUM"
                confidence = "HIGH" if fw_confidence != "LOW" else "MEDIUM"
                summary = f"Socket bound to local subnet IP ({ip_clean}:{port}). Reachable within private LAN. Firewall: {fw_mitigation}."
                defensive_rec = f"Ensure port {port} traffic is restricted to trusted internal workstations."
            else:
                reachability = "LOOPBACK_ONLY"
                exposure_tier = "LOW"
                confidence = "HIGH"
                summary = f"Socket bound to {ip_clean}:{port} (Loopback only)."

        if port == 445:
            defensive_rec = "SMB port 445 exposure posture: restrict to dedicated domain controller / file server roles; block TCP 445 at perimeter and inter-subnet firewalls to prevent lateral movement (T1021.002)."

        return {
            "binding": ip_clean or "0.0.0.0",  # nosec B104
            "port": port,
            "binding_type": "LOOPBACK" if is_loopback else ("WILDCARD" if is_wildcard else "SPECIFIC_INTERFACE"),
            "reachability": reachability,
            "reachability_type": reachability_type,
            "exposure_tier": exposure_tier,
            "confidence": confidence,
            "firewall_mitigation": fw_mitigation,
            "firewall_rule_status": fw_rule_status,
            "active_interfaces": active_interfaces,
            "has_public_reachability": (reachability == "INTERNET_EXPOSED"),
            "defensive_recommendation": defensive_rec,
            "summary": summary
        }

    def audit_network_sockets(self) -> List[Dict[str, Any]]:
        """Audits host network sockets for exposed high-risk listening ports and suspicious outbound connections."""
        events = []
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception as e:
            logger.debug(f"Could not retrieve network connections: {e}")
            return events

        for conn in connections:
            try:
                if conn.status == "LISTEN":
                    laddr = conn.laddr
                    port = laddr.port
                    ip = laddr.ip

                    if ip in ("0.0.0.0", "::", "") and port in self.HIGH_RISK_PORTS:  # nosec B104
                        service_name, reason = self.HIGH_RISK_PORTS[port]

                        proc_name = "Unknown"
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except Exception:
                                proc_name = "Unknown (Inaccessible)"
                        else:
                            proc_name = "System / Inaccessible"

                        # Context filter: Allowlist developer runtime processes listening on dev ports
                        proc_lower = proc_name.lower()
                        if port in (8080, 8000) and any(d in proc_lower for d in ["python", "uvicorn", "code", "node"]):
                            continue

                        reach = self.assess_socket_reachability(ip, port)

                        sig = f"listen_{port}_{conn.pid}"
                        if not self._is_signature_seen_recent(sig):
                            reach_reach = reach.get("reachability", "UNKNOWN")
                            reach_tier = reach.get("exposure_tier", "LOW")
                            reach_fw = reach.get("firewall_mitigation", "UNKNOWN")
                            reach_conf = reach.get("confidence", "MEDIUM")
                            reach_type = reach.get("reachability_type", "INFERRED_PASSIVE")
                            reach_rec = reach.get("defensive_recommendation", "Audit socket exposure and bind to localhost if external access is not required.")
                            reach_summary = reach.get("summary", "")

                            events.append({
                                "source_type": "Host_Network_Sensor",
                                "telemetry_origin": "HOST_TELEMETRY",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "insecure_listening_port",
                                "mitre_technique": None,  # Passive posture finding; not adversary discovery
                                "description": f"Host Listener Posture: {service_name} on {ip}:{port} [{reach_reach}] (Exposure: {reach_tier}, FW: {reach_fw}, Conf: {reach_conf}) by process '{proc_name}' (PID: {conn.pid})",
                                "source_ip": "0.0.0.0",  # nosec: B104
                                "destination_ip": None,
                                "source_port": port,
                                "destination_port": None,
                                "username": None,
                                "reachability": reach_reach,
                                "reachability_type": reach_type,
                                "exposure_tier": reach_tier,
                                "confidence": reach_conf,
                                "firewall_mitigation": reach_fw,
                                "defensive_recommendation": reach_rec,
                                "raw_log": f"Status: LISTEN | LocalAddr: {ip}:{port} | Process: {proc_name} (PID {conn.pid}) | Reachability: {reach_reach} | ReachabilityType: {reach_type} | Exposure: {reach_tier} | FW: {reach_fw} | Confidence: {reach_conf} | Detail: {reach_summary} | Reason: {reason} | Guidance: {reach_rec}"
                            })

                elif conn.status == "ESTABLISHED" and conn.raddr:
                    r_ip = conn.raddr.ip
                    r_port = conn.raddr.port

                    # Evaluate remote IP using IPClassifier: only flag true public remote connections
                    if IPClassifier.is_public_ip(r_ip):
                        if r_port in (4444, 1337, 6667, 9001, 8888):
                            sig = f"outbound_{r_ip}_{r_port}_{conn.pid}"
                            if not self._is_signature_seen_recent(sig):
                                proc_name = "Unknown"
                                if conn.pid:
                                    try:
                                        proc_name = psutil.Process(conn.pid).name()
                                    except Exception:
                                        pass
                                events.append({
                                    "source_type": "Host_Network_Sensor",
                                    "telemetry_origin": "HOST_TELEMETRY",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "event_type": "suspicious_outbound_connection",
                                    "mitre_technique": "T1071",
                                    "description": f"Suspicious outbound connection to external IP {r_ip}:{r_port} from process '{proc_name}' (PID: {conn.pid})",
                                    "source_ip": "127.0.0.1",
                                    "destination_ip": r_ip,
                                    "source_port": conn.laddr.port,
                                    "destination_port": r_port,
                                    "username": None,
                                    "raw_log": f"Status: ESTABLISHED | Remote: {r_ip}:{r_port} | Process: {proc_name}"
                                })

            except Exception as e:
                logger.debug(f"Error checking connection: {e}")

        return events

    def audit_firewall_posture(self) -> List[Dict[str, Any]]:
        """Audits host firewall status on Windows or Linux."""
        events = []
        if self.os_type == "Windows":
            try:
                res = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    capture_output=True,
                    text=True,
                    timeout=4
                )
                output = res.stdout or ""
                if "State                                 OFF" in output:
                    sig = "win_firewall_off"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Security_Posture",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "host_firewall_disabled",
                            "mitre_technique": "T1562.004",
                            "description": "Windows Defender Firewall is disabled on one or more profiles, exposing device network ports.",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "raw_log": output[:300]
                        })
            except Exception as e:
                logger.debug(f"Firewall check failed: {e}")

        elif self.os_type == "Linux":
            try:
                res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
                if "inactive" in (res.stdout or "").lower():
                    sig = "linux_ufw_inactive"
                    if not self._is_signature_seen_recent(sig):
                        events.append({
                            "source_type": "Host_Security_Posture",
                            "telemetry_origin": "HOST_TELEMETRY",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "host_firewall_disabled",
                            "mitre_technique": "T1562.004",
                            "description": "Linux UFW firewall is currently inactive.",
                            "source_ip": "127.0.0.1",
                            "destination_ip": None,
                            "raw_log": res.stdout
                        })
            except Exception:
                pass

        return events

    def audit_event_logs(self) -> List[Dict[str, Any]]:
        """Queries recent Windows System/Application logs for critical security events."""
        events = []
        if self.os_type != "Windows":
            return events

        try:
            ps_cmd = (
                "$cutoff = (Get-Date).AddMinutes(-15); "
                "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff; Id=7045,104} -MaxEvents 5 -ErrorAction SilentlyContinue | "
                "Select-Object Id, TimeCreated, Message | ConvertTo-Json"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            out = res.stdout.strip()
            if out and (out.startswith("{") or out.startswith("[")):
                from app.parsers.windows_event import WindowsEventParser
                parser = WindowsEventParser()
                parsed = parser.parse(out)
                for ev in parsed:
                    sig = f"winevent_{ev.get('event_id')}_{ev.get('timestamp')}"
                    if not self._is_signature_seen_recent(sig):
                        ev["telemetry_origin"] = "HOST_TELEMETRY"
                        events.append(ev)
        except Exception as e:
            logger.debug(f"Event log check failed: {e}")

        return events

    def _ingest_events(self, raw_events: List[Dict[str, Any]], db: Session, check_active: bool = False) -> List[Alert]:
        """Deduplicates, normalizes, persists security alerts, and triggers correlation."""
        created_alerts = []
        for raw in raw_events:
            normalized = AlertNormalizer.normalize(raw)
            ev_ts = normalized["timestamp"]
            if ev_ts.tzinfo is None:
                ev_ts = ev_ts.replace(tzinfo=timezone.utc)

            # Deduplicate: if an identical OPEN alert already exists within the sliding time window, update recurrence tracking
            dedup_window = getattr(settings, "DEDUP_WINDOW_SECONDS", 300)
            window_start = ev_ts - timedelta(seconds=dedup_window)
            window_end = ev_ts + timedelta(seconds=dedup_window)
            origin = normalized.get("telemetry_origin") or "HOST_TELEMETRY"
            origin_filter = (
                or_(Alert.telemetry_origin == origin, Alert.telemetry_origin.is_(None))
                if origin == "HISTORICAL_LOG"
                else (Alert.telemetry_origin == origin)
            )
            existing = db.query(Alert).filter(
                origin_filter,
                Alert.event_type == normalized["event_type"],
                Alert.description == normalized["description"],
                Alert.source_type == normalized["source_type"],
                Alert.source_ip == normalized.get("source_ip"),
                Alert.destination_ip == normalized.get("destination_ip"),
                Alert.username == normalized.get("username"),
                Alert.status == "OPEN",
                or_(
                    Alert.last_seen >= window_start,
                    and_(Alert.last_seen.is_(None), Alert.timestamp >= window_start)
                ),
                or_(
                    Alert.first_seen <= window_end,
                    and_(Alert.first_seen.is_(None), Alert.timestamp <= window_end)
                )
            ).order_by(
                desc(func.coalesce(Alert.last_seen, Alert.timestamp))
            ).first()
            if existing:
                existing.occurrence_count = (existing.occurrence_count or 1) + 1
                curr_first = existing.first_seen or existing.timestamp or ev_ts
                if curr_first.tzinfo is None:
                    curr_first = curr_first.replace(tzinfo=timezone.utc)
                curr_last = existing.last_seen or existing.timestamp or ev_ts
                if curr_last.tzinfo is None:
                    curr_last = curr_last.replace(tzinfo=timezone.utc)
                existing.first_seen = min(curr_first, ev_ts)
                existing.last_seen = max(curr_last, ev_ts)
                db.flush()
                continue

            alert = Alert(
                id=uuid.uuid4(),
                timestamp=normalized["timestamp"],
                is_valid_timestamp=normalized.get("is_valid_timestamp", True),
                source_type=normalized["source_type"],
                telemetry_origin=normalized.get("telemetry_origin", "HOST_TELEMETRY"),
                event_type=normalized["event_type"],
                description=normalized["description"],
                source_ip=normalized["source_ip"],
                destination_ip=normalized["destination_ip"],
                source_port=normalized["source_port"],
                destination_port=normalized["destination_port"],
                username=normalized["username"],
                severity=normalized["severity"],
                risk_score=normalized["risk_score"],
                mitre_technique=normalized["mitre_technique"],
                status="OPEN",
                raw_log=normalized.get("raw_log"),
                occurrence_count=1,
                first_seen=normalized["timestamp"],
                last_seen=normalized["timestamp"]
            )
            db.add(alert)
            db.flush()
            created_alerts.append(alert)

        if check_active:
            from app.security.stream import stream_manager
            if not stream_manager.host_monitoring_active:
                logger.info("Host monitoring was paused during audit; discarding in-flight findings and rolling back.")
                db.rollback()
                return []

        if created_alerts:
            db.commit()
            IncidentCorrelator.correlate_alerts(db)
        elif raw_events:
            db.commit()

        return created_alerts

    def run_fast_audit(self, db: Session, check_active: bool = False) -> List[Alert]:
        """Runs fast, sub-second differential checks on new processes, active sockets, and startup folder."""
        raw_events = []
        raw_events.extend(self.audit_new_processes())
        raw_events.extend(self.audit_network_sockets())
        raw_events.extend(self.audit_startup_folder())
        return self._ingest_events(raw_events, db, check_active=check_active)

    def run_full_audit(self, db: Session, check_active: bool = False) -> List[Alert]:
        """Runs all live host security audits, normalizes findings, commits to DB, and correlates."""
        raw_events = []
        raw_events.extend(self.audit_processes())
        raw_events.extend(self.audit_network_sockets())
        raw_events.extend(self.audit_startup_folder())
        raw_events.extend(self.audit_firewall_posture())
        raw_events.extend(self.audit_event_logs())
        return self._ingest_events(raw_events, db, check_active=check_active)

    def run_test_drill(self, db: Session) -> Dict[str, Any]:
        """
        Executes a controlled evaluation drill for testing alert pipelines and triage playbooks.
        Clearly marked as a [TEST DRILL] with telemetry_origin='SECURITY_DRILL'.
        """
        drill_scenarios = [
            {
                "source_type": "Host_Security_Sensor",
                "telemetry_origin": "SECURITY_DRILL",
                "event_type": "insecure_listening_port",
                "mitre_technique": "T1046",
                "description": "[TEST DRILL] Open Insecure Port: Test listener opened on 0.0.0.0:4444 (Simulated Remote Handler)",
                # Drill event mock address
                "source_ip": "0.0.0.0",  # nosec: B104
                "destination_ip": "127.0.0.1",
                "source_port": 4444,
                "destination_port": None,
                "username": "tester",
                "raw_log": "DRILL EVENT: Manual SOC evaluation trigger for port exposure validation."
            },
            {
                "source_type": "Host_Process_Sensor",
                "telemetry_origin": "SECURITY_DRILL",
                "event_type": "suspicious_command",
                "mitre_technique": "T1059.001",
                "description": "[TEST DRILL] LOLBin Execution: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA (Base64 drill script)",
                "source_ip": "127.0.0.1",
                "destination_ip": None,
                "source_port": None,
                "destination_port": None,
                "username": "tester",
                "raw_log": "DRILL EVENT: Manual SOC evaluation trigger for encoded command execution."
            },
            {
                "source_type": "Windows_Event",
                "telemetry_origin": "SECURITY_DRILL",
                "event_type": "windows_failed_logon",
                "mitre_technique": "T1110",
                "description": "[TEST DRILL] Event ID 4625: Repeated failed logons for user 'admin' from 192.168.1.180",
                "source_ip": "192.168.1.180",
                "destination_ip": "127.0.0.1",
                "source_port": 58921,
                "destination_port": 3389,
                "username": "admin",
                "raw_log": "DRILL EVENT: Simulated Windows brute force logon attempt."
            }
        ]

        import random
        chosen = random.choice(drill_scenarios).copy()
        chosen["timestamp"] = datetime.now(timezone.utc).isoformat()

        norm = AlertNormalizer.normalize(chosen)
        alert = Alert(id=uuid.uuid4(), occurrence_count=1, first_seen=norm["timestamp"], last_seen=norm["timestamp"], **norm)
        db.add(alert)
        db.commit()

        incidents = IncidentCorrelator.correlate_alerts(db)

        return {
            "status": "success",
            "message": f"Generated security test drill: {alert.description}",
            "alert": {
                "id": str(alert.id),
                "event_type": alert.event_type,
                "description": alert.description,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "telemetry_origin": alert.telemetry_origin
            },
            "incidents_created": len(incidents)
        }

# Global Singleton Sensor
host_sensor = HostSecuritySensor()

async def real_host_monitor_loop():
    """
    Continuous background loop that monitors the host system for live security anomalies in real time.
    Differential scans occur every 2.0 seconds, catching newly launched malicious processes or ports instantly.
    Full comprehensive audits run every 10 ticks (~20 seconds) alongside periodic telemetry heartbeats.
    """
    logger.info("Real Host Security Sensor real-time monitoring loop started (2.0s tick).")
    import asyncio
    from sqlalchemy import func

    # Initial short delay for app startup
    await asyncio.sleep(2)

    tick = 0
    initial_full_done = False

    while True:
        try:
            if stream_manager.host_monitoring_active:
                db = SessionLocal()
                try:
                    if not initial_full_done or (tick % 10 == 0):
                        new_alerts = host_sensor.run_full_audit(db, check_active=True)
                        initial_full_done = True
                    else:
                        new_alerts = host_sensor.run_fast_audit(db, check_active=True)

                    if not stream_manager.host_monitoring_active:
                        logger.info("Host monitoring was paused during audit cycle; discarding in-flight alerts.")
                        db.rollback()
                        new_alerts = []
                    elif new_alerts:
                        new_incidents = IncidentCorrelator.correlate_alerts(db)

                        # Efficient SQL-level KPI aggregation
                        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
                        total_incidents = db.query(func.count(Incident.id)).scalar() or 0

                        sev_counts = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
                        status_counts = dict(db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())

                        stats = {
                            "total_alerts": total_alerts,
                            "critical_count": sev_counts.get("CRITICAL", 0),
                            "high_count": sev_counts.get("HIGH", 0),
                            "medium_count": sev_counts.get("MEDIUM", 0),
                            "low_count": sev_counts.get("LOW", 0),
                            "open_count": status_counts.get("OPEN", 0),
                            "investigating_count": status_counts.get("INVESTIGATING", 0),
                            "resolved_count": status_counts.get("RESOLVED", 0),
                            "total_incidents": total_incidents
                        }

                        # Broadcast each detected alert over WebSocket
                        for alert in new_alerts:
                            ts_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(alert.timestamp, datetime) else str(alert.timestamp)
                            payload = {
                                "type": "LIVE_THREAT",
                                "origin": alert.telemetry_origin,
                                "alert": {
                                    "id": str(alert.id),
                                    "timestamp": ts_str,
                                    "severity": alert.severity,
                                    "risk_score": alert.risk_score,
                                    "event_type": alert.event_type,
                                    "description": alert.description,
                                    "source_type": alert.source_type,
                                    "telemetry_origin": alert.telemetry_origin,
                                    "source_ip": alert.source_ip,
                                    "destination_ip": alert.destination_ip,
                                    "mitre_technique": alert.mitre_technique,
                                    "status": alert.status
                                },
                                "stats": stats,
                                "new_incidents": [
                                    {
                                        "id": str(i.id),
                                        "title": i.title,
                                        "description": i.description,
                                        "risk_score": i.risk_score,
                                        "alert_count": i.alert_count,
                                        "mitre_technique": i.mitre_technique,
                                        "status": i.status
                                    } for i in new_incidents
                                ]
                            }
                            await stream_manager.broadcast(payload)
                            logger.info(f"Broadcasted REAL host security alert: {alert.description}")

                    # Periodic telemetry heartbeat every 5 ticks (~10s)
                    elif tick % 5 == 0 and stream_manager.active_connections:
                        host_info = host_sensor.get_host_info()
                        host_info["monitoring_active"] = stream_manager.host_monitoring_active
                        host_info["simulation_active"] = stream_manager.simulation_active
                        await stream_manager.broadcast({
                            "type": "HEARTBEAT",
                            "origin": "HOST_TELEMETRY",
                            "is_sensitive": True,
                            "host_info": host_info
                        })
                finally:
                    db.close()
            tick += 1
        except asyncio.CancelledError:
            logger.info("Host monitor background loop cancelled cleanly.")
            break
        except Exception as e:
            logger.error(f"Error in host monitor loop: {e}", exc_info=True)

        await asyncio.sleep(2.0)
