import os
import sys
import time
import socket
import logging
import platform
import subprocess
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set

import psutil
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.models.alert import Alert
from app.models.incident import Incident
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator
from app.security.stream import stream_manager

logger = logging.getLogger(__name__)

class HostSecuritySensor:
    """
    Real-World Native Host Security Sensor & Monitor.
    Runs locally on the host computer (Windows / Linux / macOS) to collect
    live security telemetry, detect suspicious processes, analyze network listeners,
    audit firewall posture, and read host OS event logs without needing Wazuh or Suricata.
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

    # Offensive / Hacking tool signatures
    OFFENSIVE_TOOLS = [
        "mimikatz", "chisel", "nmap", "masscan", "hydra", "socat",
        "responder", "bloodhound", "hashcat", "cain", "psexec"
    ]

    # LOLBins suspicious arguments
    SUSPICIOUS_CMD_KEYWORDS = [
        "-enc", "-encodedcommand", "downloadstring", "iex (", "iex(",
        "bypass -noprofile", "windowstyle hidden", "-w hidden",
        "vssadmin delete shadows", "certutil -urlcache", "certutil.exe -urlcache",
        "bitsadmin /transfer", "whoami /priv", "net localgroup administrators"
    ]

    # Process masquerading targets
    SYSTEM32_NAMES = ["svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe"]

    def __init__(self):
        self.os_type = platform.system()  # 'Windows', 'Linux', 'Darwin'
        self.hostname = platform.node()
        self.seen_signatures: Set[str] = set()
        self.last_log_poll_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        try:
            self.known_pids: Set[int] = set(psutil.pids())
        except Exception:
            self.known_pids = set()
        self.known_startup_files: Set[str] = self._get_startup_files()

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
        """Detects new files dropped into Windows Startup folder (Persistence)."""
        events = []
        if self.os_type != "Windows":
            return events

        current = self._get_startup_files()
        new_files = current - self.known_startup_files
        self.known_startup_files = current

        for f in new_files:
            sig = f"startup_{f}"
            if sig not in self.seen_signatures:
                self.seen_signatures.add(sig)
                fname = os.path.basename(f)
                events.append({
                    "source_type": "Host_Security_Sensor",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "persistence_startup_created",
                    "description": f"Persistence threat: New startup item added: '{fname}' in Windows Startup directory",
                    "source_ip": "127.0.0.1",
                    "destination_ip": None,
                    "raw_log": f"New startup item path: {f}"
                })
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
                name = (p.name() or '').lower()
                exe = (p.exe() or '').lower()
                cmdline_list = p.cmdline() or []
                cmdline = " ".join(cmdline_list).lower()
                username = p.username()

                # 1. Offensive tools
                for tool in self.OFFENSIVE_TOOLS:
                    if tool in name or tool in exe:
                        sig = f"tool_{tool}_{pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)
                            events.append({
                                "source_type": "Host_Process_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "suspicious_process",
                                "description": f"Offensive security tool launched: '{name}' (PID: {pid}) from '{exe}'",
                                "source_ip": "127.0.0.1",
                                "destination_ip": None,
                                "username": username,
                                "raw_log": f"PID: {pid} | Exe: {exe} | Cmd: {cmdline}"
                            })

                # 2. Suspicious LOLBin command line flags
                for kw in self.SUSPICIOUS_CMD_KEYWORDS:
                    if kw in cmdline:
                        sig = f"cmd_{kw}_{pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)
                            events.append({
                                "source_type": "Host_Process_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "suspicious_command",
                                "description": f"Suspicious command line execution in '{name}' (PID: {pid}): contains '{kw}'",
                                "source_ip": "127.0.0.1",
                                "destination_ip": None,
                                "username": username,
                                "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                            })

                # 3. Masquerading
                if self.os_type == "Windows":
                    for sys_name in self.SYSTEM32_NAMES:
                        if name == sys_name and exe:
                            if "system32" not in exe and "syswow64" not in exe:
                                sig = f"masq_{name}_{pid}"
                                if sig not in self.seen_signatures:
                                    self.seen_signatures.add(sig)
                                    events.append({
                                        "source_type": "Host_Process_Sensor",
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "event_type": "masqueraded_process",
                                        "description": f"Process masquerading detected: Critical system process '{name}' executing outside System32: '{exe}'",
                                        "source_ip": "127.0.0.1",
                                        "destination_ip": None,
                                        "username": username,
                                        "raw_log": f"PID: {pid} | Exe: {exe}"
                                    })

                # 4. Running out of temp
                if exe and any(tmp in exe for tmp in ["\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/dev/shm"]):
                    if not any(ign in name for ign in ["update", "installer", "setup", "edge", "chrome"]):
                        sig = f"tmp_exe_{pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)
                            events.append({
                                "source_type": "Host_Process_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "suspicious_process",
                                "description": f"Executable executing from temporary directory: '{name}' (Path: '{exe}', PID: {pid})",
                                "source_ip": "127.0.0.1",
                                "destination_ip": None,
                                "username": username,
                                "raw_log": f"PID: {pid} | Exe: {exe}"
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                pass
        return events

    def get_host_info(self) -> Dict[str, Any]:
        """Returns hardware and OS posture of the current machine."""
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        
        # Determine local IPs
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
            "monitoring_active": stream_manager.simulation_active
        }

    def audit_processes(self) -> List[Dict[str, Any]]:
        """Scans running host processes for anomalous execution paths and command lines."""
        events = []
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent']):
            try:
                info = p.info
                name = (info.get('name') or '').lower()
                exe = (info.get('exe') or '').lower()
                cmdline_list = info.get('cmdline') or []
                cmdline = " ".join(cmdline_list).lower()
                pid = info.get('pid')
                username = info.get('username')

                # 1. Check known offensive tools
                for tool in self.OFFENSIVE_TOOLS:
                    if tool in name or tool in exe:
                        sig = f"tool_{tool}_{pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)
                            events.append({
                                "source_type": "Host_Process_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "suspicious_process",
                                "description": f"Known offensive security / penetration testing tool '{tool}' running as process '{name}' (PID: {pid})",
                                "source_ip": "127.0.0.1",
                                "destination_ip": None,
                                "source_port": None,
                                "destination_port": None,
                                "username": username,
                                "raw_log": f"PID: {pid} | Exe: {exe} | Cmd: {cmdline}"
                            })

                # 2. Check suspicious command lines (LOLBins / Encoded PowerShell)
                for kw in self.SUSPICIOUS_CMD_KEYWORDS:
                    if kw in cmdline:
                        sig = f"cmd_{kw}_{pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)
                            events.append({
                                "source_type": "Host_Process_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "suspicious_command",
                                "description": f"Suspicious command line execution detected in '{name}' (PID: {pid}): flag '{kw}'",
                                "source_ip": "127.0.0.1",
                                "destination_ip": None,
                                "source_port": None,
                                "destination_port": None,
                                "username": username,
                                "raw_log": f"PID: {pid} | Cmd: {cmdline}"
                            })

                # 3. Process Masquerading check
                if self.os_type == "Windows":
                    for sys_name in self.SYSTEM32_NAMES:
                        if name == sys_name and exe:
                            if "system32" not in exe and "syswow64" not in exe:
                                sig = f"masq_{name}_{pid}"
                                if sig not in self.seen_signatures:
                                    self.seen_signatures.add(sig)
                                    events.append({
                                        "source_type": "Host_Process_Sensor",
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "event_type": "masqueraded_process",
                                        "description": f"Process masquerading detected: Critical system process '{name}' executing from unauthorized path: '{exe}'",
                                        "source_ip": "127.0.0.1",
                                        "destination_ip": None,
                                        "source_port": None,
                                        "destination_port": None,
                                        "username": username,
                                        "raw_log": f"PID: {pid} | Exe: {exe}"
                                    })

                # 4. Executables running directly from Temp directories
                if exe and any(tmp in exe for tmp in ["\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/dev/shm"]):
                    # Ignore harmless update/installer processes if normal
                    if not any(ign in name for ign in ["update", "installer", "setup", "edge", "chrome"]):
                        sig = f"tmp_exe_{pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)
                            events.append({
                                "source_type": "Host_Process_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "suspicious_process",
                                "description": f"Executable running from temporary directory: '{name}' (Path: '{exe}', PID: {pid})",
                                "source_ip": "127.0.0.1",
                                "destination_ip": None,
                                "username": username,
                                "raw_log": f"PID: {pid} | Exe: {exe}"
                            })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Error auditing process: {e}")

        return events

    def audit_network_sockets(self) -> List[Dict[str, Any]]:
        """Audits host network sockets for exposed high-risk listening ports and strange outbound connections."""
        events = []
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception as e:
            logger.debug(f"Could not retrieve network connections: {e}")
            return events

        for conn in connections:
            try:
                # Check listening ports on wildcard interface
                if conn.status == "LISTEN":
                    laddr = conn.laddr
                    port = laddr.port
                    ip = laddr.ip

                    # If listening on 0.0.0.0 or :: (all interfaces)
                    if ip in ("0.0.0.0", "::", "") and port in self.HIGH_RISK_PORTS:
                        service_name, reason = self.HIGH_RISK_PORTS[port]
                        sig = f"listen_{port}_{conn.pid}"
                        if sig not in self.seen_signatures:
                            self.seen_signatures.add(sig)

                            proc_name = "Unknown"
                            if conn.pid:
                                try:
                                    proc_name = psutil.Process(conn.pid).name()
                                except Exception:
                                    pass

                            events.append({
                                "source_type": "Host_Network_Sensor",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "insecure_listening_port",
                                "description": f"High-risk service '{service_name}' listening on 0.0.0.0:{port} (Process: {proc_name}, PID: {conn.pid}). {reason}.",
                                "source_ip": "0.0.0.0",
                                "destination_ip": None,
                                "source_port": port,
                                "destination_port": None,
                                "username": None,
                                "raw_log": f"Status: LISTEN | LocalAddr: {ip}:{port} | Process: {proc_name} (PID {conn.pid})"
                            })

                # Check established outbound connections to suspicious ports
                elif conn.status == "ESTABLISHED" and conn.raddr:
                    r_ip = conn.raddr.ip
                    r_port = conn.raddr.port

                    # Ignore local private networks
                    if not (r_ip.startswith("127.") or r_ip.startswith("192.168.") or r_ip.startswith("10.") or r_ip.startswith("172.")):
                        if r_port in (4444, 1337, 6667, 9001, 8888):
                            sig = f"outbound_{r_ip}_{r_port}_{conn.pid}"
                            if sig not in self.seen_signatures:
                                self.seen_signatures.add(sig)
                                proc_name = "Unknown"
                                if conn.pid:
                                    try:
                                        proc_name = psutil.Process(conn.pid).name()
                                    except Exception:
                                        pass
                                events.append({
                                    "source_type": "Host_Network_Sensor",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "event_type": "suspicious_outbound_connection",
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
                # Check if any profile has State OFF
                if "State                                 OFF" in output:
                    sig = "win_firewall_off"
                    if sig not in self.seen_signatures:
                        self.seen_signatures.add(sig)
                        events.append({
                            "source_type": "Host_Security_Posture",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "host_firewall_disabled",
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
                    if sig not in self.seen_signatures:
                        self.seen_signatures.add(sig)
                        events.append({
                            "source_type": "Host_Security_Posture",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "host_firewall_disabled",
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

        # Query recent System Event log for service creation (7045) or log clear (104)
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
                    if sig not in self.seen_signatures:
                        self.seen_signatures.add(sig)
                        events.append(ev)
        except Exception as e:
            logger.debug(f"Event log check failed: {e}")

        return events

    def _ingest_events(self, raw_events: List[Dict[str, Any]], db: Session) -> List[Alert]:
        """Deduplicates, normalizes, persists security alerts, and triggers correlation."""
        created_alerts = []
        for raw in raw_events:
            normalized = AlertNormalizer.normalize(raw)
            # Deduplicate: if an identical OPEN alert already exists, do not duplicate
            existing = db.query(Alert).filter(
                Alert.event_type == normalized["event_type"],
                Alert.description == normalized["description"],
                Alert.status == "OPEN"
            ).first()
            if existing:
                continue

            alert = Alert(
                id=uuid.uuid4(),
                timestamp=normalized["timestamp"],
                source_type=normalized["source_type"],
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
                raw_log=normalized.get("raw_log")
            )
            db.add(alert)
            created_alerts.append(alert)

        if created_alerts:
            db.commit()
            IncidentCorrelator.correlate_alerts(db)

        return created_alerts

    def run_fast_audit(self, db: Session) -> List[Alert]:
        """Runs fast, sub-second differential checks on new processes, active sockets, and startup folder."""
        raw_events = []
        raw_events.extend(self.audit_new_processes())
        raw_events.extend(self.audit_network_sockets())
        raw_events.extend(self.audit_startup_folder())
        return self._ingest_events(raw_events, db)

    def run_full_audit(self, db: Session) -> List[Alert]:
        """Runs all live host security audits, normalizes findings, commits to DB, and correlates."""
        raw_events = []
        raw_events.extend(self.audit_processes())
        raw_events.extend(self.audit_network_sockets())
        raw_events.extend(self.audit_startup_folder())
        raw_events.extend(self.audit_firewall_posture())
        raw_events.extend(self.audit_event_logs())
        return self._ingest_events(raw_events, db)

    def run_test_drill(self, db: Session) -> Dict[str, Any]:
        """
        Executes a controlled evaluation drill for testing alert pipelines and triage playbooks.
        Clearly marked as a [TEST DRILL] rather than fake simulated production data.
        """
        drill_scenarios = [
            {
                "source_type": "Host_Security_Sensor",
                "event_type": "insecure_listening_port",
                "description": "[TEST DRILL] Open Insecure Port: Test listener opened on 0.0.0.0:4444 (Simulated Remote Handler)",
                "source_ip": "0.0.0.0",
                "destination_ip": "127.0.0.1",
                "source_port": 4444,
                "destination_port": None,
                "username": "tester",
                "raw_log": "DRILL EVENT: Manual SOC evaluation trigger for port exposure validation."
            },
            {
                "source_type": "Host_Process_Sensor",
                "event_type": "suspicious_command",
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
                "event_type": "windows_failed_logon",
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
        alert = Alert(id=uuid.uuid4(), **norm)
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
                "risk_score": alert.risk_score
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

    # Initial short delay for app startup
    await asyncio.sleep(2)

    tick = 0
    initial_full_done = False

    while True:
        try:
            if stream_manager.simulation_active:
                db = SessionLocal()
                try:
                    if not initial_full_done or (tick % 10 == 0):
                        new_alerts = host_sensor.run_full_audit(db)
                        initial_full_done = True
                    else:
                        new_alerts = host_sensor.run_fast_audit(db)

                    if new_alerts:
                        new_incidents = IncidentCorrelator.correlate_alerts(db)
                        all_alerts = db.query(Alert).all()
                        stats = {
                            "total_alerts": len(all_alerts),
                            "critical_count": sum(1 for a in all_alerts if a.severity == "CRITICAL"),
                            "high_count": sum(1 for a in all_alerts if a.severity == "HIGH"),
                            "medium_count": sum(1 for a in all_alerts if a.severity == "MEDIUM"),
                            "low_count": sum(1 for a in all_alerts if a.severity == "LOW"),
                            "open_count": sum(1 for a in all_alerts if a.status == "OPEN"),
                            "investigating_count": sum(1 for a in all_alerts if a.status == "INVESTIGATING"),
                            "resolved_count": sum(1 for a in all_alerts if a.status == "RESOLVED"),
                            "total_incidents": db.query(Incident).count()
                        }

                        # Broadcast each detected alert over WebSocket
                        for alert in new_alerts:
                            ts_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(alert.timestamp, datetime) else str(alert.timestamp)
                            payload = {
                                "type": "LIVE_THREAT",
                                "alert": {
                                    "id": str(alert.id),
                                    "timestamp": ts_str,
                                    "severity": alert.severity,
                                    "risk_score": alert.risk_score,
                                    "event_type": alert.event_type,
                                    "description": alert.description,
                                    "source_type": alert.source_type,
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
                        await stream_manager.broadcast({
                            "type": "HEARTBEAT",
                            "host_info": host_info
                        })
                finally:
                    db.close()
            tick += 1
        except Exception as e:
            logger.error(f"Error in host monitor loop: {e}", exc_info=True)

        # Real-time sub-second process & socket monitoring interval: 2.0s
        await asyncio.sleep(2.0)
