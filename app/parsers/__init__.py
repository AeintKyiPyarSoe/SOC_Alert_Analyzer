from typing import Optional
from app.parsers.base import BaseParser
from app.parsers.wazuh import WazuhParser
from app.parsers.suricata import SuricataParser
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.windows_event import WindowsEventParser
from app.parsers.web_access import WebAccessParser
from app.parsers.firewall import FirewallParser
from app.parsers.generic_log import GenericLogParser

def get_parser(source_type: str) -> BaseParser:
    source = source_type.strip().lower()
    if "windows" in source or "winevent" in source or "evtx" in source:
        return WindowsEventParser()
    elif "web" in source or "apache" in source or "nginx" in source or "iis" in source:
        return WebAccessParser()
    elif "firewall" in source or "iptables" in source or "ufw" in source:
        return FirewallParser()
    elif "wazuh" in source:
        return WazuhParser()
    elif "suricata" in source or "eve" in source:
        return SuricataParser()
    elif "linux" in source or "auth" in source:
        return LinuxAuthParser()
    elif "generic" in source or "csv" in source:
        return GenericLogParser()
    
    # Fallback to generic
    return GenericLogParser()

def detect_source_type(content: str) -> str:
    """Heuristically detect source type from log content snippet."""
    sample = content[:4000].lower()

    # Windows Event Log (XML, JSON, Text)
    if "<event" in sample or "microsoft-windows" in sample or "event id:" in sample or "eventid" in sample:
        return "windows"

    # Suricata EVE
    if '"event_type"' in sample and ('"alert"' in sample or '"src_ip"' in sample or '"suricata"' in sample):
        return "suricata"

    # Wazuh JSON
    if '"rule"' in sample and ('"id"' in sample or '"level"' in sample or '"wazuh"' in sample):
        return "wazuh"

    # Linux Authentication Log
    if 'sshd[' in sample or 'sudo:' in sample or 'failed password' in sample:
        return "linux_auth"

    # Web Server Access Log (Apache / Nginx / IIS)
    if (' "get ' in sample or ' "post ' in sample or ' "put ' in sample or ' "head ' in sample) and "http/" in sample:
        return "web"

    # Firewall Log
    if '[ufw ' in sample or ('src=' in sample and 'dst=' in sample and 'proto=' in sample) or ('drop ' in sample and 'tcp' in sample):
        return "firewall"

    # Generic JSON or CSV
    if sample.strip().startswith("{") or sample.strip().startswith("["):
        return "generic"
    if "," in sample and any(kw in sample for kw in ["source_ip", "event_type", "severity", "description", "timestamp"]):
        return "generic"

    return "generic"

__all__ = [
    "BaseParser",
    "WazuhParser",
    "SuricataParser",
    "LinuxAuthParser",
    "WindowsEventParser",
    "WebAccessParser",
    "FirewallParser",
    "GenericLogParser",
    "get_parser",
    "detect_source_type"
]
