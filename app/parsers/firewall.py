import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class FirewallParser(BaseParser):
    """
    Parser for Firewall and Packet Filter Logs.
    Supports:
      - Linux iptables / ufw syslog (e.g. '[UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=1234 DPT=80')
      - Windows Firewall log (pfirewall.log format: '2026-09-10 14:00:00 DROP TCP 192.168.1.50 192.168.1.10 54120 445 ...')
      - pfSense / OPNsense filterlog format
    """

    # Linux iptables / UFW pattern
    IPTABLES_PATTERN = re.compile(
        r"(?P<ts>^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?).*?"
        r"(?:\[(?P<action>.*?BLOCK|.*?DROP|.*?REJECT)\]|kernel:\s*.*?)\s*"
        r".*?SRC=(?P<src>[0-9a-fA-F\.\:]+)\s+DST=(?P<dst>[0-9a-fA-F\.\:]+).*?"
        r"PROTO=(?P<proto>\w+)(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?",
        re.IGNORECASE
    )

    # Windows Firewall (pfirewall.log) pattern
    # Format: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
    WIN_FIREWALL_PATTERN = re.compile(
        r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<action>DROP|OPEN|CLOSE)\s+(?P<proto>\w+)\s+"
        r"(?P<src>[0-9a-fA-F\.\:]+)\s+(?P<dst>[0-9a-fA-F\.\:]+)\s+(?P<spt>\d+)\s+(?P<dpt>\d+)",
        re.IGNORECASE
    )

    def parse(self, content: str) -> List[Dict[str, Any]]:
        events = []
        if not content:
            return events

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check Windows Firewall
            m_win = self.WIN_FIREWALL_PATTERN.search(line)
            if m_win:
                action = m_win.group("action").upper()
                if action == "DROP":
                    ts_str = f"{m_win.group('date')} {m_win.group('time')}"
                    events.append({
                        "source_type": "Firewall",
                        "timestamp": self._parse_iso(ts_str),
                        "event_type": "firewall_blocked_traffic",
                        "description": f"Windows Firewall dropped inbound {m_win.group('proto')} connection from {m_win.group('src')} to port {m_win.group('dpt')}",
                        "source_ip": m_win.group("src"),
                        "destination_ip": m_win.group("dst"),
                        "source_port": int(m_win.group("spt")),
                        "destination_port": int(m_win.group("dpt")),
                        "username": None,
                        "raw_log": line
                    })
                continue

            # Check iptables / UFW
            m_ip = self.IPTABLES_PATTERN.search(line)
            if m_ip:
                events.append({
                    "source_type": "Firewall",
                    "timestamp": self._parse_syslog_ts(m_ip.group("ts")),
                    "event_type": "firewall_blocked_traffic",
                    "description": f"Firewall blocked packet from {m_ip.group('src')} targeting port {m_ip.group('dpt') or 'unknown'} ({m_ip.group('proto')})",
                    "source_ip": m_ip.group("src"),
                    "destination_ip": m_ip.group("dst"),
                    "source_port": int(m_ip.group("spt")) if m_ip.group("spt") else None,
                    "destination_port": int(m_ip.group("dpt")) if m_ip.group("dpt") else None,
                    "username": None,
                    "raw_log": line
                })

        return events

    def _parse_iso(self, ts_str: str) -> str:
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    def _parse_syslog_ts(self, ts_str: str) -> str:
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass

        current_year = datetime.now(timezone.utc).year
        for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                dt = datetime.strptime(f"{current_year} {ts_str}", f"%Y {fmt}")
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except Exception:
                continue

        return datetime.now(timezone.utc).isoformat()
