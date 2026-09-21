import re
import json
import xml.etree.ElementTree as ET
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class WindowsEventParser(BaseParser):
    """
    Parser for real-world Windows Event Logs.
    Supports JSON exports, XML exports (wevtutil / Event Viewer), and text log dumps.
    Covers critical defensive events:
      - 4625: Failed Logon (Brute Force)
      - 4624: Successful Logon (unusual remote/network logon)
      - 4688: Process Creation with Command Line
      - 7045: New Service Installed (Persistence)
      - 4698: Scheduled Task Created (Persistence)
      - 4720: User Account Created (Local Account)
      - 4728/4732: User Added to Privileged Group
      - 1102 / 104: Audit/System Log Cleared (Defense Evasion)
      - 1116 / 1117: Windows Defender Malware / Threat Detected
      - 4104: PowerShell Script Block Execution
    """

    EVENT_ID_MAP = {
        4625: ("windows_failed_logon", "Windows Failed Logon / Bad Password Attempt"),
        4624: ("windows_successful_logon", "Windows Successful Logon"),
        4688: ("windows_suspicious_process", "Windows Process Created"),
        7045: ("windows_service_installed", "Windows Service Installed"),
        4698: ("windows_scheduled_task", "Windows Scheduled Task Created"),
        4720: ("windows_account_created", "Windows User Account Created"),
        4728: ("windows_privilege_escalation", "User Added to Privileged Security Group"),
        4732: ("windows_privilege_escalation", "User Added to Local Administrators Group"),
        1102: ("windows_log_cleared", "Windows Security Audit Log Cleared"),
        104: ("windows_log_cleared", "Windows System Event Log Cleared"),
        1116: ("windows_defender_threat", "Windows Defender Threat Detected"),
        1117: ("windows_defender_action", "Windows Defender Action Taken on Malware"),
        4104: ("powershell_script_block", "PowerShell Script Block Execution")
    }

    def parse(self, content: str) -> List[Dict[str, Any]]:
        content = content.strip()
        if not content:
            return []

        # Try JSON first
        if content.startswith("[") or content.startswith("{"):
            try:
                events = self._parse_json(content)
                if events:
                    return events
            except Exception as e:
                logger.debug(f"JSON parsing attempt failed: {e}")

        # Try XML next
        if "<Event" in content:
            try:
                events = self._parse_xml(content)
                if events:
                    return events
            except Exception as e:
                logger.debug(f"XML parsing attempt failed: {e}")

        # Fallback to Text / Key-Value dump
        return self._parse_text(content)

    def _parse_json(self, content: str) -> List[Dict[str, Any]]:
        events = []
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Try line by line JSON
            items = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for item in items:
            if not isinstance(item, dict):
                continue
            ev = self._extract_json_event(item)
            if ev:
                events.append(ev)
        return events

    def _extract_json_event(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_id = item.get("Id") or item.get("EventID") or item.get("id") or item.get("event_id")
        if not event_id:
            return None
        try:
            event_id = int(event_id)
        except (ValueError, TypeError):
            return None

        event_type, default_desc = self.EVENT_ID_MAP.get(
            event_id, ("windows_event", f"Windows Event ID {event_id}")
        )

        # Timestamps
        time_created = item.get("TimeCreated") or item.get("TimeGenerated") or item.get("timestamp")
        timestamp = self._parse_timestamp(time_created)

        # Message / Details
        msg = item.get("Message") or item.get("message") or item.get("description") or default_desc

        # Extract IP, username, process info from message or dictionary
        src_ip = item.get("IpAddress") or item.get("SourceNetworkAddress") or item.get("source_ip")
        src_port = item.get("IpPort") or item.get("SourcePort") or item.get("source_port")
        username = item.get("TargetUserName") or item.get("AccountName") or item.get("username")

        if not src_ip and isinstance(msg, str):
            ip_m = re.search(r"(?:Source Network Address|IP Address|Workstation IP|Client IP):\s*([0-9a-fA-F\.\:]+)", msg, re.IGNORECASE)
            if ip_m:
                candidate = ip_m.group(1).strip()
                if candidate != "-" and candidate != "::1":
                    src_ip = candidate

        if not username and isinstance(msg, str):
            user_m = re.search(r"(?:Account Name|Target User Name|User Name|User):\s*([^\s\r\n\t]+)", msg, re.IGNORECASE)
            if user_m:
                u = user_m.group(1).strip()
                if u not in ("-", "SYSTEM", "N/A"):
                    username = u

        # Build clean description
        first_line = msg.split("\n")[0].strip() if isinstance(msg, str) else default_desc
        description = f"[Event {event_id}] {first_line}"
        if username:
            description += f" (User: {username})"
        if src_ip:
            description += f" from {src_ip}"

        return {
            "source_type": "Windows_Event",
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "event_id": event_id,
            "source_ip": src_ip,
            "destination_ip": item.get("DestinationIp") or item.get("destination_ip"),
            "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
            "destination_port": None,
            "username": username,
            "raw_log": json.dumps(item) if not isinstance(msg, str) else msg
        }

    def _parse_xml(self, content: str) -> List[Dict[str, Any]]:
        events = []
        clean_content = re.sub(r'\sxmlns(?::\w+)?="[^"]+"', '', content.strip())
        try:
            root = ET.fromstring(clean_content)
        except ET.ParseError:
            try:
                root = ET.fromstring(f"<Events>{clean_content}</Events>")
            except Exception:
                return []

        event_nodes = [e for e in root.iter() if e.tag.lower() == "event"]

        for node in event_nodes:
            try:
                system = node.find("System")
                if system is None:
                    system = node.find("system")

                event_data = node.find("EventData")
                if event_data is None:
                    event_data = node.find("eventdata")

                event_id_el = system.find("EventID") if system is not None else None
                if event_id_el is None and system is not None:
                    event_id_el = system.find("eventid")

                event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else None
                if not event_id:
                    continue

                event_type, default_desc = self.EVENT_ID_MAP.get(
                    event_id, ("windows_event", f"Windows Event ID {event_id}")
                )

                time_el = system.find("TimeCreated") if system is not None else None
                if time_el is None and system is not None:
                    time_el = system.find("timecreated")
                time_str = time_el.attrib.get("SystemTime") if time_el is not None else None
                timestamp = self._parse_timestamp(time_str)

                # Extract Data elements
                data_dict = {}
                if event_data is not None:
                    for d in event_data.findall("Data"):
                        name = d.attrib.get("Name")
                        if name:
                            data_dict[name] = d.text or ""

                username = data_dict.get("TargetUserName") or data_dict.get("AccountName") or data_dict.get("SubjectUserName")
                src_ip = data_dict.get("IpAddress") or data_dict.get("SourceNetworkAddress")
                if src_ip in ("-", "::1", "127.0.0.1"):
                    src_ip = None
                src_port = data_dict.get("IpPort") or data_dict.get("SourcePort")

                desc = f"[Event {event_id}] {default_desc}"
                if username:
                    desc += f" (User: {username})"
                if src_ip:
                    desc += f" from {src_ip}"

                events.append({
                    "source_type": "Windows_Event",
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "description": desc,
                    "event_id": event_id,
                    "source_ip": src_ip,
                    "destination_ip": None,
                    "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
                    "destination_port": None,
                    "username": username,
                    "raw_log": ET.tostring(node, encoding="utf-8").decode("utf-8", errors="replace")
                })
            except Exception as e:
                logger.debug(f"Failed parsing XML event node: {e}")

        return events

    def _parse_text(self, content: str) -> List[Dict[str, Any]]:
        events = []
        # Split by "Event ID:" or "Log Name:" blocks
        blocks = re.split(r"(?:\r?\n){2,}(?=Log Name:|Event ID:|Event\[)", content)
        if len(blocks) == 1:
            blocks = [content]

        for block in blocks:
            id_m = re.search(r"Event\s*ID\s*:\s*(\d+)", block, re.IGNORECASE)
            if not id_m:
                continue

            event_id = int(id_m.group(1))
            event_type, default_desc = self.EVENT_ID_MAP.get(
                event_id, ("windows_event", f"Windows Event ID {event_id}")
            )

            date_m = re.search(r"Date\s*:\s*([^\r\n]+)", block, re.IGNORECASE)
            timestamp = self._parse_timestamp(date_m.group(1) if date_m else None)

            ip_m = re.search(r"(?:Source Network Address|IP Address):\s*([0-9a-fA-F\.\:]+)", block, re.IGNORECASE)
            src_ip = ip_m.group(1).strip() if ip_m else None
            if src_ip in ("-", "::1", "127.0.0.1"):
                src_ip = None

            port_m = re.search(r"(?:Source Port|IpPort):\s*(\d+)", block, re.IGNORECASE)
            src_port = int(port_m.group(1)) if port_m else None

            user_m = re.search(r"(?:Account Name|Target User Name|User):\s*([^\s\r\n\t]+)", block, re.IGNORECASE)
            username = user_m.group(1).strip() if user_m else None
            if username in ("-", "N/A", "SYSTEM"):
                username = None

            events.append({
                "source_type": "Windows_Event",
                "timestamp": timestamp,
                "event_type": event_type,
                "description": f"[Event {event_id}] {default_desc}" + (f" (User: {username})" if username else ""),
                "event_id": event_id,
                "source_ip": src_ip,
                "destination_ip": None,
                "source_port": src_port,
                "destination_port": None,
                "username": username,
                "raw_log": block
            })

        return events

    def _parse_timestamp(self, ts_val: Any) -> str:
        if not ts_val:
            return datetime.now(timezone.utc).isoformat()
        ts_str = str(ts_val).strip()
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass

        for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str.split(".")[0], fmt)
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except Exception:
                continue

        return datetime.now(timezone.utc).isoformat()
