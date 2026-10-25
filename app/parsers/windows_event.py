import re
import json
import logging
import defusedxml.ElementTree as ET
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
        # Sysmon Specific Event IDs (Microsoft-Windows-Sysmon/Operational)
        1: ("sysmon_process_creation", "Sysmon Process Creation"),
        3: ("sysmon_network_connection", "Sysmon Network Connection Detected"),
        7: ("sysmon_image_loaded", "Sysmon Module / DLL Image Loaded"),
        8: ("sysmon_create_remote_thread", "Sysmon CreateRemoteThread Detected (Process Injection)"),
        10: ("sysmon_process_access", "Sysmon ProcessAccess Detected (LSASS / Memory Access)"),
        11: ("sysmon_file_created", "Sysmon File Created"),
        12: ("sysmon_registry_event", "Sysmon Registry Object Created / Deleted"),
        13: ("sysmon_registry_event", "Sysmon Registry Value Set (Persistence Run Key)"),
        22: ("sysmon_dns_query", "Sysmon DNS Query Detected"),
        25: ("sysmon_process_tampering", "Sysmon Process Tampering Detected"),
        # Critical Windows Security & System Event IDs
        4625: ("windows_failed_logon", "Windows Failed Logon / Bad Password Attempt"),
        4624: ("windows_successful_logon", "Windows Successful Logon"),
        4688: ("windows_process_creation", "Windows Process Created"),
        4672: ("windows_special_privileges", "Special Privileges Assigned to New Logon"),
        4776: ("windows_ntlm_auth", "NTLM Credential Validation Attempt"),
        5140: ("windows_network_share", "Network Share Object Accessed (SMB)"),
        5145: ("windows_network_share_detailed", "Network Share Object Checked for Access"),
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

        provider = str(item.get("Provider_Name") or item.get("Provider") or item.get("Channel") or "")
        is_sysmon = "sysmon" in provider.lower() or event_id in (1, 3, 7, 8, 10, 11, 12, 13, 22, 25)
        source_type = "Sysmon" if is_sysmon else "Windows_Event"

        # Timestamps
        time_created = item.get("TimeCreated") or item.get("TimeGenerated") or item.get("timestamp")
        timestamp = self._parse_timestamp(time_created)

        # Message / Details / EventData
        data = item.get("EventData") if isinstance(item.get("EventData"), dict) else item
        msg = item.get("Message") or item.get("message") or item.get("description")

        # Extract IP, username, process info from message or dictionary
        src_ip = data.get("IpAddress") or data.get("SourceNetworkAddress") or data.get("SourceIp") or item.get("source_ip")
        src_port = data.get("IpPort") or data.get("SourcePort") or item.get("source_port")
        dst_ip = data.get("DestinationIp") or item.get("destination_ip") or item.get("DestinationAddress")
        dst_port = data.get("DestinationPort") or item.get("destination_port")
        username = data.get("TargetUserName") or data.get("AccountName") or data.get("SubjectUserName") or data.get("User") or item.get("username")
        logon_type = data.get("LogonType") or item.get("LogonType")

        # Extract Sysmon / Process Creation fields
        image = data.get("Image") or data.get("NewProcessName") or data.get("ProcessName")
        cmdline = data.get("CommandLine") or data.get("ProcessCommandLine")
        parent_image = data.get("ParentImage") or data.get("ParentProcessName")
        target_obj = data.get("TargetObject") or data.get("TargetFilename") or data.get("TargetImage")
        granted_access = data.get("GrantedAccess")
        query_name = data.get("QueryName")

        if not logon_type and isinstance(msg, str):
            lt_m = re.search(r"(?:Logon Type|LogonType):\s*(\d+)", msg, re.IGNORECASE)
            if lt_m:
                logon_type = lt_m.group(1).strip()

        if not src_ip and isinstance(msg, str):
            ip_m = re.search(r"(?:Source Network Address|IP Address|Workstation IP|Client IP|SourceIp):\s*([0-9a-fA-F\.\:]+)", msg, re.IGNORECASE)
            if ip_m:
                candidate = ip_m.group(1).strip()
                if candidate not in ("-", "::1"):
                    src_ip = candidate

        if not username and isinstance(msg, str):
            user_m = re.search(r"(?:Account Name|Target User Name|User Name|User):\s*([^\s\r\n\t]+)", msg, re.IGNORECASE)
            if user_m:
                u = user_m.group(1).strip()
                if u not in ("-", "SYSTEM", "N/A"):
                    username = u

        # Classify process creation suspiciousness
        if event_id in (4688, 1):
            cmd_check = f"{cmdline or ''} {image or ''}".lower()
            suspicious_tokens = (
                "-enc", "-encodedcommand", "powershell", "certutil", "mshta", "vssadmin",
                "mimikatz", "netsh advfirewall", "downloadstring", "downloadfile",
                "invoke-expression", "-w hidden", "-windowstyle hidden", "wscript",
                "cscript", "rundll32", "regsvr32", "bitsadmin", "sekurlsa",
                "msbuild", "wmic", "shadowcopy", "set-mppreference"
            )
            if any(t in cmd_check for t in suspicious_tokens):
                event_type = "windows_suspicious_process" if event_id == 4688 else "sysmon_suspicious_process"
        elif event_id == 3:
            img_lower = str(image or "").lower()
            dst_port_num = int(dst_port) if dst_port and str(dst_port).isdigit() else None
            untrusted_paths = ("\\users\\public\\", "\\appdata\\local\\temp\\", "\\programdata\\")
            is_untrusted_loc = any(p in img_lower for p in untrusted_paths)
            is_masquerade = ("svchost" in img_lower and "system32" not in img_lower)
            high_risk_ports = (4444, 1337, 5985, 6667)
            if (dst_port_num in high_risk_ports) or (is_untrusted_loc and dst_port_num not in (80, 443)) or is_masquerade:
                event_type = "sysmon_suspicious_network"
        elif event_id == 22:
            q_lower = str(query_name or "").lower()
            suspicious_dns_indicators = (
                "dynu.net", "duckdns.org", "no-ip.", "ngrok.io", "hopto.org",
                "zapto.org", "bounceme.net", "c2", "beacon", "tunnel"
            )
            if any(ind in q_lower for ind in suspicious_dns_indicators):
                event_type = "sysmon_suspicious_dns"

        # Build clean, informative description
        first_line = msg.split("\n")[0].strip() if isinstance(msg, str) else default_desc
        prefix = f"[Sysmon Event {event_id}]" if is_sysmon else f"[Event {event_id}]"

        if is_sysmon:
            if event_id == 1:
                description = f"{prefix} Process Created: {image or 'Unknown'}"
                if cmdline:
                    description += f" - CommandLine: {cmdline}"
                if parent_image:
                    description += f" (Parent: {parent_image})"
            elif event_id == 3:
                description = f"{prefix} Network Connection: {image or 'Process'} -> {dst_ip or 'Remote'}:{dst_port or 'Port'}"
            elif event_id == 10:
                description = f"{prefix} Process Access: {data.get('SourceImage', 'Unknown')} accessed {target_obj or 'Target'} (GrantedAccess: {granted_access or 'Unknown'})"
            elif event_id == 11:
                description = f"{prefix} File Created: {target_obj or 'File'} by {image or 'Process'}"
            elif event_id == 13:
                description = f"{prefix} Registry Value Set: {target_obj or 'Key'} by {image or 'Process'}"
            elif event_id == 22:
                description = f"{prefix} DNS Query: {query_name or 'Domain'} by {image or 'Process'}"
            else:
                description = f"{prefix} {first_line}"
        elif event_id == 4688:
            description = f"{prefix} Process Created: {image or 'Unknown'}"
            if cmdline:
                description += f" - CommandLine: {cmdline}"
            if parent_image:
                description += f" (Parent: {parent_image})"
            if username:
                description += f" (User: {username})"
        elif event_id == 4624 and str(logon_type) in ("2", "7", "11"):
            description = f"{prefix} Windows Interactive Console Logon (User: {username or 'Unknown'}, LogonType: {logon_type})"
        else:
            description = f"{prefix} {first_line}"
            if username:
                description += f" (User: {username})"
            if src_ip:
                description += f" from {src_ip}"

        return {
            "source_type": source_type,
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "event_id": event_id,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
            "destination_port": int(dst_port) if dst_port and str(dst_port).isdigit() else None,
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

                provider_el = system.find("Provider") if system is not None else None
                provider_name = provider_el.attrib.get("Name", "") if provider_el is not None else ""
                channel_el = system.find("Channel") if system is not None else None
                channel_name = channel_el.text or "" if channel_el is not None else ""

                is_sysmon = "sysmon" in provider_name.lower() or "sysmon" in channel_name.lower() or event_id in (1, 3, 7, 8, 10, 11, 12, 13, 22, 25)
                source_type = "Sysmon" if is_sysmon else "Windows_Event"

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

                username = data_dict.get("TargetUserName") or data_dict.get("AccountName") or data_dict.get("SubjectUserName") or data_dict.get("User")
                logon_type = data_dict.get("LogonType")
                src_ip = data_dict.get("IpAddress") or data_dict.get("SourceNetworkAddress") or data_dict.get("SourceIp")
                if src_ip in ("-", "::1", "127.0.0.1"):
                    src_ip = None
                src_port = data_dict.get("IpPort") or data_dict.get("SourcePort")
                dst_ip = data_dict.get("DestinationIp") or data_dict.get("DestinationAddress")
                dst_port = data_dict.get("DestinationPort")

                # Sysmon specific fields
                image = data_dict.get("Image") or data_dict.get("NewProcessName")
                cmdline = data_dict.get("CommandLine") or data_dict.get("ProcessCommandLine")
                parent_image = data_dict.get("ParentImage") or data_dict.get("ParentProcessName")
                target_obj = data_dict.get("TargetObject") or data_dict.get("TargetFilename") or data_dict.get("TargetImage")
                granted_access = data_dict.get("GrantedAccess")
                query_name = data_dict.get("QueryName")

                # Classify process creation suspiciousness
                if event_id in (4688, 1):
                    cmd_check = f"{cmdline or ''} {image or ''}".lower()
                    suspicious_tokens = (
                        "-enc", "-encodedcommand", "powershell", "certutil", "mshta", "vssadmin",
                        "mimikatz", "netsh advfirewall", "downloadstring", "downloadfile",
                        "invoke-expression", "-w hidden", "-windowstyle hidden", "wscript",
                        "cscript", "rundll32", "regsvr32", "bitsadmin", "sekurlsa"
                    )
                    if any(t in cmd_check for t in suspicious_tokens):
                        event_type = "windows_suspicious_process" if event_id == 4688 else "sysmon_suspicious_process"
                elif event_id == 22:
                    q_lower = str(query_name or "").lower()
                    suspicious_dns_indicators = (
                        "dynu.net", "duckdns.org", "no-ip.", "ngrok.io", "hopto.org",
                        "zapto.org", "bounceme.net", "c2", "beacon", "tunnel"
                    )
                    if any(ind in q_lower for ind in suspicious_dns_indicators):
                        event_type = "sysmon_suspicious_dns"

                prefix = f"[Sysmon Event {event_id}]" if is_sysmon else f"[Event {event_id}]"
                if is_sysmon:
                    if event_id == 1:
                        desc = f"{prefix} Process Created: {image or 'Unknown'}"
                        if cmdline:
                            desc += f" - CommandLine: {cmdline}"
                        if parent_image:
                            desc += f" (Parent: {parent_image})"
                    elif event_id == 3:
                        desc = f"{prefix} Network Connection: {image or 'Process'} -> {dst_ip or 'Remote'}:{dst_port or 'Port'}"
                    elif event_id == 10:
                        desc = f"{prefix} Process Access: {data_dict.get('SourceImage', 'Unknown')} accessed {target_obj or 'Target'} (GrantedAccess: {granted_access or 'Unknown'})"
                    elif event_id == 11:
                        desc = f"{prefix} File Created: {target_obj or 'File'} by {image or 'Process'}"
                    elif event_id == 13:
                        desc = f"{prefix} Registry Value Set: {target_obj or 'Key'} by {image or 'Process'}"
                    elif event_id == 22:
                        desc = f"{prefix} DNS Query: {query_name or 'Domain'} by {image or 'Process'}"
                    else:
                        desc = f"{prefix} {default_desc}"
                elif event_id == 4688:
                    desc = f"{prefix} Process Created: {image or 'Unknown'}"
                    if cmdline:
                        desc += f" - CommandLine: {cmdline}"
                    if parent_image:
                        desc += f" (Parent: {parent_image})"
                    if username:
                        desc += f" (User: {username})"
                elif event_id == 4624 and str(logon_type) in ("2", "7", "11"):
                    desc = f"{prefix} Windows Interactive Console Logon (User: {username or 'Unknown'}, LogonType: {logon_type})"
                else:
                    desc = f"{prefix} {default_desc}"
                    if username:
                        desc += f" (User: {username})"
                    if src_ip:
                        desc += f" from {src_ip}"

                events.append({
                    "source_type": source_type,
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "description": desc,
                    "event_id": event_id,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
                    "destination_port": int(dst_port) if dst_port and str(dst_port).isdigit() else None,
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
