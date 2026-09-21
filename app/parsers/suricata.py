import json
import logging
from typing import List, Dict, Any
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class SuricataParser(BaseParser):
    """
    Parser for Suricata EVE JSON log files.
    Extracts security alert records (event_type == 'alert').
    """

    def parse(self, content: str) -> List[Dict[str, Any]]:
        events = []
        content = content.strip()
        if not content:
            return events

        # Try parsing as whole JSON list/dict first
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        ev = self._extract_event(item)
                        if ev:
                            events.append(ev)
                return events
            elif isinstance(parsed, dict):
                ev = self._extract_event(parsed)
                if ev:
                    events.append(ev)
                return events
        except json.JSONDecodeError:
            pass

        # Parse line by line (typical EVE JSONL format)
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    ev = self._extract_event(item)
                    if ev:
                        events.append(ev)
            except json.JSONDecodeError as e:
                logger.warning(f"SuricataParser skipping malformed line {line_num}: {e}")

        return events

    def _extract_event(self, item: Dict[str, Any]) -> Dict[str, Any]:
        alert = item.get("alert")
        # If it's an EVE record, process if alert dict exists or event_type is 'alert'
        if not alert and item.get("event_type") != "alert":
            return None

        alert = alert or {}
        signature = alert.get("signature") or "Suricata Network Alert"
        signature_id = alert.get("signature_id")
        suricata_severity = alert.get("severity")  # In Suricata: 1=High, 2=Med, 3=Low, 4=Info

        # Map signature to event_type
        sig_lower = signature.lower()
        if "scan" in sig_lower or "sweep" in sig_lower:
            event_type = "network_scan"
        elif "brute" in sig_lower or "failed" in sig_lower or "login" in sig_lower:
            event_type = "ssh_authentication_failure"
        elif "dos" in sig_lower or "flood" in sig_lower:
            event_type = "denial_of_service"
        elif "exploit" in sig_lower or "cve" in sig_lower:
            event_type = "exploit_attempt"
        elif "powershell" in sig_lower or "shell" in sig_lower:
            event_type = "suspicious_command"
        else:
            event_type = "network_anomaly"

        src_port = item.get("src_port")
        dest_port = item.get("dest_port")

        return {
            "source_type": "Suricata",
            "timestamp": item.get("timestamp"),
            "event_type": event_type,
            "description": signature,
            "signature_id": signature_id,
            "suricata_severity": suricata_severity,
            "source_ip": item.get("src_ip"),
            "destination_ip": item.get("dest_ip"),
            "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
            "destination_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
            "proto": item.get("proto"),
            "raw_log": json.dumps(item)
        }
