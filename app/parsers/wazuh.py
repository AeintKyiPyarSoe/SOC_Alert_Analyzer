import json
import logging
from typing import List, Dict, Any
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class WazuhParser(BaseParser):
    """
    Parser for Wazuh JSON alerts.
    Supports single JSON document, array of JSON objects, or line-delimited JSON (JSONL).
    """

    def parse(self, content: str) -> List[Dict[str, Any]]:
        events = []
        content = content.strip()
        if not content:
            return events

        # Try parsing as whole JSON array or object first
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        events.append(self._extract_fields(item))
                return events
            elif isinstance(parsed, dict):
                events.append(self._extract_fields(parsed))
                return events
        except json.JSONDecodeError:
            # Fall back to line-by-line JSON parsing
            pass

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(self._extract_fields(item))
            except json.JSONDecodeError as e:
                logger.warning(f"WazuhParser skipping malformed line {line_num}: {e}")

        return events

    def _extract_fields(self, item: Dict[str, Any]) -> Dict[str, Any]:
        rule = item.get("rule", {})
        data = item.get("data", {})
        agent = item.get("agent", {})

        # Source / Destination IPs
        src_ip = data.get("srcip") or data.get("src_ip") or item.get("srcip")
        dst_ip = data.get("dstip") or data.get("dst_ip") or item.get("dstip")
        
        # Source / Destination Ports
        src_port = data.get("srcport") or data.get("src_port")
        dst_port = data.get("dstport") or data.get("dst_port")

        # Username
        username = data.get("dstuser") or data.get("srcuser") or data.get("user") or item.get("dstuser")

        # Description & Event Type
        description = rule.get("description") or item.get("full_log") or "Wazuh Alert"
        rule_id = str(rule.get("id", ""))
        groups = rule.get("groups", [])
        
        event_type = "wazuh_alert"
        if "authentication_failed" in groups or "authentication_failures" in groups or "5710" in rule_id or "5716" in rule_id:
            event_type = "ssh_authentication_failure"
        elif "sshd" in groups or "ssh" in groups:
            event_type = "ssh_activity"
        elif "rootcheck" in groups:
            event_type = "rootcheck_anomaly"
        elif "syscheck" in groups:
            event_type = "file_integrity_change"
        elif any("scan" in g for g in groups):
            event_type = "network_scan"
        elif "command" in groups or "powershell" in description.lower():
            event_type = "suspicious_command"

        return {
            "source_type": "Wazuh",
            "timestamp": item.get("timestamp"),
            "event_type": event_type,
            "description": description,
            "rule_id": rule_id,
            "rule_level": rule.get("level"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
            "destination_port": int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            "username": username,
            "agent_name": agent.get("name"),
            "raw_log": json.dumps(item)
        }
