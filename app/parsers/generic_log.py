import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class GenericLogParser(BaseParser):
    """
    Parser for generic security logs in JSON or CSV format.
    Allows importing alerts from any custom tool, script, antivirus, or CSV report.
    """

    def parse(self, content: str) -> List[Dict[str, Any]]:
        content = content.strip()
        if not content:
            return []

        # Try JSON first
        if content.startswith("[") or content.startswith("{"):
            try:
                data = json.loads(content)
                items = data if isinstance(data, list) else [data]
                events = []
                for item in items:
                    if isinstance(item, dict):
                        ev = self._from_dict(item)
                        if ev:
                            events.append(ev)
                if events:
                    return events
            except json.JSONDecodeError:
                pass

        # Try CSV
        try:
            reader = csv.DictReader(io.StringIO(content))
            events = []
            for row in reader:
                ev = self._from_dict(row)
                if ev:
                    events.append(ev)
            if events:
                return events
        except Exception as e:
            logger.debug(f"CSV parsing error: {e}")

        return []

    def _from_dict(self, d: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Normalize key names to lowercase
        lower_d = {k.lower().strip(): v for k, v in d.items() if isinstance(k, str)}

        desc = (
            lower_d.get("description") or
            lower_d.get("message") or
            lower_d.get("title") or
            lower_d.get("alert") or
            "Security Anomaly"
        )

        event_type = (
            lower_d.get("event_type") or
            lower_d.get("classification") or
            lower_d.get("category") or
            "security_anomaly"
        )

        src_ip = lower_d.get("source_ip") or lower_d.get("src_ip") or lower_d.get("src") or lower_d.get("ip")
        dst_ip = lower_d.get("destination_ip") or lower_d.get("dst_ip") or lower_d.get("dst")

        src_port = lower_d.get("source_port") or lower_d.get("src_port") or lower_d.get("sport")
        dst_port = lower_d.get("destination_port") or lower_d.get("dst_port") or lower_d.get("dport")

        username = lower_d.get("username") or lower_d.get("user") or lower_d.get("account")
        source_type = lower_d.get("source_type") or lower_d.get("source") or "Generic_Log"

        ts = lower_d.get("timestamp") or lower_d.get("time") or lower_d.get("date")

        return {
            "source_type": source_type,
            "timestamp": ts or datetime.now(timezone.utc).isoformat(),
            "event_type": str(event_type).replace(" ", "_").lower(),
            "description": str(desc),
            "source_ip": str(src_ip) if src_ip else None,
            "destination_ip": str(dst_ip) if dst_ip else None,
            "source_port": int(src_port) if src_port and str(src_port).isdigit() else None,
            "destination_port": int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            "username": str(username) if username else None,
            "raw_log": json.dumps(d)
        }
