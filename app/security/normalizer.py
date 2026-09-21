import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.security.mitre_mapper import MitreMapper
from app.security.risk_engine import RiskEngine

class AlertNormalizer:
    """Normalizes raw parsed event dictionaries into canonical Alert entities."""

    @classmethod
    def normalize(cls, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        source_type = raw_event.get("source_type", "Unknown")
        event_type = raw_event.get("event_type", "security_anomaly")
        description = raw_event.get("description", "Security Event Detected")

        # Normalize Timestamp
        timestamp = cls._normalize_timestamp(raw_event.get("timestamp"))

        # Sanitize IP addresses
        source_ip = cls._sanitize_ip(raw_event.get("source_ip"))
        destination_ip = cls._sanitize_ip(raw_event.get("destination_ip"))

        # Sanitize Ports
        source_port = cls._sanitize_port(raw_event.get("source_port"))
        destination_port = cls._sanitize_port(raw_event.get("destination_port"))

        # Determine external IP exposure
        is_external = False
        if source_ip:
            try:
                ip_obj = ipaddress.ip_address(source_ip)
                is_external = not (ip_obj.is_private or ip_obj.is_loopback)
            except ValueError:
                pass

        # Check for known attack signatures in description
        desc_lower = description.lower()
        is_known_signature = any(kw in desc_lower for kw in [
            "brute", "cve", "exploit", "unauthorized", "scan", "powershell", "backdoor"
        ])

        # Map MITRE ATT&CK technique
        mitre_technique = MitreMapper.map_event(event_type, description)

        # Calculate Risk Score & Severity
        raw_level = raw_event.get("rule_level") or raw_event.get("suricata_severity")
        risk_score, severity, _ = RiskEngine.calculate_risk(
            event_type=event_type,
            source_type=source_type,
            raw_level=raw_level,
            frequency_count=1,
            is_external_ip=is_external,
            is_known_attack_signature=is_known_signature
        )

        return {
            "timestamp": timestamp,
            "source_type": source_type,
            "event_type": event_type,
            "description": description,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "username": raw_event.get("username"),
            "severity": severity,
            "risk_score": risk_score,
            "mitre_technique": mitre_technique,
            "status": "OPEN",
            "raw_log": raw_event.get("raw_log")
        }

    @staticmethod
    def _normalize_timestamp(ts_val: Any) -> datetime:
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                return ts_val.replace(tzinfo=timezone.utc)
            return ts_val.astimezone(timezone.utc)

        if not ts_val or not isinstance(ts_val, str):
            return datetime.now(timezone.utc)

        ts_str = ts_val.strip()
        # Handle ISO format
        try:
            # Handle 'Z' suffix
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        return datetime.now(timezone.utc)

    @staticmethod
    def _sanitize_ip(ip_val: Any) -> Optional[str]:
        if not ip_val or not isinstance(ip_val, str):
            return None
        ip_str = ip_val.strip()
        try:
            # Validate IP format
            ipaddress.ip_address(ip_str)
            return ip_str
        except ValueError:
            return None

    @staticmethod
    def _sanitize_port(port_val: Any) -> Optional[int]:
        if port_val is None:
            return None
        try:
            port = int(port_val)
            if 1 <= port <= 65535:
                return port
        except (ValueError, TypeError):
            pass
        return None
