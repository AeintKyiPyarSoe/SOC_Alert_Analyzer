import re
import email.utils
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from app.security.mitre_mapper import MitreMapper
from app.security.risk_engine import RiskEngine
from app.security.ip_utils import IPClassifier

class AlertNormalizer:
    """Normalizes raw parsed event dictionaries into canonical Alert entities."""

    # Attack signature terms evaluated with boundary checking
    ATTACK_SIGNATURE_PATTERNS = [
        r"\bbrute\b", r"\bcve-\d{4}-\d+\b", r"\bexploit\b", r"\bunauthorized\b",
        r"\bscan\b", r"\bpowershell\b", r"\bbackdoor\b", r"\bmimikatz\b",
        r"\bchisel\b", r"\bransomware\b", r"\bsql injection\b", r"\bxss\b"
    ]

    PRIVILEGED_USERS = {"root", "admin", "administrator", "system", "sa"}

    @classmethod
    def normalize(cls, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        source_type = raw_event.get("source_type", "Unknown")
        telemetry_origin = raw_event.get("telemetry_origin") or cls._infer_telemetry_origin(source_type, raw_event)
        event_type = raw_event.get("event_type", "security_anomaly")

        # Sanitize and validate IP addresses using IPClassifier
        source_ip = IPClassifier.sanitize_ip(raw_event.get("source_ip"))
        destination_ip = IPClassifier.sanitize_ip(raw_event.get("destination_ip"))

        # Sanitize Ports
        source_port = cls._sanitize_port(raw_event.get("source_port"))
        destination_port = cls._sanitize_port(raw_event.get("destination_port"))

        # Sanitize Username
        raw_user = raw_event.get("username")
        if raw_user is not None:
            user_clean = str(raw_user).strip()
            username = user_clean if user_clean else None
        else:
            username = None

        # Detailed Description Synthesis (never leave ambiguous "Security Event Detected")
        raw_desc = (raw_event.get("description") or "").strip()
        if not raw_desc or raw_desc.lower() in ("security event detected", "security event", "security anomaly", "event", "alert"):
            description = cls._synthesize_detailed_description(
                raw_event, event_type, source_type, source_ip, destination_ip, source_port, destination_port, username
            )
        else:
            description = raw_desc

        # Normalize Timestamp and explicitly identify validity
        timestamp, is_valid_timestamp = cls._normalize_timestamp(raw_event.get("timestamp"))

        # Determine true public external exposure
        is_external = IPClassifier.is_public_ip(source_ip)

        # Check for attack signatures with word-boundary matching to prevent false positives
        desc_lower = description.lower()
        is_known_signature = any(
            re.search(pat, desc_lower) for pat in cls.ATTACK_SIGNATURE_PATTERNS
        )

        # Check privileged user context
        is_privileged = bool(username and username.lower() in cls.PRIVILEGED_USERS)

        # Map MITRE ATT&CK technique
        mitre_technique = raw_event.get("mitre_technique") or MitreMapper.map_event(event_type, description)

        # Calculate Risk Score & Severity
        raw_level = raw_event.get("rule_level") or raw_event.get("suricata_severity")
        risk_score, severity, _ = RiskEngine.calculate_risk(
            event_type=event_type,
            source_type=source_type,
            raw_level=raw_level,
            frequency_count=raw_event.get("frequency_count", 1),
            is_external_ip=is_external,
            is_known_attack_signature=is_known_signature,
            is_privileged_user=is_privileged
        )

        raw_log = raw_event.get("raw_log")
        if not is_valid_timestamp:
            raw_log = f"[INVALID_TIMESTAMP_DETECTED: original='{raw_event.get('timestamp')}']\n{raw_log or ''}".strip()

        return {
            "timestamp": timestamp,
            "is_valid_timestamp": is_valid_timestamp,
            "source_type": source_type,
            "telemetry_origin": telemetry_origin,
            "event_type": event_type,
            "description": description,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "username": username,
            "severity": severity,
            "risk_score": risk_score,
            "mitre_technique": mitre_technique,
            "status": "OPEN",
            "raw_log": raw_log
        }

    @staticmethod
    def _infer_telemetry_origin(source_type: str, raw_event: Dict[str, Any]) -> str:
        desc = (raw_event.get("description") or "").upper()
        if "[TEST DRILL]" in desc or "DRILL EVENT" in (raw_event.get("raw_log") or ""):
            return "SECURITY_DRILL"
        st = source_type.lower()
        if "host" in st or "sensor" in st:
            return "HOST_TELEMETRY"
        if "simulator" in st:
            return "SIMULATED_DEMO"
        return "HISTORICAL_LOG"

    @classmethod
    def _normalize_timestamp(cls, ts_val: Any) -> Tuple[datetime, bool]:
        """
        Parses multi-format timestamps.
        Returns a tuple: (normalized_utc_datetime, is_valid_timestamp_boolean).
        Invalid or missing timestamps are explicitly identified with is_valid=False.
        """
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                return ts_val.replace(tzinfo=timezone.utc), True
            return ts_val.astimezone(timezone.utc), True

        # Check numeric epoch timestamps
        if isinstance(ts_val, (int, float)):
            try:
                # 13 digits = milliseconds epoch
                if ts_val > 1e11:
                    return datetime.fromtimestamp(ts_val / 1000.0, tz=timezone.utc), True
                return datetime.fromtimestamp(ts_val, tz=timezone.utc), True
            except (ValueError, OverflowError, OSError):
                return datetime.now(timezone.utc), False

        if not ts_val or not isinstance(ts_val, str):
            return datetime.now(timezone.utc), False

        ts_str = ts_val.strip()
        if not ts_str:
            return datetime.now(timezone.utc), False

        # Numeric epoch string
        if ts_str.isdigit():
            try:
                val = int(ts_str)
                if val > 1e11:
                    return datetime.fromtimestamp(val / 1000.0, tz=timezone.utc), True
                return datetime.fromtimestamp(val, tz=timezone.utc), True
            except Exception:
                pass

        # 1. ISO 8601 with or without Z
        iso_str = ts_str
        if iso_str.endswith("Z"):
            iso_str = iso_str[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc), True
        except ValueError:
            pass

        # 2. RFC 2822 / Email format (e.g. "Mon, 20 Oct 2026 01:30:39 +0000")
        try:
            dt = email.utils.parsedate_to_datetime(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc), True
        except Exception:
            pass

        # 3. Apache / Nginx Combined Log format: "10/Sep/2026:10:00:00 +0000"
        for fmt in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc), True
            except ValueError:
                pass

        # 4. Syslog format (e.g. "Sep 10 10:00:00" or "Oct 20 01:30:39")
        try:
            current_year = datetime.now(timezone.utc).year
            dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt, True
        except ValueError:
            pass

        # Parsing failed -> explicitly return fallback with is_valid=False
        return datetime.now(timezone.utc), False

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

    @classmethod
    def _synthesize_detailed_description(
        cls,
        raw_event: Dict[str, Any],
        event_type: str,
        source_type: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
        source_port: Optional[int],
        destination_port: Optional[int],
        username: Optional[str]
    ) -> str:
        """Synthesizes an explicit, context-rich description when raw event description is vague or missing."""
        clean_type = event_type.replace("_", " ").title()
        details = []

        if username:
            details.append(f"targeting user account '{username}'")
        if source_ip and destination_ip:
            details.append(f"from host {source_ip} to destination {destination_ip}")
        elif source_ip:
            details.append(f"originating from source IP {source_ip}")
        elif destination_ip:
            details.append(f"directed towards destination IP {destination_ip}")

        if destination_port:
            details.append(f"on destination port {destination_port}")
        elif source_port:
            details.append(f"via port {source_port}")

        proc = raw_event.get("process_name") or raw_event.get("process")
        cmd = raw_event.get("command_line") or raw_event.get("cmd")
        if proc:
            details.append(f"involving process '{proc}'")
        elif cmd:
            details.append(f"executing command '{str(cmd)[:60]}'")

        context_str = f" ({', '.join(details)})" if details else ""
        return f"{clean_type} activity detected via {source_type}{context_str}."

