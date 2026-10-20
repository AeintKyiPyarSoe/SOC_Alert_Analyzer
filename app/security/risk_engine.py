import math
from typing import Dict, Any, Tuple, Optional

class RiskEngine:
    """
    Explainable, deterministic rule-based cybersecurity risk calculation engine.
    Standardizes threat assessment on a 0-100 scale across 4 severity tiers:
      - 0 to 24:   LOW
      - 25 to 49:  MEDIUM
      - 50 to 74:  HIGH
      - 75 to 100: CRITICAL

    The scoring formula incorporates:
      1. Baseline Event Severity (0-100 based on MITRE tactic / impact)
      2. Tool Rule Level Escalation (Wazuh levels 0-15, Suricata 1-4)
      3. Frequency / Burst Multiplier (detecting brute-force & distributed scans)
      4. Attack Signature Confidence (known CVEs, exploits, LOLBin signatures)
      5. Network Asset Exposure (public internet vs internal RFC 1918 vs loopback)
      6. User Account Privilege Context (targeting root / Administrator)
      7. False Positive Dampeners (mitigating routine administrative or loopback tasks)
    """

    # Base severities by event type (0-100 scale baseline)
    BASE_SEVERITY_MAP: Dict[str, int] = {
        # Authentication & Credential Access
        "ssh_authentication_failure": 45,
        "ssh_invalid_user": 50,
        "ssh_login_successful": 15,
        "windows_failed_logon": 45,
        "windows_successful_logon": 15,
        "windows_account_created": 45,
        "windows_privilege_escalation": 65,
        # Execution & Defense Evasion
        "windows_suspicious_process": 65,
        "suspicious_process": 65,
        "suspicious_command": 60,
        "powershell_script_block": 60,
        "masqueraded_process": 70,
        "windows_log_cleared": 80,
        "host_firewall_disabled": 70,
        "windows_defender_threat": 75,
        "windows_defender_action": 45,
        "cryptominer_detected": 75,
        # Persistence
        "windows_service_installed": 55,
        "windows_scheduled_task": 50,
        "persistence_startup_created": 70,
        "file_integrity_change": 25,
        # Discovery & Network
        "network_scan": 35,
        "insecure_listening_port": 40,
        "suspicious_outbound_connection": 60,
        "firewall_blocked_traffic": 35,
        "network_anomaly": 25,
        # Exploits & Web Attacks
        "exploit_attempt": 75,
        "denial_of_service": 65,
        "web_sql_injection": 80,
        "web_xss_attempt": 60,
        "web_path_traversal": 70,
        "web_shell_probe": 75,
        "web_scanner_activity": 40,
        "web_reconnaissance": 35,
        # Other
        "sudo_command_execution": 30,
        "rootcheck_anomaly": 55,
        "wazuh_alert": 30
    }

    @classmethod
    def calculate_risk(
        cls,
        event_type: Optional[str],
        source_type: Optional[str] = None,
        raw_level: Any = None,
        frequency_count: int = 1,
        is_external_ip: bool = True,
        is_known_attack_signature: bool = False,
        detection_confidence: Optional[float] = None,
        is_privileged_user: bool = False,
        is_benign_internal_context: bool = False
    ) -> Tuple[int, str, Dict[str, Any]]:
        """
        Computes risk score, severity band, and transparent contributing factors.
        Safely handles missing, malformed, or out-of-bounds parameters.
        """
        # 1. Base Score with safe handling of missing / unexpected event types
        clean_event = str(event_type or "").strip().lower()
        base = cls.BASE_SEVERITY_MAP.get(clean_event, 30)

        # Incorporate tool-specific severity hints if available
        src_lower = str(source_type or "").strip().lower()
        if src_lower == "wazuh" and raw_level is not None:
            try:
                level = int(raw_level)
                # Wazuh levels: 0-15+
                if level >= 12:
                    base = max(base, 70)
                elif level >= 8:
                    base = max(base, 50)
                elif level >= 5:
                    base = max(base, 35)
            except (ValueError, TypeError):
                pass
        elif src_lower == "suricata" and raw_level is not None:
            try:
                suricata_sev = int(raw_level)
                # Suricata: 1=High, 2=Med, 3=Low, 4=Info
                if suricata_sev == 1:
                    base = max(base, 65)
                elif suricata_sev == 2:
                    base = max(base, 45)
                elif suricata_sev == 3:
                    base = max(base, 25)
            except (ValueError, TypeError):
                pass

        # 2. Frequency Modifier (burst / repeated activity)
        try:
            freq = max(1, int(frequency_count or 1))
        except (ValueError, TypeError):
            freq = 1

        frequency_mod = 0
        if freq >= 30:
            frequency_mod = 30
        elif freq >= 10:
            frequency_mod = 20
        elif freq >= 5:
            frequency_mod = 10
        elif freq > 1:
            frequency_mod = 5

        # 3. Attack Confidence Modifier (safely handle NaN, inf, out-of-bounds)
        if detection_confidence is not None:
            try:
                conf_val = float(detection_confidence)
                if math.isnan(conf_val) or math.isinf(conf_val):
                    confidence_mod = 0
                else:
                    clamped_conf = max(0.0, min(1.0, conf_val))
                    confidence_mod = int(round(clamped_conf * 10))
            except (ValueError, TypeError):
                confidence_mod = 0
        else:
            confidence_mod = 10 if is_known_attack_signature else 0

        # 4. External IP Exposure Modifier
        asset_mod = 5 if bool(is_external_ip) else 0

        # 5. User Account Privilege Modifier
        privilege_mod = 10 if bool(is_privileged_user) else 0

        # 6. False-Positive Dampener
        # Dampen score for verified internal maintenance / benign administrative context
        dampener_mod = 20 if bool(is_benign_internal_context) else 0

        # Calculate final clamped score [0, 100]
        raw_total = base + frequency_mod + confidence_mod + asset_mod + privilege_mod - dampener_mod
        total_score = min(100, max(0, raw_total))
        severity = cls.get_severity_level(total_score)

        breakdown = {
            "base_severity": base,
            "confidence_modifier": confidence_mod,
            "frequency_modifier": frequency_mod,
            "network_exposure_modifier": asset_mod,
            "privilege_modifier": privilege_mod,
            "false_positive_dampener": dampener_mod,
            "final_score": total_score
        }

        return total_score, severity, breakdown

    @staticmethod
    def get_severity_level(score: int) -> str:
        """Categorize 0-100 score into four standard tiers."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
