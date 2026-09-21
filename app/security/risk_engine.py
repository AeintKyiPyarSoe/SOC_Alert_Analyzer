from typing import Dict, Any, Tuple

class RiskEngine:
    """
    Explainable, rule-based cybersecurity risk calculation engine.
    Standardizes threat assessment on a 0-100 scale across 4 severity tiers:
      - 0 to 24:   LOW
      - 25 to 49:  MEDIUM
      - 50 to 74:  HIGH
      - 75 to 100: CRITICAL
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
        event_type: str,
        source_type: str,
        raw_level: Any = None,
        frequency_count: int = 1,
        is_external_ip: bool = True,
        is_known_attack_signature: bool = False
    ) -> Tuple[int, str, Dict[str, Any]]:
        """
        Computes risk score, severity band, and transparent contributing factors.
        """
        # 1. Base Score
        base = cls.BASE_SEVERITY_MAP.get(event_type.lower(), 30)

        # Incorporate tool-specific severity hints if available
        if source_type == "Wazuh" and raw_level is not None:
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
        elif source_type == "Suricata" and raw_level is not None:
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
        frequency_mod = 0
        if frequency_count >= 30:
            frequency_mod = 30
        elif frequency_count >= 10:
            frequency_mod = 20
        elif frequency_count >= 5:
            frequency_mod = 10
        elif frequency_count > 1:
            frequency_mod = 5

        # 3. Attack Confidence Modifier
        confidence_mod = 10 if is_known_attack_signature else 0

        # 4. External IP Exposure Modifier
        asset_mod = 5 if is_external_ip else 0

        total_score = min(100, max(0, base + frequency_mod + confidence_mod + asset_mod))
        severity = cls.get_severity_level(total_score)

        breakdown = {
            "base_severity": base,
            "frequency_modifier": frequency_mod,
            "confidence_modifier": confidence_mod,
            "network_exposure_modifier": asset_mod,
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
