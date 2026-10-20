import math
import pytest
from app.security.mitre_mapper import MitreMapper
from app.security.risk_engine import RiskEngine
from app.config import Settings, _load_or_generate_local_credentials

# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapper Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_mitre_mapper_all_patterns():
    # Brute force variants
    assert MitreMapper.map_event("ssh_authentication_failure", "") == "T1110"
    assert MitreMapper.map_event("", "password spray attack against domain") == "T1110.001"
    assert MitreMapper.map_event("windows_successful_logon", "") == "T1078"

    # Privilege escalation & account changes
    assert MitreMapper.map_event("windows_privilege_escalation", "") == "T1098"
    assert MitreMapper.map_event("windows_account_created", "") == "T1136.001"

    # Persistence
    assert MitreMapper.map_event("persistence_startup_created", "") == "T1547.001"
    assert MitreMapper.map_event("windows_service_installed", "") == "T1543.003"
    assert MitreMapper.map_event("windows_scheduled_task", "") == "T1053.005"

    # Defense evasion
    assert MitreMapper.map_event("windows_log_cleared", "") == "T1070.001"
    assert MitreMapper.map_event("host_firewall_disabled", "") == "T1562.001"
    assert MitreMapper.map_event("masqueraded_process", "") == "T1036"

    # Discovery & Scan
    assert MitreMapper.map_event("network_scan", "") == "T1046"
    assert MitreMapper.map_event("", "inbound syn scan detected") == "T1046"
    assert MitreMapper.map_event("firewall_blocked_traffic", "") == "T1046"

    # C2 & Scripts
    assert MitreMapper.map_event("suspicious_outbound_connection", "") == "T1071"
    assert MitreMapper.map_event("", "malicious powershell execution") == "T1059.001"
    assert MitreMapper.map_event("windows_suspicious_process", "") == "T1059"

    # Web attacks
    assert MitreMapper.map_event("web_sql_injection", "") == "T1190"
    assert MitreMapper.map_event("web_path_traversal", "") == "T1190"
    assert MitreMapper.map_event("web_xss_attempt", "") == "T1190"
    assert MitreMapper.map_event("web_shell_probe", "") == "T1505.003"
    assert MitreMapper.map_event("web_scanner_activity", "") == "T1595"

    # Resource Hijacking & Elevation
    assert MitreMapper.map_event("cryptominer_detected", "") == "T1496"
    assert MitreMapper.map_event("sudo_command_execution", "") == "T1548"
    assert MitreMapper.map_event("", "attempted uac bypass on endpoint") == "T1548"
    assert MitreMapper.map_event("file_integrity", "") == "T1565"

    # DoS & Exploits
    assert MitreMapper.map_event("denial_of_service", "") == "T1498"
    assert MitreMapper.map_event("", "exploit attempt targeting cve-2023-1234") == "T1190"

    # Unmapped fallback
    assert MitreMapper.map_event("benign_random_event", "normal benign description") is None

def test_mitre_mapper_details_and_urls():
    assert MitreMapper.get_details(None) is None
    assert MitreMapper.get_url(None) is None

    # Known technique
    details = MitreMapper.get_details("T1110")
    assert details is not None
    assert "Brute Force" in details["name"]
    assert MitreMapper.get_url("T1110") == "https://attack.mitre.org/techniques/T1110/"

    # Unregistered technique format fallback
    fallback_url = MitreMapper.get_url("T9999.001")
    assert fallback_url == "https://attack.mitre.org/techniques/T9999/001/"

    # Non-technique format
    assert MitreMapper.get_url("INVALID") is None

# ---------------------------------------------------------------------------
# Risk Scoring Engine Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_risk_scoring_wazuh_and_suricata_modifiers():
    engine = RiskEngine()

    # Wazuh levels: 12 (base >= 70), 8 (base >= 50), 5 (base >= 35)
    r12, _, _ = engine.calculate_risk("unknown_event", source_type="wazuh", raw_level="12")
    r8, _, _ = engine.calculate_risk("unknown_event", source_type="wazuh", raw_level="8")
    r5, _, _ = engine.calculate_risk("unknown_event", source_type="wazuh", raw_level="5")
    rinv, _, _ = engine.calculate_risk("unknown_event", source_type="wazuh", raw_level="not-a-number")
    assert r12 >= 70
    assert r8 >= 50
    assert r5 >= 35
    assert rinv >= 20

    # Suricata severities: 1 (base >= 65), 2 (base >= 45), 3 (base >= 25)
    s1, _, _ = engine.calculate_risk("unknown_event", source_type="suricata", raw_level="1")
    s2, _, _ = engine.calculate_risk("unknown_event", source_type="suricata", raw_level="2")
    s3, _, _ = engine.calculate_risk("unknown_event", source_type="suricata", raw_level="3")
    sinv, _, _ = engine.calculate_risk("unknown_event", source_type="suricata", raw_level="bad-input")
    assert s1 >= 65
    assert s2 >= 45
    assert s3 >= 25
    assert sinv >= 20

def test_risk_scoring_confidence_frequency_and_bounds():
    engine = RiskEngine()

    # NaN / Inf confidence
    r_nan, _, _ = engine.calculate_risk("port_scan", detection_confidence=float("nan"))
    r_inf, _, _ = engine.calculate_risk("port_scan", detection_confidence=float("inf"))
    r_norm, _, _ = engine.calculate_risk("port_scan", detection_confidence=0.8)
    assert r_nan <= r_norm
    assert r_inf <= r_norm

    # Frequency modifiers
    r_freq35, _, _ = engine.calculate_risk("ssh_authentication_failure", frequency_count=35)
    r_freq15, _, _ = engine.calculate_risk("ssh_authentication_failure", frequency_count=15)
    r_freq6, _, _ = engine.calculate_risk("ssh_authentication_failure", frequency_count=6)
    r_freq2, _, _ = engine.calculate_risk("ssh_authentication_failure", frequency_count=2)
    r_freq_bad, _, _ = engine.calculate_risk("ssh_authentication_failure", frequency_count="bad")
    assert r_freq35 > r_freq15 > r_freq6 > r_freq2 >= r_freq_bad

    # Privilege and Dampener
    r_priv, _, _ = engine.calculate_risk("port_scan", is_privileged_user=True)
    r_damp, _, _ = engine.calculate_risk("port_scan", is_benign_internal_context=True)
    assert r_priv > r_damp

    # Clamping bounds: [0, 100]
    r_high, _, _ = engine.calculate_risk("host_ransomware_activity", frequency_count=100, is_external_ip=True, is_privileged_user=True, detection_confidence=1.0)
    assert 0 <= r_high <= 100
    r_low, _, _ = engine.calculate_risk("unknown_event", is_benign_internal_context=True)
    assert 0 <= r_low <= 100

# ---------------------------------------------------------------------------
# Configuration & Production Security Validation Tests
# ---------------------------------------------------------------------------

def test_config_production_strict_validations(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "short")
    with pytest.raises(RuntimeError, match="SECRET_KEY must be set to a secure string"):
        Settings()

    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("AUTH_ENABLED", "false")
    with pytest.raises(RuntimeError, match="AUTH_ENABLED cannot be disabled when ENVIRONMENT is set to 'production'"):
        Settings()

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("ADMIN_API_KEY", "default-admin-key")
    with pytest.raises(RuntimeError, match="ADMIN_API_KEY must be set to a secure value in production"):
        Settings()

    monkeypatch.setenv("ADMIN_API_KEY", "secure-admin-token-1234567890")
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")
    with pytest.raises(RuntimeError, match="Wildcard '\\*' in ALLOWED_ORIGINS is prohibited"):
        Settings()

def test_load_or_generate_local_credentials(tmp_path):
    creds = _load_or_generate_local_credentials(tmp_path)
    assert "admin_key" in creds
    assert "secret_key" in creds
    assert creds["is_first_run"] is True

    # Loading existing credentials
    creds2 = _load_or_generate_local_credentials(tmp_path)
    assert creds2["admin_key"] == creds["admin_key"]
    assert creds2["secret_key"] == creds["secret_key"]
