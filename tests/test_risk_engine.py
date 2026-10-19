from app.security.risk_engine import RiskEngine

def test_risk_scoring_bounds():
    score, sev, breakdown = RiskEngine.calculate_risk(
        event_type="ssh_authentication_failure",
        source_type="Linux_Auth",
        frequency_count=1,
        is_external_ip=False
    )
    assert 0 <= score <= 100
    assert sev == RiskEngine.get_severity_level(score)

def test_severity_tier_thresholds():
    assert RiskEngine.get_severity_level(10) == "LOW"
    assert RiskEngine.get_severity_level(24) == "LOW"
    assert RiskEngine.get_severity_level(25) == "MEDIUM"
    assert RiskEngine.get_severity_level(49) == "MEDIUM"
    assert RiskEngine.get_severity_level(50) == "HIGH"
    assert RiskEngine.get_severity_level(74) == "HIGH"
    assert RiskEngine.get_severity_level(75) == "CRITICAL"
    assert RiskEngine.get_severity_level(100) == "CRITICAL"

def test_burst_frequency_escalation():
    # 1 attempt
    score_1, _, _ = RiskEngine.calculate_risk("ssh_authentication_failure", "Linux_Auth", frequency_count=1)
    # 35 attempts
    score_35, sev_35, breakdown_35 = RiskEngine.calculate_risk("ssh_authentication_failure", "Linux_Auth", frequency_count=35)
    
    assert score_35 > score_1
    assert breakdown_35["frequency_modifier"] == 30
    assert sev_35 in ["HIGH", "CRITICAL"]

def test_privilege_context_and_confidence_modifiers():
    # Standard user
    score_std, _, b_std = RiskEngine.calculate_risk(
        event_type="windows_failed_logon",
        source_type="Windows_Event",
        is_privileged_user=False
    )
    # Privileged account (e.g. Administrator/root)
    score_priv, _, b_priv = RiskEngine.calculate_risk(
        event_type="windows_failed_logon",
        source_type="Windows_Event",
        is_privileged_user=True
    )
    assert score_priv == score_std + 10
    assert b_priv["privilege_modifier"] == 10

def test_false_positive_dampener():
    # Base risk for suspicious command
    score_base, _, _ = RiskEngine.calculate_risk(
        event_type="suspicious_command",
        source_type="Host_Process_Sensor",
        is_benign_internal_context=False
    )
    # Verified benign context (e.g. dev build script in loopback)
    score_dampened, _, b_damp = RiskEngine.calculate_risk(
        event_type="suspicious_command",
        source_type="Host_Process_Sensor",
        is_benign_internal_context=True
    )
    assert score_dampened < score_base
    assert b_damp["false_positive_dampener"] == 20

def test_exact_severity_boundaries():
    assert RiskEngine.get_severity_level(0) == "LOW"
    assert RiskEngine.get_severity_level(24) == "LOW"
    assert RiskEngine.get_severity_level(25) == "MEDIUM"
    assert RiskEngine.get_severity_level(49) == "MEDIUM"
    assert RiskEngine.get_severity_level(50) == "HIGH"
    assert RiskEngine.get_severity_level(74) == "HIGH"
    assert RiskEngine.get_severity_level(75) == "CRITICAL"
    assert RiskEngine.get_severity_level(100) == "CRITICAL"

def test_risk_breakdown_arithmetic_sum():
    score, sev, b = RiskEngine.calculate_risk(
        event_type="ssh_authentication_failure",
        source_type="Linux_Auth",
        frequency_count=15,
        is_external_ip=True,
        is_known_attack_signature=True,
        is_privileged_user=True,
        is_benign_internal_context=False
    )
    expected_sum = (
        b["base_severity"]
        + b["frequency_modifier"]
        + b["confidence_modifier"]
        + b["network_exposure_modifier"]
        + b["privilege_modifier"]
        - b["false_positive_dampener"]
    )
    assert score == min(100, max(0, expected_sum))
    assert b["final_score"] == score

def test_risk_clamping_extremes():
    # Extreme upper bound (theoretical sum > 100)
    score_max, sev_max, _ = RiskEngine.calculate_risk(
        event_type="web_sql_injection",  # base 80
        source_type="Wazuh",
        raw_level=15,
        frequency_count=50,             # +30
        is_external_ip=True,            # +5
        is_known_attack_signature=True, # +10
        is_privileged_user=True         # +10 => raw total = 135
    )
    assert score_max == 100
    assert sev_max == "CRITICAL"

    # Extreme lower bound (raw total < 0)
    score_min, sev_min, _ = RiskEngine.calculate_risk(
        event_type="ssh_login_successful", # base 15
        source_type="Linux_Auth",
        frequency_count=1,
        is_external_ip=False,
        is_benign_internal_context=True    # -20 => raw total = -5
    )
    assert score_min == 0
    assert sev_min == "LOW"

