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
