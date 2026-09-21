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
