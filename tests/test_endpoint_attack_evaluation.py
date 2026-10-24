"""
Tests for realistic endpoint attack evaluation benchmark using Sysmon and Windows Event logs.
Verifies detection accuracy, MITRE ATT&CK technique mapping, and 0 False Positives on benign activity.
"""

from app.security.endpoint_attack_evaluator import (
    EndpointAttackEvaluator,
    ENDPOINT_SCENARIOS
)


def test_endpoint_attack_evaluation_benchmark():
    """Verify that all realistic endpoint attacks and benign scenarios achieve 100% accuracy."""
    evaluator = EndpointAttackEvaluator()
    report = evaluator.run_benchmark(ENDPOINT_SCENARIOS)

    m = report["metrics"]
    assert m["false_positives"] == 0, f"Expected 0 False Positives, got {m['false_positives']}"
    assert m["false_negatives"] == 0, f"Expected 0 False Negatives, got {m['false_negatives']}"
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["accuracy"] == 1.0
    assert report["total_scenarios"] == 18


def test_individual_endpoint_attack_scenarios():
    """Verify specific realistic attack detections and MITRE technique classifications."""
    evaluator = EndpointAttackEvaluator()

    # Scenario 1: Certutil cradle -> T1105
    certutil_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_01_certutil_cradle")
    res1 = evaluator.evaluate_scenario(certutil_sc)
    assert res1["detected"] is True
    assert res1["detected_technique"] == "T1105"

    # Scenario 6: Mimikatz LSASS Dump -> T1003.001
    mimikatz_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_06_mimikatz_lsass_dump")
    res6 = evaluator.evaluate_scenario(mimikatz_sc)
    assert res6["detected"] is True
    assert res6["detected_technique"] == "T1003.001"

    # Scenario 7: Registry Run Key -> T1547.001
    run_key_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_07_registry_run_key")
    res7 = evaluator.evaluate_scenario(run_key_sc)
    assert res7["detected"] is True
    assert res7["detected_technique"] == "T1547.001"

    # Benign Scenario: TrustedInstaller -> 0 FP, risk < 40
    trusted_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "benign_01_trustedinstaller")
    res_b1 = evaluator.evaluate_scenario(trusted_sc)
    assert res_b1["detected"] is False
    assert res_b1["risk_score"] < 40
