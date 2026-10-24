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


def test_ground_truth_label_flipping_independence():
    """Prove that flipping is_malicious has ZERO effect on the predicted detection result."""
    from copy import deepcopy
    evaluator = EndpointAttackEvaluator()

    # Malicious scenario flipped to is_malicious=False
    attack_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_01_certutil_cradle")
    sc_flipped = deepcopy(attack_sc)
    sc_flipped.is_malicious = False

    orig_res = evaluator.evaluate_scenario(attack_sc)
    flipped_res = evaluator.evaluate_scenario(sc_flipped)

    assert orig_res["detected"] is True
    assert flipped_res["detected"] is True
    assert orig_res["detected_technique"] == flipped_res["detected_technique"] == "T1105"
    assert orig_res["risk_score"] == flipped_res["risk_score"]

    # Benign scenario flipped to is_malicious=True
    benign_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "benign_01_trustedinstaller")
    b_flipped = deepcopy(benign_sc)
    b_flipped.is_malicious = True

    b_orig_res = evaluator.evaluate_scenario(benign_sc)
    b_flipped_res = evaluator.evaluate_scenario(b_flipped)

    assert b_orig_res["detected"] is False
    assert b_flipped_res["detected"] is False
    assert b_orig_res["detected_technique"] is None
    assert b_flipped_res["detected_technique"] is None
    assert b_orig_res["risk_score"] == b_flipped_res["risk_score"]


def test_expected_technique_independence():
    """Prove that altering expected_technique has ZERO effect on the detected MITRE technique."""
    from copy import deepcopy
    evaluator = EndpointAttackEvaluator()

    attack_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_06_mimikatz_lsass_dump")
    sc_tampered = deepcopy(attack_sc)
    sc_tampered.expected_technique = "T9999.999"

    res = evaluator.evaluate_scenario(sc_tampered)
    assert res["detected_technique"] == "T1003.001"
    assert res["technique_match"] is False  # Ground truth mismatch correctly reported


def test_empty_and_malformed_datasets():
    """Verify robust handling of empty datasets and malformed telemetry."""
    from copy import deepcopy
    evaluator = EndpointAttackEvaluator()

    # Empty scenario list
    empty_report = evaluator.run_benchmark([])
    assert empty_report["total_scenarios"] == 0
    assert empty_report["metrics"]["true_positives"] == 0
    assert empty_report["metrics"]["accuracy"] == 0.0

    # Malformed scenario raw_event
    attack_sc = next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_01_certutil_cradle")
    malformed_sc = deepcopy(attack_sc)
    malformed_sc.raw_event = {"corrupted": "bad_data_without_id"}

    res = evaluator.evaluate_scenario(malformed_sc)
    assert res["detected"] is False
    assert "error" in res


def test_ambiguous_telemetry_does_not_become_threat():
    """Verify that ambiguous or benign event without attack indicators does not silently become a threat."""
    from app.security.endpoint_attack_evaluator import EndpointAttackScenario
    evaluator = EndpointAttackEvaluator()

    ambiguous_sc = EndpointAttackScenario(
        scenario_id="ambiguous_event",
        attack_phase="Unknown",
        is_malicious=False,
        event_id=99999,
        source_type="Windows_Event",
        raw_event={
            "Id": 99999,
            "TimeCreated": "2026-10-25T01:00:00Z",
            "Message": "Routine diagnostic event logged by system component."
        }
    )

    res = evaluator.evaluate_scenario(ambiguous_sc)
    assert res["detected"] is False
    assert res["risk_score"] < 40
    assert res["detected_technique"] is None


def test_technique_mismatch_reporting():
    """Verify that technique mismatches are explicitly tracked and reported in benchmark metrics."""
    from copy import deepcopy
    evaluator = EndpointAttackEvaluator()

    attack_sc = deepcopy(next(s for s in ENDPOINT_SCENARIOS if s.scenario_id == "attack_02_mshta_proxy"))
    attack_sc.expected_technique = "T1059"  # Deliberate mismatch (expected T1218)

    report = evaluator.run_benchmark([attack_sc])
    m = report["metrics"]
    assert m["mitre_technique_match_accuracy"] == 0.0
    assert len(m["mitre_technique_mismatches"]) == 1
    assert m["mitre_technique_mismatches"][0]["scenario_id"] == "attack_02_mshta_proxy"
    assert m["mitre_technique_mismatches"][0]["expected_technique"] == "T1059"
    assert m["mitre_technique_mismatches"][0]["detected_technique"] == "T1218"
