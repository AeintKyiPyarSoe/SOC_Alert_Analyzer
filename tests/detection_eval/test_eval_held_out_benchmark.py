from unittest.mock import MagicMock
from app.security.host_sensor import HostSecuritySensor
from app.security.detection_benchmark import (
    HELDOUT_SCENARIOS,
    evaluate_dataset
)


def create_mock_proc(pid, name, exe, cmdline, parent_name=None):
    p = MagicMock()
    p.pid = pid
    p.name.return_value = name
    p.exe.return_value = exe
    p.cmdline.return_value = cmdline
    p.username.return_value = "SYSTEM"

    if parent_name:
        parent = MagicMock()
        parent.name.return_value = parent_name
        p.parent.return_value = parent
    else:
        p.parent.return_value = None
    return p


def test_held_out_behavioral_evaluation_benchmark():
    """
    Evaluates detection rules against a dedicated, held-out benchmark dataset of
    30 process execution scenarios (15 malicious and 15 difficult benign edge cases).
    
    Computes and asserts:
      - True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
      - Precision, Recall, F1 Score, Accuracy, and False Positive Rate (FPR).
    
    This benchmark is maintained separately from development unit tests to assess
    generalization and resistance to false alarms on complex administrative and developer workflows.
    """
    res = evaluate_dataset("Held-Out Benchmark", HELDOUT_SCENARIOS)

    # Verification on held-out benchmark
    assert res["true_positives"] == 15, f"Expected 15 True Positives, got {res['true_positives']}"
    assert res["false_positives"] == 0, f"Expected 0 False Positives, got {res['false_positives']}"
    assert res["false_negatives"] == 0, f"Expected 0 False Negatives, got {res['false_negatives']}"
    assert res["true_negatives"] == 15, f"Expected 15 True Negatives, got {res['true_negatives']}"

    assert res["precision"] == 1.0, f"Precision should be 1.0, got {res['precision']}"
    assert res["recall"] == 1.0, f"Recall should be 1.0, got {res['recall']}"
    assert res["f1_score"] == 1.0, f"F1 Score should be 1.0, got {res['f1_score']}"
    assert res["false_positive_rate"] == 0.0, f"False Positive Rate should be 0.0, got {res['false_positive_rate']}"
    assert res["accuracy"] == 1.0, f"Accuracy should be 1.0, got {res['accuracy']}"


def test_held_out_ambiguous_and_duplicate_handling():
    """
    Verifies that the detection engine handles duplicate process observations
    and suppresses redundant alerts via seen_signatures tracking.
    """
    sensor = HostSecuritySensor()
    sensor.seen_signatures.clear()

    # Create mock process
    proc = create_mock_proc(6001, "mimikatz.exe", "C:\\Tools\\mimikatz.exe", ["mimikatz.exe"])

    # First observation should produce an alert event
    first_events = sensor._analyze_single_process(proc)
    assert len(first_events) == 1, "First observation should produce alert"

    # Immediate second observation of identical process must be deduplicated
    second_events = sensor._analyze_single_process(proc)
    assert len(second_events) == 0, "Duplicate observation must be suppressed by signature deduplication"
