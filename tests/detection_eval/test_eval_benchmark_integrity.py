import os
import json
import tempfile
from app.security.detection_benchmark import (
    BASELINE_SCENARIOS,
    HELDOUT_SCENARIOS,
    check_dataset_overlap,
    run_full_benchmark,
    BENCHMARK_VERSION
)


def test_benchmark_dataset_integrity_and_sample_counts():
    """Verify exact counts and ground truth distributions."""
    assert len(BASELINE_SCENARIOS) == 20
    assert len(HELDOUT_SCENARIOS) == 30

    dev_mal = [s for s in BASELINE_SCENARIOS if s.is_malicious]
    dev_ben = [s for s in BASELINE_SCENARIOS if not s.is_malicious]
    assert len(dev_mal) == 10
    assert len(dev_ben) == 10

    eval_mal = [s for s in HELDOUT_SCENARIOS if s.is_malicious]
    eval_ben = [s for s in HELDOUT_SCENARIOS if not s.is_malicious]
    assert len(eval_mal) == 15
    assert len(eval_ben) == 15

    for s in BASELINE_SCENARIOS + HELDOUT_SCENARIOS:
        assert s.scenario_id, "Scenario ID must not be empty"
        assert s.rationale, f"Scenario {s.scenario_id} missing documented rationale"
        assert s.family, f"Scenario {s.scenario_id} missing family classification"
        if s.is_malicious:
            assert s.mitre_technique, f"Malicious scenario {s.scenario_id} missing MITRE mapping"


def test_benchmark_zero_data_leakage_and_overlap():
    """Ensure zero overlap between development and held-out benchmark datasets."""
    overlaps = check_dataset_overlap(BASELINE_SCENARIOS, HELDOUT_SCENARIOS)
    assert len(overlaps) == 0, f"Found unintended dataset overlap: {overlaps}"


def test_full_benchmark_execution_and_json_report():
    """Verify execution and JSON artifact generation."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    try:
        report = run_full_benchmark(output_json_path=temp_path)
        assert report["benchmark_version"] == BENCHMARK_VERSION
        assert report["overall_summary"]["total_support"] == 50
        assert report["overall_summary"]["false_positives"] == 0
        assert report["overall_summary"]["false_negatives"] == 0
        assert report["overall_summary"]["accuracy"] == 1.0

        assert os.path.exists(temp_path)
        with open(temp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["benchmark_version"] == BENCHMARK_VERSION
        assert "overall_summary" in data
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
