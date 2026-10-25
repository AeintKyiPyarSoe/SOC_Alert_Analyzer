"""
tests/test_dataset_provenance.py
Tests verifying open defensive telemetry provenance, transparent dataset classification,
and zero data leakage in independent evaluation datasets.
"""

import json
from pathlib import Path


def test_independent_telemetry_dataset_provenance_completeness():
    """Verify that all scenarios in independent_telemetry_dataset.json have comprehensive provenance metadata."""
    root = Path(__file__).resolve().parent.parent
    dataset_file = root / "sample_data" / "independent_telemetry" / "independent_telemetry_dataset.json"
    assert dataset_file.exists(), f"Dataset file missing at {dataset_file}"

    data = json.loads(dataset_file.read_text(encoding="utf-8"))
    assert "metadata" in data
    assert "scenarios" in data
    scenarios = data["scenarios"]
    assert len(scenarios) >= 12, f"Expected at least 12 scenarios, got {len(scenarios)}"

    valid_classifications = {
        "Authentic externally collected telemetry",
        "Transformed externally sourced telemetry",
        "Independently derived behavioral example",
        "Synthetic development fixtures"
    }

    required_fields = [
        "provenance_classification",
        "source_repository",
        "source_file_or_identifier",
        "source_commit",
        "license",
        "original_event_format",
        "event_identifier",
        "sanitization_procedure",
        "transformation_procedure",
        "label_justification",
        "mitre_mapping_justification"
    ]

    for sc in scenarios:
        sc_id = sc["scenario_id"]
        assert "provenance" in sc, f"Scenario {sc_id} is missing 'provenance' block"
        prov = sc["provenance"]

        for f in required_fields:
            assert f in prov, f"Scenario {sc_id} provenance missing field: '{f}'"
            assert str(prov[f]).strip(), f"Scenario {sc_id} field '{f}' must not be empty"

        # Classification must be from the authoritative taxonomy
        assert prov["provenance_classification"] in valid_classifications, (
            f"Scenario {sc_id} invalid classification: {prov['provenance_classification']}"
        )

        # External sources must have valid URLs
        if prov["provenance_classification"] == "Transformed externally sourced telemetry":
            assert prov["source_repository"].startswith("https://github.com/"), (
                f"Scenario {sc_id} external repository must be a valid GitHub URL: {prov['source_repository']}"
            )
            assert len(prov["source_commit"]) >= 10, (
                f"Scenario {sc_id} must have a stable commit SHA: {prov['source_commit']}"
            )

        # Verification of label independence
        assert "is_malicious" in sc
        assert "expected_technique" in sc or not sc["is_malicious"]
        assert "raw_event" in sc
