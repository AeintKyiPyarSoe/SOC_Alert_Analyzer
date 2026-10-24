#!/usr/bin/env python3
"""
SOC Alert Analyzer — Realistic Endpoint Attack Evaluation Benchmark Runner

Evaluates detection heuristics against realistic Sysmon and Windows Event logs
spanning initial access, defense evasion, credential dumping, persistence,
lateral movement, command & control, and benign workflows.

Usage:
  python scripts/evaluate_endpoint_attacks.py
"""

import sys
import json
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security.endpoint_attack_evaluator import (
    EndpointAttackEvaluator,
    BENCHMARK_VERSION
)


def main():
    print(f"SOC Alert Analyzer — Endpoint Attack Telemetry Evaluation Runner (v{BENCHMARK_VERSION})")
    print("=========================================================================================")

    evaluator = EndpointAttackEvaluator()
    report = evaluator.run_benchmark()

    m = report["metrics"]
    total = report["total_scenarios"]

    print(f"\n{'='*70}")
    print("  EVALUATION RESULTS: REALISTIC SYSMON & WINDOWS EVENT LOGS")
    print(f"{'='*70}")
    print(f"  Total Scenarios Evaluated : {total}")
    print(f"  True Positives (TP)       : {m['true_positives']}")
    print(f"  False Positives (FP)      : {m['false_positives']}")
    print(f"  True Negatives (TN)       : {m['true_negatives']}")
    print(f"  False Negatives (FN)      : {m['false_negatives']}")
    print("  -------------------------------------------------------------")
    print(f"  Precision                 : {m['precision']:.4f} ({m['precision']*100:.1f}%)")
    print(f"  Recall (Sensitivity)      : {m['recall']:.4f} ({m['recall']*100:.1f}%)")
    print(f"  Specificity               : {m['specificity']:.4f} ({m['specificity']*100:.1f}%)")
    print(f"  F1 Score                  : {m['f1_score']:.4f} ({m['f1_score']*100:.1f}%)")
    print(f"  False Positive Rate (FPR) : {m['false_positive_rate']:.4f} ({m['false_positive_rate']*100:.1f}%)")
    print(f"  Accuracy                  : {m['accuracy']:.4f} ({m['accuracy']*100:.1f}%)")
    print(f"  MITRE Technique Match Acc : {m['mitre_technique_match_accuracy']:.4f} ({m['mitre_technique_match_accuracy']*100:.1f}%)")
    print(f"  MITRE Mismatches Count    : {len(m['mitre_technique_mismatches'])}")
    print(f"{'='*70}")

    print("\n  CONFUSION MATRIX:")
    print("  +-----------------------------+-----------------------------+")
    print("  |                             |        ACTUAL CLASS         |")
    print("  |                             |   Malicious   |   Benign    |")
    print("  +-----------------------------+---------------+-------------+")
    print(f"  | PREDICTED | Detected Threat | TP = {m['true_positives']:<8} | FP = {m['false_positives']:<7} |")
    print(f"  |   CLASS   | Benign / Passed | FN = {m['false_negatives']:<8} | TN = {m['true_negatives']:<7} |")
    print("  +-----------------------------+---------------+-------------+\n")

    json_report_path = Path(__file__).resolve().parent.parent / "docs" / "endpoint_attack_evaluation_report.json"
    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Machine-readable evaluation report saved to {json_report_path}")

    # Enforce quality gates
    assert m["false_positives"] == 0, f"Quality gate failure: Expected 0 FP, got {m['false_positives']}"
    assert m["false_negatives"] == 0, f"Quality gate failure: Expected 0 FN, got {m['false_negatives']}"
    print("[+] All endpoint attack evaluation checks PASSED successfully.")


if __name__ == "__main__":
    main()
