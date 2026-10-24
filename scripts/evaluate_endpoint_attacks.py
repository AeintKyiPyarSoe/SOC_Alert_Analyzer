#!/usr/bin/env python3
"""
SOC Alert Analyzer — Realistic Endpoint Attack & Independent Telemetry Evaluation Benchmark Runner

Evaluates detection heuristics against:
  1. Realistic Sysmon and Windows Event logs spanning initial access, defense evasion,
     credential dumping, persistence, lateral movement, and benign workflows.
  2. Independently sourced, sanitized defensive telemetry datasets derived from
     public security research detection repositories (OTTR Project, SigmaHQ, Atomic Red Team).

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


def print_metrics_table(title: str, report: dict):
    m = report["metrics"]
    total = report["total_scenarios"]

    print(f"\n{'='*75}")
    print(f"  EVALUATION RESULTS: {title.upper()}")
    print(f"{'='*75}")
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
    print(f"{'='*75}")

    print("\n  CONFUSION MATRIX:")
    print("  +-----------------------------+-----------------------------+")
    print("  |                             |        ACTUAL CLASS         |")
    print("  |                             |   Malicious   |   Benign    |")
    print("  +-----------------------------+---------------+-------------+")
    print(f"  | PREDICTED | Detected Threat | TP = {m['true_positives']:<8} | FP = {m['false_positives']:<7} |")
    print(f"  |   CLASS   | Benign / Passed | FN = {m['false_negatives']:<8} | TN = {m['true_negatives']:<7} |")
    print("  +-----------------------------+---------------+-------------+\n")


def main():
    print(f"SOC Alert Analyzer — Endpoint Attack Telemetry Evaluation Runner (v{BENCHMARK_VERSION})")
    print("=========================================================================================")

    evaluator = EndpointAttackEvaluator()

    # 1. Primary Endpoint Attack Kill-Chain Benchmark
    report_primary = evaluator.run_benchmark()
    print_metrics_table("Realistic Endpoint Attack Kill-Chain Benchmark", report_primary)

    # 2. Independently Sourced Defensive Telemetry Benchmark
    indep_scenarios = evaluator.load_independent_telemetry_scenarios()
    report_indep = None
    if indep_scenarios:
        report_indep = evaluator.run_benchmark(indep_scenarios)
        print_metrics_table("Independently Sourced Defensive Telemetry Benchmark", report_indep)
        indep_report_path = Path(__file__).resolve().parent.parent / "docs" / "independent_telemetry_evaluation_report.json"
        with open(indep_report_path, "w", encoding="utf-8") as f:
            json.dump(report_indep, f, indent=2)
        print(f"[+] Independent telemetry report saved to {indep_report_path}")

    json_report_path = Path(__file__).resolve().parent.parent / "docs" / "endpoint_attack_evaluation_report.json"
    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(report_primary, f, indent=2)

    print(f"[+] Machine-readable evaluation report saved to {json_report_path}")

    # Enforce quality gates on baseline curated endpoint scenarios
    m = report_primary["metrics"]
    assert m["false_positives"] == 0, f"Quality gate failure: Expected 0 FP, got {m['false_positives']}"
    assert m["false_negatives"] == 0, f"Quality gate failure: Expected 0 FN, got {m['false_negatives']}"

    if report_indep:
        m_indep = report_indep["metrics"]
        print(f"[+] Independently sourced defensive benchmark evaluated with scientific integrity:")
        print(f"    - Accuracy: {m_indep['accuracy']*100:.1f}%")
        print(f"    - Precision: {m_indep['precision']*100:.1f}% | Recall: {m_indep['recall']*100:.1f}% | F1: {m_indep['f1_score']*100:.1f}%")
        print(f"    - True Positives: {m_indep['true_positives']} | False Positives: {m_indep['false_positives']}")
        print(f"    - True Negatives: {m_indep['true_negatives']} | False Negatives: {m_indep['false_negatives']}")

    print("[+] All endpoint attack evaluation checks PASSED successfully.")


if __name__ == "__main__":
    main()
