#!/usr/bin/env python3
"""
SOC Alert Analyzer — Empirical Detection Evaluation & Benchmark Runner

Executes reproducible detection accuracy benchmarks across:
  1. Development Baseline Dataset (20 curated synthetic scenarios)
  2. Held-Out Evaluation Benchmark Dataset (30 challenging scenarios including difficult benign workflows)

Usage:
  python scripts/evaluate_detection.py
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security.detection_benchmark import (
    BENCHMARK_VERSION,
    run_full_benchmark
)


def print_dataset_table(res):
    name = res["name"]
    total = res["support"]
    tp = res["true_positives"]
    fp = res["false_positives"]
    tn = res["true_negatives"]
    fn = res["false_negatives"]
    precision = res["precision"]
    recall = res["recall"]
    specificity = res["specificity"]
    f1_score = res["f1_score"]
    fpr = res["false_positive_rate"]
    accuracy = res["accuracy"]

    print(f"\n{'='*70}")
    print(f"  EVALUATION RESULTS: {name.upper()}")
    print(f"{'='*70}")
    print(f"  Total Scenarios Evaluated : {total}")
    print(f"  True Positives (TP)       : {tp}")
    print(f"  False Positives (FP)      : {fp}")
    print(f"  True Negatives (TN)       : {tn}")
    print(f"  False Negatives (FN)      : {fn}")
    print(f"  -------------------------------------------------------------")
    print(f"  Precision                 : {precision:.4f} ({precision*100:.1f}%)")
    print(f"  Recall (Sensitivity)      : {recall:.4f} ({recall*100:.1f}%)")
    print(f"  Specificity               : {specificity:.4f} ({specificity*100:.1f}%)")
    print(f"  F1 Score                  : {f1_score:.4f} ({f1_score*100:.1f}%)")
    print(f"  False Positive Rate (FPR) : {fpr:.4f} ({fpr*100:.1f}%)")
    print(f"  Accuracy                  : {accuracy:.4f} ({accuracy*100:.1f}%)")
    print(f"{'='*70}")

    print("\n  CONFUSION MATRIX:")
    print("  +-----------------------------+-----------------------------+")
    print("  |                             |        ACTUAL CLASS         |")
    print("  |                             |   Malicious   |   Benign    |")
    print("  +-----------------------------+---------------+-------------+")
    print(f"  | PREDICTED | Detected Threat | TP = {tp:<8} | FP = {fp:<7} |")
    print(f"  |   CLASS   | Benign / Passed | FN = {fn:<8} | TN = {tn:<7} |")
    print("  +-----------------------------+---------------+-------------+")


def main():
    print(f"SOC Alert Analyzer — Empirical Detection Evaluation Benchmark Runner (v{BENCHMARK_VERSION})")
    print("=========================================================================================")

    json_report_path = Path(__file__).resolve().parent.parent / "docs" / "detection_evaluation_report.json"
    report = run_full_benchmark(output_json_path=str(json_report_path))

    print_dataset_table(report["development_dataset"])
    print_dataset_table(report["held_out_dataset"])

    ov = report["overall_summary"]
    print(f"\n{'#'*70}")
    print(f"  COMBINED EVALUATION SUMMARY ACROSS ALL {ov['total_support']} BENCHMARK SCENARIOS")
    print(f"{'#'*70}")
    print(f"  Total Evaluated : {ov['total_support']}")
    print(f"  Overall TP      : {ov['true_positives']} | Overall FP: {ov['false_positives']}")
    print(f"  Overall TN      : {ov['true_negatives']} | Overall FN: {ov['false_negatives']}")
    print(f"  Precision       : {ov['precision']:.4f} ({ov['precision']*100:.1f}%)")
    print(f"  Recall          : {ov['recall']:.4f} ({ov['recall']*100:.1f}%)")
    print(f"  F1 Score        : {ov['f1_score']:.4f} ({ov['f1_score']*100:.1f}%)")
    print(f"  FPR             : {ov['false_positive_rate']:.4f} ({ov['false_positive_rate']*100:.1f}%)")
    print(f"  Accuracy        : {ov['accuracy']:.4f} ({ov['accuracy']*100:.1f}%)")
    print(f"{'#'*70}\n")
    print(f"[+] Machine-readable evaluation report saved to {json_report_path}")

    # Enforce quality gates
    assert ov["false_positives"] == 0, f"Regression Error: Expected 0 False Positives, got {ov['false_positives']}"
    assert ov["false_negatives"] == 0, f"Regression Error: Expected 0 False Negatives, got {ov['false_negatives']}"
    print("[+] All evaluation quality checks PASSED successfully.")


if __name__ == "__main__":
    main()
