#!/usr/bin/env python3
"""
SOC Alert Analyzer — MITRE ATT&CK Automated Threat Summary & Reporting Utility

Generates an automated summary mapping alerts to MITRE ATT&CK tactics and techniques.
Can evaluate the live application database or parse mock SIEM JSON exports directly from
sample_alerts/ without requiring live API keys.

Usage:
  python scripts/generate_mitre_report.py --input sample_alerts/siem_multi_stage_incident.json
  python scripts/generate_mitre_report.py --input sample_alerts/wazuh_alerts.json --format json
  python scripts/generate_mitre_report.py --format markdown --output docs/latest_mitre_report.md
"""

import sys
import json
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.security.mitre_mapper import MitreMapper
from app.parsers import detect_source_type, get_parser
from app.security.normalizer import AlertNormalizer


def parse_file_alerts(file_path: Path):
    """Parses alerts directly from a local log or SIEM JSON export file."""
    if not file_path.exists():
        print(f"[-] Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    content = file_path.read_text(encoding="utf-8", errors="replace")
    source_type = detect_source_type(content)
    parser = get_parser(source_type)
    raw_events = parser.parse(content)

    normalized_alerts = []
    for raw in raw_events:
        norm = AlertNormalizer.normalize(raw)
        normalized_alerts.append(norm)

    return normalized_alerts


def fetch_database_alerts():
    """Fetches stored alerts from the configured application database."""
    from app.database.connection import SessionLocal, init_db
    from app.models.alert import Alert

    init_db()
    db = SessionLocal()
    try:
        alerts = db.query(Alert).all()
        return alerts
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="SOC Alert Analyzer — Automated MITRE ATT&CK Threat Mapping & Report Generator"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        default=None,
        help="Path to security log or mock SIEM JSON file (e.g. sample_alerts/siem_multi_stage_incident.json)"
    )
    parser.add_argument(
        "--format", "-f",
        type=str,
        choices=["markdown", "json", "text"],
        default="markdown",
        help="Output format: markdown (default), json, or text"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Path to write the generated report (default: print to stdout)"
    )

    args = parser.parse_args()

    # Load alerts
    if args.input:
        input_path = Path(args.input)
        alerts = parse_file_alerts(input_path)
        print(f"[*] Parsed {len(alerts)} alerts from {input_path.name}", file=sys.stderr)
    else:
        alerts = fetch_database_alerts()
        print(f"[*] Loaded {len(alerts)} alerts from application database", file=sys.stderr)

    if not alerts:
        print("[-] Warning: No alerts found to evaluate.", file=sys.stderr)

    # Generate MITRE ATT&CK Summary
    summary = MitreMapper.generate_summary_report(alerts)

    # Format report
    if args.format == "markdown":
        output_content = MitreMapper.generate_markdown_report(summary)
    elif args.format == "text":
        output_content = MitreMapper.generate_text_summary(summary)
    else:
        output_content = json.dumps(summary, indent=2)

    # Output destination
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_content, encoding="utf-8")
        print(f"[+] Successfully wrote MITRE ATT&CK report to {out_path}", file=sys.stderr)
    else:
        print(output_content)


if __name__ == "__main__":
    main()
