#!/usr/bin/env python3
"""
SOC Alert Analyzer — Release Artifact Checksum Verifier & Generator

Validates that release binaries and SHA256SUMS.txt strictly match.
Supports both generation and verification modes.

Usage:
  python scripts/verify_release_checksum.py --verify dist/SHA256SUMS.txt
  python scripts/verify_release_checksum.py --generate dist/SOC_Alert_Analyzer.exe dist/SHA256SUMS.txt
"""

import sys
import os
import re
import hashlib
import argparse
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest in memory-efficient 64KB blocks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_checksum_file(artifact_path: Path, output_file: Path) -> str:
    """Computes artifact hash and generates standardized SHA256SUMS.txt."""
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    size = artifact_path.stat().st_size
    if size == 0:
        raise ValueError(f"Artifact is empty (0 bytes): {artifact_path}")

    digest = compute_sha256(artifact_path)
    entry = f"{digest}  {artifact_path.name}\n"

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(entry)

    print(f"[+] Successfully generated checksum for {artifact_path.name}")
    print(f"    SHA-256: {digest}")
    print(f"    Size   : {size:,} bytes")
    print(f"    Saved  : {output_file}")
    return digest


def verify_checksum_file(checksum_file: Path) -> bool:
    """Verifies that the file listed in checksum_file exists and matches digest."""
    if not checksum_file.exists():
        raise FileNotFoundError(f"Checksum file not found: {checksum_file}")

    with open(checksum_file, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        raise ValueError(f"Checksum file is empty: {checksum_file}")

    match = re.match(r"^([a-fA-F0-9]{64})\s{2}(.+)$", content)
    if not match:
        raise ValueError(
            f"Invalid format in {checksum_file}. Expected '<64-char sha256>  <filename>', got: '{content}'"
        )

    expected_hash = match.group(1).lower()
    artifact_name = match.group(2).strip()

    # Search in same directory as checksum file or dist directory
    artifact_path = checksum_file.parent / artifact_name
    if not artifact_path.exists():
        raise FileNotFoundError(
            f"Artifact '{artifact_name}' referenced in checksum file not found at: {artifact_path}"
        )

    size = artifact_path.stat().st_size
    computed_hash = compute_sha256(artifact_path).lower()

    print(f"[*] Verifying artifact: {artifact_path}")
    print(f"    Expected SHA-256: {expected_hash}")
    print(f"    Computed SHA-256: {computed_hash}")
    print(f"    Artifact Size   : {size:,} bytes")

    if computed_hash != expected_hash:
        print(f"[!] CHECKSUM MISMATCH for {artifact_name}!", file=sys.stderr)
        return False

    print("[+] Checksum verification PASSED.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Verify or generate SHA256SUMS.txt")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", type=str, help="Path to SHA256SUMS.txt to verify")
    group.add_argument("--generate", nargs=2, metavar=("ARTIFACT", "CHECKSUM_FILE"), help="Generate checksum file")

    args = parser.parse_args()

    try:
        if args.verify:
            success = verify_checksum_file(Path(args.verify))
            sys.exit(0 if success else 1)
        elif args.generate:
            artifact, out_file = args.generate
            generate_checksum_file(Path(artifact), Path(out_file))
            # Verify immediately after generation
            success = verify_checksum_file(Path(out_file))
            sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
