"""
tests/test_release_manifest_consistency.py
Release Manifest & Version Consistency Regression Suite

Asserts strict synchronization across:
  1. app.__version__
  2. app.config.settings.VERSION
  3. FastAPI metadata version
  4. README.md release badge & version references
  5. CHANGELOG.md release section
  6. CycloneDX sbom.json metadata & purl
  7. SPDX sbom.spdx.json document name & package info
  8. dist/SHA256SUMS.txt format, binary name, and hash validity
"""

import re
import json
import hashlib
from pathlib import Path

import app
from app.config import settings
from app.main import app as fastapi_app

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_internal_python_version_parity():
    """Verify code symbols and FastAPI application expose identical semantic version strings."""
    ver = app.__version__
    assert settings.VERSION == ver, f"Settings.VERSION ({settings.VERSION}) does not match app.__version__ ({ver})"
    assert fastapi_app.version == ver, f"FastAPI version ({fastapi_app.version}) does not match app.__version__ ({ver})"


def test_sbom_manifests_version_parity():
    """Verify CycloneDX and SPDX SBOM files match the canonical version."""
    ver = app.__version__
    sbom_path = ROOT_DIR / "sbom.json"
    spdx_path = ROOT_DIR / "sbom.spdx.json"

    assert sbom_path.exists(), "sbom.json missing"
    assert spdx_path.exists(), "sbom.spdx.json missing"

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)
    assert sbom["metadata"]["component"]["version"] == ver
    assert f"@{ver}" in sbom["metadata"]["component"]["purl"]

    with open(spdx_path, "r", encoding="utf-8") as f:
        spdx = json.load(f)
    assert spdx["packages"][0]["versionInfo"] == ver
    assert ver in spdx["name"]


def test_readme_and_changelog_version_consistency():
    """Verify README.md release badge and CHANGELOG.md match the canonical version."""
    ver = app.__version__
    readme_path = ROOT_DIR / "README.md"
    changelog_path = ROOT_DIR / "CHANGELOG.md"

    assert readme_path.exists(), "README.md missing"
    assert changelog_path.exists(), "CHANGELOG.md missing"

    readme_text = readme_path.read_text(encoding="utf-8")
    expected_badge = f"release-v{ver}"
    assert expected_badge in readme_text, f"README.md does not contain badge with '{expected_badge}'"

    changelog_text = changelog_path.read_text(encoding="utf-8")
    expected_header = f"## [{ver}]"
    assert expected_header in changelog_text, f"CHANGELOG.md does not contain entry for '{expected_header}'"


def test_checksum_manifest_format_and_integrity():
    """Verify dist/SHA256SUMS.txt adheres strictly to standard format and verifies binary if present."""
    checksum_path = ROOT_DIR / "dist" / "SHA256SUMS.txt"
    assert checksum_path.exists(), "dist/SHA256SUMS.txt missing"

    content = checksum_path.read_text(encoding="utf-8").strip()
    assert content, "SHA256SUMS.txt is empty"

    lines = content.splitlines()
    assert len(lines) >= 1, "Expected at least one checksum entry"

    match = re.match(r"^([a-fA-F0-9]{64})\s+(\S+)$", lines[0].strip())
    assert match is not None, f"Checksum line does not match SHA256 format: {lines[0]}"

    expected_hash, binary_name = match.group(1).lower(), match.group(2)
    assert binary_name == "SOC_Alert_Analyzer.exe", f"Unexpected binary name in checksum: {binary_name}"

    exe_path = ROOT_DIR / "dist" / binary_name
    if exe_path.exists():
        h = hashlib.sha256()
        with open(exe_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        actual_hash = h.hexdigest().lower()
        assert actual_hash == expected_hash, (
            f"Binary hash mismatch! Computed: {actual_hash}, SHA256SUMS.txt: {expected_hash}"
        )


def test_readme_official_release_checksum_matches_repository_manifest():
    """Fail if current-release download instructions refer to a different EXE."""
    readme = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    manifest = (ROOT_DIR / "dist" / "SHA256SUMS.txt").read_text(encoding="utf-8").strip()
    digest, binary_name = manifest.split(maxsplit=1)
    assert binary_name == "SOC_Alert_Analyzer.exe"
    # Scope to the actual Windows download instructions to avoid unrelated historical hashes.
    download_instructions = readme.split("### Option A: Standalone Windows Executable", 1)[1].split("### Option B:", 1)[0]
    hashes = re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])", download_instructions)
    assert hashes == [digest], f"README Windows download checksum {hashes} != official {digest}"


def test_release_notes_official_checksum_matches_repository_manifest():
    """Official release digest in release notes must match the repository official manifest."""
    import app
    notes = ROOT_DIR / "docs" / f"release_notes_v{app.__version__}.md"
    assert notes.exists(), f"Missing current release notes: {notes}"
    content = notes.read_text(encoding="utf-8")
    digest = (ROOT_DIR / "dist" / "SHA256SUMS.txt").read_text(encoding="utf-8").split()[0]
    match = re.search(r"\\*\\*Authoritative Binary SHA-256[^\\n]*?\\*\\*\\s*`([0-9a-f]{64})`", content)
    assert match, "Release notes must identify the official published artifact digest"
    assert match.group(1) == digest, "Release notes official digest differs from dist/SHA256SUMS.txt"


def test_readme_test_count_claims_are_consistent():
    """Catch stale badges, body text and pytest result output before merging."""
    readme = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    badge = re.search(r"tests-(\\d+)%20passed%20%7C%20(\\d+)%20skipped", readme)
    assert badge, "Test badge must distinguish passed from skipped"
    passed, skipped = map(int, badge.groups())
    body = re.search(r"\\*\\*(\\d+) passed, (\\d+) skipped, (\\d+) failed", readme)
    assert body, "README testing section must report passed, skipped and failed"
    assert (passed, skipped, 0) == tuple(map(int, body.groups()))
    summary = re.search(r"={5,}\\s*(\\d+) passed, (\\d+) skipped, (\\d+) warning", readme)
    assert summary, "README CI test summary must include skipped tests"
    assert (passed, skipped) == tuple(map(int, summary.groups()[:2]))
    collected = re.search(r"(\\d+) collected pytest tests \\(\\d+ passed, \\d+ skipped", readme)
    assert collected, "README project tree test count must report collected/passed/skipped"
    assert int(collected.group(1)) == passed + skipped
    assert int(collected.group(2)) == passed
