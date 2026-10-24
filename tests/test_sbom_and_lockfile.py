"""
Tests verifying reproducible dependency lockfile and Software Bill of Materials (SBOM).
"""

import json
from pathlib import Path


def test_requirements_lock_exists_and_pinned():
    """Verify requirements.lock exists and contains pinned versions for core dependencies."""
    root = Path(__file__).resolve().parent.parent
    lock_file = root / "requirements.lock"
    assert lock_file.exists(), "requirements.lock must exist"

    content = lock_file.read_text(encoding="utf-8")
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
    assert len(lines) >= 15, "requirements.lock must contain at least 15 dependencies"

    for l in lines:
        assert "==" in l, f"Dependency line '{l}' in requirements.lock must be pinned with '=='"


def test_cyclonedx_sbom_valid():
    """Verify sbom.json is valid CycloneDX v1.5 JSON with required metadata and components."""
    root = Path(__file__).resolve().parent.parent
    sbom_file = root / "sbom.json"
    assert sbom_file.exists(), "sbom.json must exist"

    data = json.loads(sbom_file.read_text(encoding="utf-8"))
    assert data.get("bomFormat") == "CycloneDX"
    assert data.get("specVersion") == "1.5"
    assert "components" in data
    assert len(data["components"]) >= 15

    names = {c["name"] for c in data["components"]}
    assert "fastapi" in names
    assert "pydantic" in names
    assert "sqlalchemy" in names
    assert "psutil" in names


def test_spdx_sbom_valid():
    """Verify sbom.spdx.json is valid SPDX v2.3 JSON document."""
    root = Path(__file__).resolve().parent.parent
    spdx_file = root / "sbom.spdx.json"
    assert spdx_file.exists(), "sbom.spdx.json must exist"

    data = json.loads(spdx_file.read_text(encoding="utf-8"))
    assert data.get("spdxVersion") == "SPDX-2.3"
    assert "packages" in data
    assert len(data["packages"]) >= 15
