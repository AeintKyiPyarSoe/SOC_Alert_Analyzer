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
    assert "psycopg2-binary" in names

    # Verify application metadata version alignment
    import app
    assert data["metadata"]["component"]["version"] == app.__version__


def test_spdx_sbom_valid():
    """Verify sbom.spdx.json is valid SPDX v2.3 JSON document."""
    root = Path(__file__).resolve().parent.parent
    spdx_file = root / "sbom.spdx.json"
    assert spdx_file.exists(), "sbom.spdx.json must exist"

    data = json.loads(spdx_file.read_text(encoding="utf-8"))
    assert data.get("spdxVersion") == "SPDX-2.3"
    assert "packages" in data
    assert len(data["packages"]) >= 15

    import app
    root_pkg = next(p for p in data["packages"] if p["name"] == "SOC_Alert_Analyzer")
    assert root_pkg["versionInfo"] == app.__version__


def test_sbom_and_lockfile_component_count_parity():
    """Verify that sbom.json and requirements.lock inventory the identical dependency set."""
    root = Path(__file__).resolve().parent.parent
    lock_file = root / "requirements.lock"
    sbom_file = root / "sbom.json"

    lock_lines = [l.split("==")[0].strip() for l in lock_file.read_text(encoding="utf-8").splitlines() if "==" in l and not l.strip().startswith("#")]
    sbom_data = json.loads(sbom_file.read_text(encoding="utf-8"))
    sbom_names = [c["name"] for c in sbom_data["components"]]

    assert set(lock_lines) == set(sbom_names), "Lockfile and CycloneDX SBOM must inventory identical packages"
