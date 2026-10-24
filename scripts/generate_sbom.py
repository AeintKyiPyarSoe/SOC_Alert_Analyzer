#!/usr/bin/env python3
"""
SOC Alert Analyzer — Reproducible Dependency Lockfile & Software Bill of Materials (SBOM) Generator

Generates:
  1. requirements.lock - Pinned, reproducible dependency manifest.
  2. sbom.json - CycloneDX v1.5 standard Software Bill of Materials.
  3. sbom.spdx.json - SPDX v2.3 compliant Software Bill of Materials.

Usage:
  python scripts/generate_sbom.py
"""

import os
import sys
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
import importlib.metadata

# Core dependencies required for SOC Alert Analyzer
CORE_DEPENDENCIES = [
    "fastapi",
    "starlette",
    "pydantic",
    "pydantic-core",
    "uvicorn",
    "sqlalchemy",
    "alembic",
    "psutil",
    "defusedxml",
    "jinja2",
    "markupsafe",
    "python-dotenv",
    "python-multipart",
    "httpx",
    "httpcore",
    "anyio",
    "sniffio",
    "idna",
    "certifi",
    "typing-extensions",
]


def get_installed_version(pkg_name: str) -> str:
    """Retrieves installed package version or fallback."""
    try:
        return importlib.metadata.version(pkg_name)
    except Exception:
        return "latest"


def generate_requirements_lock(output_path: Path):
    """Generates a reproducible, pinned requirements.lock file."""
    lines = [
        "# ==============================================================================",
        "# SOC Alert Analyzer - Reproducible Dependency Lockfile",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        "# ==============================================================================",
        ""
    ]

    pinned = {}
    for dep in CORE_DEPENDENCIES:
        version = get_installed_version(dep)
        pinned[dep] = version
        lines.append(f"{dep}=={version}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Generated requirements.lock with {len(pinned)} pinned dependencies: {output_path}")
    return pinned


def generate_cyclonedx_sbom(output_path: Path, pinned_deps: dict, app_version: str):
    """Generates a valid CycloneDX v1.5 JSON Software Bill of Materials (SBOM)."""
    now = datetime.now(timezone.utc).isoformat()
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    components = []
    for name, version in pinned_deps.items():
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
            "scope": "required",
            "supplier": {
                "name": "PyPI Community"
            }
        })

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "SOC Alert Analyzer Project",
                    "name": "SBOM Generator",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": "SOC_Alert_Analyzer",
                "version": app_version,
                "description": "Defensive blue-team SOC alert triage and host security audit workbench",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ],
                "purl": f"pkg:github/AeintKyiPyarSoe/SOC_Alert_Analyzer@{app_version}"
            }
        },
        "components": components
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)

    print(f"[+] Generated CycloneDX SBOM ({len(components)} components): {output_path}")


def generate_spdx_sbom(output_path: Path, pinned_deps: dict, app_version: str):
    """Generates a valid SPDX v2.3 JSON Software Bill of Materials."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SOC_Alert_Analyzer-{app_version}",
        "documentNamespace": f"https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer/spdx/{app_version}",
        "creationInfo": {
            "creators": [
                "Tool: SOC_Alert_Analyzer_SBOM_Generator-1.0.0",
                "Organization: SOC Alert Analyzer Project"
            ],
            "created": now
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-SOC-Alert-Analyzer",
                "name": "SOC_Alert_Analyzer",
                "versionInfo": app_version,
                "downloadLocation": "https://github.com/AeintKyiPyarSoe/SOC_Alert_Analyzer",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT"
            }
        ]
    }

    for name, version in pinned_deps.items():
        pkg_id = f"SPDXRef-Package-{name.replace('_', '-').replace('.', '-')}"
        spdx_doc["packages"].append({
            "SPDXID": pkg_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": f"https://pypi.org/project/{name}/{version}/",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{name}@{version}"
                }
            ]
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spdx_doc, f, indent=2)

    print(f"[+] Generated SPDX SBOM: {output_path}")


def main():
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    import app

    lock_file = root / "requirements.lock"
    sbom_file = root / "sbom.json"
    spdx_file = root / "sbom.spdx.json"

    pinned = generate_requirements_lock(lock_file)
    generate_cyclonedx_sbom(sbom_file, pinned, app.__version__)
    generate_spdx_sbom(spdx_file, pinned, app.__version__)
    print("[+] All lockfile and SBOM artifacts generated successfully.")


if __name__ == "__main__":
    main()
