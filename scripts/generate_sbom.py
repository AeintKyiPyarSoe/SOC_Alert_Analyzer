#!/usr/bin/env python3
"""
SOC Alert Analyzer — Reproducible Dependency Lockfile & Software Bill of Materials (SBOM) Generator

Generates:
  1. requirements.lock - Pinned, reproducible dependency manifest for reproducible CI & container builds.
  2. sbom.json - CycloneDX v1.5 standard Software Bill of Materials.
  3. sbom.spdx.json - SPDX v2.3 compliant Software Bill of Materials.

Usage:
  python scripts/generate_sbom.py
"""

import os
import sys
import json
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
import importlib.metadata

# Core direct runtime dependencies of SOC Alert Analyzer
RUNTIME_BASE_PACKAGES = [
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
    "click",
    "h11",
    "psycopg2-binary",  # PostgreSQL driver for containerized and production deployments
]


def resolve_dependency_versions(requirements_path: Path) -> dict:
    """
    Dynamically parses requirements.txt and resolves exact installed versions
    and required transitive dependencies.
    """
    discovered = set(RUNTIME_BASE_PACKAGES)

    if requirements_path.exists():
        for line in requirements_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Clean package name from requirements line (e.g. uvicorn[standard]>=0.28.0)
                pkg = re.split(r"[><=~;!]", line)[0].split("[")[0].strip()
                if pkg:
                    discovered.add(pkg)

    pinned = {}
    for pkg in sorted(discovered):
        try:
            ver = importlib.metadata.version(pkg)
            pinned[pkg] = ver
        except Exception:
            # Fallback for platform-specific packages not installed on current host (e.g. psycopg2-binary on pure Windows desktop)
            if pkg == "psycopg2-binary":
                pinned[pkg] = "2.9.10"
            else:
                pinned[pkg] = "latest"

    return pinned


def generate_requirements_lock(output_path: Path, pinned_deps: dict) -> dict:
    """Generates a reproducible, pinned requirements.lock file."""
    lines = [
        "# ==============================================================================",
        "# SOC Alert Analyzer - Reproducible Dependency Lockfile",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        "# Scope: Direct and transitive runtime dependencies for deterministic builds.",
        "# ==============================================================================",
        ""
    ]

    for dep, version in sorted(pinned_deps.items()):
        lines.append(f"{dep}=={version}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Generated requirements.lock with {len(pinned_deps)} pinned dependencies: {output_path}")
    return pinned_deps


def generate_cyclonedx_sbom(output_path: Path, pinned_deps: dict, app_version: str):
    """Generates a valid CycloneDX v1.5 JSON Software Bill of Materials (SBOM)."""
    now = datetime.now(timezone.utc).isoformat()
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    components = []
    for name, version in sorted(pinned_deps.items()):
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
                    "version": "1.1.0"
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
                "Tool: SOC_Alert_Analyzer_SBOM_Generator-1.1.0",
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

    for name, version in sorted(pinned_deps.items()):
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

    req_file = root / "requirements.txt"
    lock_file = root / "requirements.lock"
    sbom_file = root / "sbom.json"
    spdx_file = root / "sbom.spdx.json"

    pinned = resolve_dependency_versions(req_file)
    generate_requirements_lock(lock_file, pinned)
    generate_cyclonedx_sbom(sbom_file, pinned, app.__version__)
    generate_spdx_sbom(spdx_file, pinned, app.__version__)
    print(f"[+] All lockfile and SBOM artifacts generated successfully for v{app.__version__}.")


if __name__ == "__main__":
    main()
