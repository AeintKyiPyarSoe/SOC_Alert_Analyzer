import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.parsers import detect_source_type, get_parser
from app.security.mitre_mapper import MitreMapper, MITRE_TACTICS, MITRE_TECHNIQUES
from app.security.normalizer import AlertNormalizer
from app.models.alert import Alert
from app.database.connection import get_db


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. Sample Data Verification Tests
# ---------------------------------------------------------------------------

def test_sample_alerts_directory_and_files_exist():
    sample_dir = Path(__file__).resolve().parent.parent / "sample_alerts"
    assert sample_dir.exists(), "sample_alerts directory must exist"
    assert sample_dir.is_dir(), "sample_alerts must be a directory"

    expected_files = [
        "wazuh_alerts.json",
        "suricata_eve.json",
        "windows_security_events.json",
        "siem_multi_stage_incident.json",
        "web_application_alerts.json",
        "README.md"
    ]
    for filename in expected_files:
        file_path = sample_dir / filename
        assert file_path.exists(), f"Expected sample file missing: {filename}"
        assert file_path.stat().st_size > 0, f"Sample file is empty: {filename}"


def test_sample_alerts_json_validity_and_parsing():
    sample_dir = Path(__file__).resolve().parent.parent / "sample_alerts"
    json_files = [
        "wazuh_alerts.json",
        "suricata_eve.json",
        "windows_security_events.json",
        "siem_multi_stage_incident.json",
        "web_application_alerts.json"
    ]

    for fname in json_files:
        path = sample_dir / fname
        content = path.read_text(encoding="utf-8")
        src_type = detect_source_type(content)
        parser = get_parser(src_type)
        events = parser.parse(content)

        assert len(events) > 0, f"Failed to extract events from {fname} using parser {parser.__class__.__name__}"

        # Verify normalization succeeds for all events
        mapped_count = 0
        for ev in events:
            norm = AlertNormalizer.normalize(ev)
            assert norm["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert 0 <= norm["risk_score"] <= 100
            if norm.get("mitre_technique"):
                mapped_count += 1

        assert mapped_count > 0, f"Expected at least one MITRE technique mapping in {fname}"


# ---------------------------------------------------------------------------
# 2. MITRE ATT&CK Summary and Reporting Tests
# ---------------------------------------------------------------------------

def test_mitre_summary_report_generation():
    sample_path = Path(__file__).resolve().parent.parent / "sample_alerts" / "siem_multi_stage_incident.json"
    data = json.loads(sample_path.read_text(encoding="utf-8"))

    summary = MitreMapper.generate_summary_report(data)

    assert summary["total_alerts"] == len(data)
    assert summary["mapped_alerts"] > 0
    assert summary["coverage_percentage"] > 70.0
    assert summary["tactics_count"] >= 5
    assert summary["techniques_count"] >= 5
    assert summary["highest_severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert len(summary["tactics"]) == summary["tactics_count"]
    assert len(summary["matrix_grid"]) == 14  # All 14 enterprise tactics

    # Check top techniques
    assert len(summary["top_techniques"]) > 0
    top = summary["top_techniques"][0]
    assert "id" in top
    assert "name" in top
    assert "tactic" in top
    assert "alert_count" in top


def test_mitre_markdown_report_formatting():
    sample_path = Path(__file__).resolve().parent.parent / "sample_alerts" / "siem_multi_stage_incident.json"
    data = json.loads(sample_path.read_text(encoding="utf-8"))
    summary = MitreMapper.generate_summary_report(data)

    md = MitreMapper.generate_markdown_report(summary)

    assert "# SOC Alert Analyzer" in md
    assert "Executive Summary" in md
    assert "Adversary Tactic Distribution" in md
    assert "Enterprise ATT&CK Matrix Overview" in md
    assert "Defensive Action Items" in md
    assert "TA0001" in md or "TA0002" in md


def test_mitre_text_summary_formatting():
    sample_path = Path(__file__).resolve().parent.parent / "sample_alerts" / "siem_multi_stage_incident.json"
    data = json.loads(sample_path.read_text(encoding="utf-8"))
    summary = MitreMapper.generate_summary_report(data)

    txt = MitreMapper.generate_text_summary(summary)

    assert "SOC ALERT ANALYZER" in txt
    assert "TACTIC DISTRIBUTION:" in txt
    assert "TOP TECHNIQUES:" in txt


# ---------------------------------------------------------------------------
# 3. API Endpoints & Web Route Tests
# ---------------------------------------------------------------------------

def test_mitre_report_api_endpoints(client, db_session):
    # Ingest a sample event into DB
    sample_path = Path(__file__).resolve().parent.parent / "sample_alerts" / "siem_multi_stage_incident.json"
    data = json.loads(sample_path.read_text(encoding="utf-8"))
    for item in data[:5]:
        norm = AlertNormalizer.normalize(item)
        import uuid
        alert = Alert(
            id=uuid.uuid4(),
            occurrence_count=1,
            first_seen=norm["timestamp"],
            last_seen=norm["timestamp"],
            **norm
        )
        db_session.add(alert)
    db_session.commit()

    headers = {"X-API-Key": settings.ANALYST_API_KEY}

    # 1. JSON Report
    resp_json = client.get("/api/v1/reports/mitre?format=json", headers=headers)
    assert resp_json.status_code == 200
    res_data = resp_json.json()
    assert "coverage_percentage" in res_data
    assert "matrix_grid" in res_data

    # 2. Markdown Report
    resp_md = client.get("/api/v1/reports/mitre?format=markdown", headers=headers)
    assert resp_md.status_code == 200
    assert "text/markdown" in resp_md.headers.get("content-type", "")
    assert "Executive Summary" in resp_md.text

    # 3. Text Report
    resp_txt = client.get("/api/v1/reports/mitre?format=text", headers=headers)
    assert resp_txt.status_code == 200
    assert "text/plain" in resp_txt.headers.get("content-type", "")
    assert "TACTIC DISTRIBUTION:" in resp_txt.text

    # 4. Matrix API
    resp_matrix = client.get("/api/v1/reports/mitre/matrix", headers=headers)
    assert resp_matrix.status_code == 200
    m_data = resp_matrix.json()
    assert len(m_data["matrix_grid"]) == 14

    # 5. HTML Web View
    resp_html = client.get("/reports/mitre", headers=headers)
    assert resp_html.status_code == 200
    assert "text/html" in resp_html.headers.get("content-type", "")
    assert "Enterprise ATT&CK Navigator Matrix Heatmap" in resp_html.text


def test_quick_load_sample_datasets(client, db_session):
    headers = {"X-API-Key": settings.ANALYST_API_KEY}

    # Test loading windows sample dataset
    resp_win = client.post("/api/v1/sample-data/load/windows", headers=headers)
    assert resp_win.status_code == 200
    assert resp_win.json()["status"] == "success"
    assert resp_win.json()["alerts_count"] > 0

    # Test loading multi_stage sample dataset
    resp_apt = client.post("/api/v1/sample-data/load/multi_stage", headers=headers)
    assert resp_apt.status_code == 200
    assert resp_apt.json()["status"] == "success"
    assert resp_apt.json()["alerts_count"] > 0
