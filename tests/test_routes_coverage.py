import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.models.alert import Alert
from app.models.incident import Incident
from app.security.stream import stream_manager

@pytest.fixture
def analyst_headers():
    return {"X-API-Key": settings.ANALYST_API_KEY}

@pytest.fixture
def admin_headers():
    return {"X-API-Key": settings.ADMIN_API_KEY}

def test_stream_status_and_toggles(client, unauthenticated_client, analyst_headers):
    # Check status unauthenticated (public health)
    status_resp = unauthenticated_client.get("/api/v1/stream/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert "host_monitoring_active" in data
    assert "simulation_active" in data

    # Toggle host monitor requires Analyst
    unauth_resp = unauthenticated_client.post("/api/v1/host/monitor/toggle?active=false")
    assert unauth_resp.status_code == 401

    auth_resp = client.post("/api/v1/host/monitor/toggle?active=false", headers=analyst_headers)
    assert auth_resp.status_code == 200
    assert auth_resp.json()["host_monitoring_active"] is False
    assert stream_manager.host_monitoring_active is False

    # Turn back on
    auth_resp2 = client.post("/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)
    assert auth_resp2.status_code == 200
    assert stream_manager.host_monitoring_active is True

    # Simulation toggles
    sim_resp = client.post("/api/v1/simulation/toggle?active=true", headers=analyst_headers)
    assert sim_resp.status_code == 200
    assert stream_manager.simulation_active is True

    stream_toggle_resp = client.post("/api/v1/stream/toggle?active=false", headers=analyst_headers)
    assert stream_toggle_resp.status_code == 200
    assert stream_manager.simulation_active is False

def test_sample_data_loader_route(client, analyst_headers):
    # Invalid dataset type
    resp_bad = client.post("/api/v1/sample-data/load/invalid_type", headers=analyst_headers)
    assert resp_bad.status_code == 400

    # Load wazuh sample
    resp_wazuh = client.post("/api/v1/sample-data/load/wazuh", headers=analyst_headers)
    assert resp_wazuh.status_code == 200
    assert resp_wazuh.json()["status"] == "success"

def test_alert_and_incident_status_transitions(client, analyst_headers, admin_headers, db_session):
    # Create test alert
    alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        severity="HIGH",
        risk_score=75,
        event_type="test_event",
        description="Test status transition alert",
        source_type="Test_Source",
        telemetry_origin="HOST_TELEMETRY",
        status="OPEN"
    )
    db_session.add(alert)
    db_session.commit()

    # Update alert status
    patch_resp = client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "INVESTIGATING"},
        headers=analyst_headers
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "INVESTIGATING"

    # Create linked incident
    incident = Incident(
        id=uuid.uuid4(),
        title="Test Incident",
        description="Test incident for status update",
        risk_score=80,
        status="OPEN",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        alert_count=1
    )
    incident.alerts.append(alert)
    db_session.add(incident)
    db_session.commit()

    # Update incident status (cascades to alert)
    inc_patch_resp = client.patch(
        f"/api/v1/incidents/{incident.id}/status",
        json={"status": "RESOLVED"},
        headers=analyst_headers
    )
    assert inc_patch_resp.status_code == 200
    assert inc_patch_resp.json()["status"] == "RESOLVED"

    # Delete alert as admin
    del_resp = client.delete(f"/api/v1/alerts/{alert.id}", headers=admin_headers)
    assert del_resp.status_code == 200

def test_host_audit_and_drill_routes(client, analyst_headers):
    # Host drill test alert
    drill_resp = client.post("/api/v1/host/drill", headers=analyst_headers)
    assert drill_resp.status_code == 200

    # Host audit
    audit_resp = client.post("/api/v1/host/audit", headers=analyst_headers)
    assert audit_resp.status_code == 200
    assert "findings_count" in audit_resp.json()

def test_html_views_filtering_and_404s(client, analyst_headers):
    # Filtered alerts view
    resp_alerts = client.get("/alerts?severity=HIGH&status=OPEN&source=Wazuh&search=192")
    assert resp_alerts.status_code == 200

    # Filtered incidents view
    resp_incidents = client.get("/incidents?status=OPEN")
    assert resp_incidents.status_code == 200

    # 404 Alert investigation view
    missing_id = uuid.uuid4()
    resp_404_alert = client.get(f"/alerts/{missing_id}")
    assert resp_404_alert.status_code == 404

    # 404 Incident investigation view
    resp_404_inc = client.get(f"/incidents/{missing_id}")
    assert resp_404_inc.status_code == 404
