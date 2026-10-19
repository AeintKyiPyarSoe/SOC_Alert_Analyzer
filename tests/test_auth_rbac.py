import uuid
import io
import json
from datetime import datetime, timezone
from app.models.alert import Alert
from app.models.incident import Incident
from app.config import settings

def test_unauthenticated_requests_fail_on_sensitive_endpoints(unauthenticated_client):
    fake_id = uuid.uuid4()
    # Status updates require authentication
    r = unauthenticated_client.patch(f"/api/v1/alerts/{fake_id}/status", json={"status": "RESOLVED"})
    assert r.status_code == 401
    assert "Authentication required" in r.json()["detail"]

    r = unauthenticated_client.patch(f"/api/v1/incidents/{fake_id}/status", json={"status": "RESOLVED"})
    assert r.status_code == 401

    # Audits and drills require authentication
    r = unauthenticated_client.post("/api/v1/host/audit")
    assert r.status_code == 401

    r = unauthenticated_client.post("/api/v1/host/drill")
    assert r.status_code == 401

    # Clear and delete require authentication
    r = unauthenticated_client.post("/api/v1/alerts/clear")
    assert r.status_code == 401

    r = unauthenticated_client.delete(f"/api/v1/alerts/{fake_id}")
    assert r.status_code == 401

    # Ingestion requires authentication
    r = unauthenticated_client.post(
        "/api/v1/alerts/upload",
        files={"file": ("test.json", io.BytesIO(b'[]'), "application/json")}
    )
    assert r.status_code == 401

def test_invalid_api_key_rejected(unauthenticated_client):
    r = unauthenticated_client.get(
        "/api/v1/auth/me",
        headers={"X-API-Key": "completely-invalid-key-xyz"}
    )
    assert r.status_code == 401
    assert "Invalid API key" in r.json()["detail"]

def test_public_read_endpoints_accessible_and_sanitized(unauthenticated_client):
    # Public views are accessible, but return sanitized demonstration data
    r = unauthenticated_client.get("/api/v1/alerts")
    assert r.status_code == 200

    r = unauthenticated_client.get("/api/v1/incidents")
    assert r.status_code == 200

    r = unauthenticated_client.get("/api/v1/dashboard/stats")
    assert r.status_code == 200

    # Host status returns sanitized demonstration profile for unauthenticated clients
    r = unauthenticated_client.get("/api/v1/host/status")
    assert r.status_code == 200
    host_data = r.json()
    assert host_data.get("sanitized") is True
    assert "demo-soc" in host_data.get("hostname", "")

def test_authenticated_host_status_returns_genuine_telemetry(analyst_client):
    # Authenticated client receives genuine host telemetry
    r = analyst_client.get("/api/v1/host/status")
    assert r.status_code == 200
    host_data = r.json()
    assert host_data.get("sanitized") is not True

def test_unauthenticated_cannot_access_genuine_alert_or_incident_detail(unauthenticated_client, db_session):
    # Create genuine host alert
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        is_valid_timestamp=True,
        source_type="HostSensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Genuine Host Audit Finding",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        source_port=54321,
        destination_port=445,
        username="SYSTEM",
        severity="HIGH",
        risk_score=75,
        mitre_technique="T1059",
        status="OPEN",
        raw_log="Secret internal host log contents"
    )
    db_session.add(real_alert)
    db_session.commit()

    # Anonymous client attempting to retrieve genuine alert detail is rejected
    r = unauthenticated_client.get(f"/api/v1/alerts/{real_alert.id}")
    assert r.status_code == 401
    assert "Authentication required" in r.json()["detail"]

def test_analyst_role_permissions(analyst_client, db_session):
    # Verify role profile
    r = analyst_client.get("/api/v1/auth/me")
    assert r.status_code == 200
    assert r.json()["role"] == "ANALYST"

    # Analyst CAN run host audit
    r = analyst_client.post("/api/v1/host/drill")
    assert r.status_code == 200

    # Analyst CANNOT clear all alerts (requires ADMIN)
    r = analyst_client.post("/api/v1/alerts/clear")
    assert r.status_code == 403
    assert "Insufficient permissions" in r.json()["detail"]

    # Analyst CANNOT delete alert (requires ADMIN)
    fake_id = uuid.uuid4()
    r = analyst_client.delete(f"/api/v1/alerts/{fake_id}")
    assert r.status_code == 403

def test_admin_role_permissions(client, db_session):
    # Verify role profile
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 200
    assert r.json()["role"] == "ADMIN"

    # Admin CAN clear all alerts
    r = client.post("/api/v1/alerts/clear")
    assert r.status_code == 200
    assert r.json()["status"] == "success"
