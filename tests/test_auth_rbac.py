import uuid
import io
import json
from app.models.alert import Alert

def test_unauthenticated_requests_fail_on_sensitive_endpoints(unauthenticated_client):
    # Status updates require authentication
    fake_id = uuid.uuid4()
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

def test_public_read_endpoints_accessible(unauthenticated_client):
    r = unauthenticated_client.get("/api/v1/alerts")
    assert r.status_code == 200

    r = unauthenticated_client.get("/api/v1/incidents")
    assert r.status_code == 200

    r = unauthenticated_client.get("/api/v1/dashboard/stats")
    assert r.status_code == 200

    r = unauthenticated_client.get("/api/v1/host/status")
    assert r.status_code == 200

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
