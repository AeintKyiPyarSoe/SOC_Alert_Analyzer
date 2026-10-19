import uuid
from datetime import datetime, timezone, timedelta
from app.config import settings
from app.models.alert import Alert
from app.models.incident import Incident
from app.security.correlator import IncidentCorrelator
from app.security.session import session_manager

def test_security_headers_present(unauthenticated_client):
    """Verify that all defensive security headers are returned on HTTP responses."""
    resp = unauthenticated_client.get("/api/v1/auth/me")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in headers.get("Permissions-Policy", "")
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")

def test_login_rate_limiting_and_lockout(unauthenticated_client):
    """Verify that repeated failed login attempts trigger an HTTP 429 lockout."""
    # Reset lockouts for test client
    session_manager._login_attempts.clear()
    session_manager._lockouts.clear()

    # Attempt 5 incorrect logins (threshold is 5 attempts)
    for _ in range(5):
        resp = unauthenticated_client.post(
            "/api/v1/auth/login",
            json={"api_key": "wrong_invalid_key_12345"}
        )
        assert resp.status_code == 401

    # 6th attempt should be blocked with 429
    blocked_resp = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": "wrong_invalid_key_12345"}
    )
    assert blocked_resp.status_code == 429
    assert "Too many failed login attempts" in blocked_resp.json()["detail"]

    # Clean up
    session_manager._login_attempts.clear()
    session_manager._lockouts.clear()

def test_security_audit_logs_role_protection(client, unauthenticated_client):
    """Verify that the security audit trail requires elevated ADMIN clearance."""
    # Unauthenticated / anonymous attempt fails
    anon_resp = unauthenticated_client.get("/api/v1/audit/logs")
    assert anon_resp.status_code in (401, 403)

    # Admin client succeeds
    admin_resp = client.get("/api/v1/audit/logs")
    assert admin_resp.status_code == 200
    data = admin_resp.json()
    assert data["status"] == "success"
    assert "logs" in data
    assert isinstance(data["logs"], list)

def test_multi_stage_compromise_incident_escalation(db_session):
    """
    Verify that an authentication brute-force sequence followed by successful logon
    is automatically correlated into an escalated multi-stage Compromised Account incident.
    """
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.77"

    # 3 Failed login alerts
    for i in range(3):
        fail_alert = Alert(
            id=uuid.uuid4(),
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="Linux_Auth",
            event_type="ssh_authentication_failure",
            description=f"Failed password for user admin from {source_ip}",
            source_ip=source_ip,
            destination_ip="192.168.1.10",
            severity="MEDIUM",
            risk_score=45,
            status="OPEN"
        )
        db_session.add(fail_alert)

    # 1 Successful login alert from same source IP
    succ_alert = Alert(
        id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=45),
        source_type="Linux_Auth",
        event_type="ssh_login_successful",
        description=f"Accepted password for user admin from {source_ip}",
        source_ip=source_ip,
        destination_ip="192.168.1.10",
        severity="LOW",
        risk_score=15,
        status="OPEN"
    )
    db_session.add(succ_alert)
    db_session.commit()

    incidents = IncidentCorrelator.correlate_alerts(db_session, window_seconds=300)
    assert len(incidents) >= 1

    # Check that multi-stage attack was detected
    all_incidents = db_session.query(Incident).all()
    multi_stage = [inc for inc in all_incidents if "Compromised Account" in inc.title or inc.risk_score >= 85]
    assert len(multi_stage) >= 1
    assert multi_stage[0].risk_score >= 85

def test_simulated_demo_alerts_isolated_from_production_stats(db_session, client):
    """Verify that SIMULATED_DEMO alerts do not contaminate genuine KPI metrics."""
    # Insert genuine alert
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Genuine suspicious host process",
        severity="HIGH",
        risk_score=65,
        status="OPEN"
    )
    # Insert demo simulation alert
    demo_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Live_Threat_Stream",
        telemetry_origin="SIMULATED_DEMO",
        event_type="web_sql_injection",
        description="Simulated educational training drill",
        severity="CRITICAL",
        risk_score=85,
        status="OPEN"
    )
    db_session.add_all([real_alert, demo_alert])
    db_session.commit()

    resp = client.get("/api/v1/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.json()

    # If DEMO_MODE is False (default), only genuine alerts are counted in stats
    if not settings.DEMO_MODE:
        assert stats["total_alerts"] == 1
        assert stats["high_count"] == 1
        assert stats["critical_count"] == 0
