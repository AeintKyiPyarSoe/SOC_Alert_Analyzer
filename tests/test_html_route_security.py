import uuid
from datetime import datetime, timezone
import pytest
from app.models.alert import Alert
from app.models.incident import Incident
from app.config import settings

def test_html_dashboard_anonymous_isolates_real_telemetry(db_session, unauthenticated_client):
    """Verify that unauthenticated GET / does not expose real host alerts, incidents, or host hardware."""
    # Create genuine host alert
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Confidential Internal Process Memory Dump",
        source_ip="10.50.1.99",
        destination_ip=None,
        severity="CRITICAL",
        risk_score=95,
        status="OPEN"
    )
    db_session.add(real_alert)
    db_session.commit()

    resp = unauthenticated_client.get("/")
    assert resp.status_code == 200
    html = resp.text

    # Real alert description and IP must NOT be in the HTML delivered to anonymous users
    assert "Confidential Internal Process Memory Dump" not in html
    assert "10.50.1.99" not in html

def test_html_dashboard_authenticated_renders_real_telemetry(db_session, client):
    """Verify that authenticated analyst/admin GET / correctly renders real alerts and host information."""
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Genuine Production Threat Detected",
        source_ip="10.50.1.105",
        destination_ip=None,
        severity="HIGH",
        risk_score=80,
        status="OPEN"
    )
    db_session.add(real_alert)
    db_session.commit()

    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    assert "Genuine Production Threat Detected" in html

def test_html_alerts_view_anonymous_does_not_list_real_telemetry(db_session, unauthenticated_client):
    """Verify that GET /alerts does not expose real host alerts to unauthenticated users."""
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Real Root Compromise Attempt",
        source_ip="192.168.10.22",
        destination_ip=None,
        severity="CRITICAL",
        risk_score=99,
        status="OPEN"
    )
    db_session.add(real_alert)
    db_session.commit()

    resp = unauthenticated_client.get("/alerts")
    assert resp.status_code == 200
    assert "Real Root Compromise Attempt" not in resp.text

def test_html_alert_investigation_direct_url_anonymous_rejected(db_session, unauthenticated_client):
    """Verify direct URL access to /alerts/{real_alert_id} without authentication is rejected with 401."""
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Private Enterprise Incident Alert",
        source_ip="10.0.0.15",
        destination_ip=None,
        severity="HIGH",
        risk_score=75,
        status="OPEN"
    )
    db_session.add(real_alert)
    db_session.commit()

    # Anonymous direct GET must fail with 401 Unauthorized
    resp = unauthenticated_client.get(f"/alerts/{real_alert.id}")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]

def test_html_alert_investigation_authenticated_succeeds(db_session, client):
    """Verify that authenticated clients can view single alert investigation playbook HTML."""
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Authorized Triage Target",
        source_ip="10.0.0.18",
        destination_ip=None,
        severity="MEDIUM",
        risk_score=50,
        status="OPEN"
    )
    db_session.add(real_alert)
    db_session.commit()

    resp = client.get(f"/alerts/{real_alert.id}")
    assert resp.status_code == 200
    assert "Authorized Triage Target" in resp.text
    assert "<html" in resp.text.lower()

def test_html_incidents_view_anonymous_hides_real_incidents(db_session, unauthenticated_client):
    """Verify that GET /incidents hides genuine correlated incidents from anonymous users."""
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Breach Evidence",
        severity="CRITICAL",
        risk_score=90,
        status="OPEN"
    )
    incident = Incident(
        id=uuid.uuid4(),
        title="High Priority Production Intrusion",
        description="Multiple attacker actions on host",
        correlation_key="compromise_seq",
        risk_score=90,
        alert_count=1,
        status="OPEN",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        alerts=[real_alert]
    )
    db_session.add_all([real_alert, incident])
    db_session.commit()

    resp = unauthenticated_client.get("/incidents")
    assert resp.status_code == 200
    assert "High Priority Production Intrusion" not in resp.text

def test_html_incident_investigation_direct_url_anonymous_rejected(db_session, unauthenticated_client):
    """Verify direct URL access to /incidents/{real_incident_id} without authentication is rejected with 401."""
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="Sensitive Host Breach Detail",
        severity="CRITICAL",
        risk_score=95,
        status="OPEN"
    )
    incident = Incident(
        id=uuid.uuid4(),
        title="Active Advanced Persistent Threat",
        description="Compromised credentials and lateral movement",
        correlation_key="apt_seq",
        risk_score=95,
        alert_count=1,
        status="OPEN",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        alerts=[real_alert]
    )
    db_session.add_all([real_alert, incident])
    db_session.commit()

    resp = unauthenticated_client.get(f"/incidents/{incident.id}")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]

def test_html_demo_mode_allows_simulated_alerts_for_anonymous(db_session, unauthenticated_client, monkeypatch):
    """Verify that in DEMO_MODE, anonymous users can view SIMULATED_DEMO alerts, but real alerts remain protected."""
    monkeypatch.setattr(settings, "DEMO_MODE", True)

    demo_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Live_Threat_Stream",
        telemetry_origin="SIMULATED_DEMO",
        event_type="web_sql_injection",
        description="Simulated SQL Injection Exercise",
        source_ip="192.0.2.1",
        severity="HIGH",
        risk_score=70,
        status="OPEN"
    )
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="suspicious_process",
        description="True Production Threat",
        source_ip="10.20.30.40",
        severity="CRITICAL",
        risk_score=95,
        status="OPEN"
    )
    db_session.add_all([demo_alert, real_alert])
    db_session.commit()

    # Anonymous user in DEMO_MODE accessing demo alert succeeds
    demo_resp = unauthenticated_client.get(f"/alerts/{demo_alert.id}")
    assert demo_resp.status_code == 200
    assert "Simulated SQL Injection Exercise" in demo_resp.text

    # Anonymous user in DEMO_MODE accessing real alert is STILL rejected with 401
    real_resp = unauthenticated_client.get(f"/alerts/{real_alert.id}")
    assert real_resp.status_code == 401
