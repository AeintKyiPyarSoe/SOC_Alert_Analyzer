import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import SessionLocal
from app.models.alert import Alert
from app.models.incident import Incident
from app.config import settings

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_dashboard_stats_anonymous_isolated_from_genuine_telemetry(db_session):
    """
    SECURITY TEST:
    Verify that an unauthenticated (anonymous) request to GET /api/v1/dashboard/stats
    cannot retrieve genuine operational statistics or alert counts derived from private host telemetry.
    """
    client = TestClient(app)

    # 1. Clear existing alerts for clean baseline
    db_session.query(Alert).delete()
    db_session.query(Incident).delete()
    db_session.commit()

    # 2. Seed genuine private host alerts (HOST_TELEMETRY and HISTORICAL_LOG)
    real_alert_1 = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Security_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="web_shell_probe",
        description="Private genuine web shell execution on server",
        severity="CRITICAL",
        risk_score=95.0,
        status="OPEN"
    )
    real_alert_2 = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Wazuh",
        telemetry_origin="HISTORICAL_LOG",
        event_type="ssh_brute_force",
        description="Private genuine SSH brute force attack",
        severity="HIGH",
        risk_score=80.0,
        status="OPEN"
    )
    db_session.add_all([real_alert_1, real_alert_2])
    db_session.commit()

    # 3. Request stats as unauthenticated anonymous visitor
    resp = client.get("/api/v1/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()

    # CRITICAL SECURITY ASSERTION: Anonymous client must receive 0 alerts,
    # because NO SIMULATED_DEMO alerts exist in database. Genuine host alerts are withheld!
    assert data["total_alerts"] == 0
    assert data["critical_count"] == 0
    assert data["high_count"] == 0
    assert data["total_incidents"] == 0

    # 4. Now request stats as authenticated Analyst
    analyst_key = settings.ANALYST_API_KEY
    resp_auth = client.get("/api/v1/dashboard/stats", headers={"X-API-Key": analyst_key})
    assert resp_auth.status_code == 200
    data_auth = resp_auth.json()

    # Authenticated analyst receives the real operational metrics
    assert data_auth["total_alerts"] == 2
    assert data_auth["critical_count"] == 1
    assert data_auth["high_count"] == 1

def test_dashboard_stats_demo_alerts_accessible_to_anonymous(db_session):
    """
    Verify that when SIMULATED_DEMO alerts exist, anonymous visitors
    can view the demonstration counts without exposing real alerts.
    """
    client = TestClient(app)

    # 1. Clean slate
    db_session.query(Alert).delete()
    db_session.query(Incident).delete()
    db_session.commit()

    # 2. Add 1 genuine alert and 2 demo alerts
    real_alert = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Host_Security_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="credential_dumping",
        description="Genuine memory dump",
        severity="CRITICAL",
        risk_score=90.0,
        status="OPEN"
    )
    demo_alert_1 = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Simulator",
        telemetry_origin="SIMULATED_DEMO",
        event_type="demo_scan",
        description="Synthetic demo port scan",
        severity="LOW",
        risk_score=15.0,
        status="OPEN"
    )
    demo_alert_2 = Alert(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="Simulator",
        telemetry_origin="SIMULATED_DEMO",
        event_type="demo_login",
        description="Synthetic demo login attempt",
        severity="MEDIUM",
        risk_score=45.0,
        status="OPEN"
    )
    db_session.add_all([real_alert, demo_alert_1, demo_alert_2])
    db_session.commit()

    # Anonymous request should only see the 2 demo alerts
    resp = client.get("/api/v1/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_alerts"] == 2
    assert data["critical_count"] == 0  # real alert withheld!
    assert data["low_count"] == 1
    assert data["medium_count"] == 1

    # Authenticated Analyst sees real operational alert (filtering out demo)
    resp_auth = client.get("/api/v1/dashboard/stats", headers={"X-API-Key": settings.ANALYST_API_KEY})
    assert resp_auth.status_code == 200
    data_auth = resp_auth.json()
    assert data_auth["total_alerts"] == 1
    assert data_auth["critical_count"] == 1
    assert data_auth["low_count"] == 0

def test_monitoring_and_simulation_toggle_authorization():
    """
    Test RBAC authorization on host monitoring and threat simulation toggles.
    """
    client = TestClient(app)

    # Anonymous attempts to toggle monitoring or simulation must be rejected (401 Unauthorized)
    resp_mon_anon = client.post("/api/v1/host/monitor/toggle?active=false")
    assert resp_mon_anon.status_code == 401

    resp_sim_anon = client.post("/api/v1/simulation/toggle?active=true")
    assert resp_sim_anon.status_code == 401

    # Authenticated Analyst can toggle monitoring
    analyst_key = settings.ANALYST_API_KEY
    resp_mon = client.post("/api/v1/host/monitor/toggle?active=false", headers={"X-API-Key": analyst_key})
    assert resp_mon.status_code == 200
    assert resp_mon.json()["host_monitoring_active"] is False

    # Restore monitoring
    resp_mon_on = client.post("/api/v1/host/monitor/toggle?active=true", headers={"X-API-Key": analyst_key})
    assert resp_mon_on.status_code == 200
    assert resp_mon_on.json()["host_monitoring_active"] is True

    # Toggle simulation
    resp_sim = client.post("/api/v1/simulation/toggle?active=true", headers={"X-API-Key": analyst_key})
    assert resp_sim.status_code == 200
    assert resp_sim.json()["simulation_active"] is True

    # Check status endpoint
    resp_status = client.get("/api/v1/stream/status")
    assert resp_status.status_code == 200
    status_data = resp_status.json()
    assert status_data["host_monitoring_active"] is True
    assert status_data["simulation_active"] is True
