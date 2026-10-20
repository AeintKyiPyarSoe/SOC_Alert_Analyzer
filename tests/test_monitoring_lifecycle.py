import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.security.stream import ThreatStreamManager

client = TestClient(app)


def test_monitoring_stream_manager_idempotency_and_lifecycle():
    """Verify start/stop idempotency, state flags, and cleanup."""
    async def _async_test():
        mgr = ThreatStreamManager()

        # Initial state agrees with settings or explicit defaults
        assert mgr.active_connections == {}

        # 1. Starting host monitoring is idempotent
        assert mgr.start_host_monitoring() is True
        assert mgr.host_monitoring_active is True
        assert mgr.start_host_monitoring() is True
        assert mgr.host_monitoring_active is True

        # 2. Stopping host monitoring is idempotent
        assert mgr.stop_host_monitoring() is False
        assert mgr.host_monitoring_active is False
        assert mgr.stop_host_monitoring() is False
        assert mgr.host_monitoring_active is False

        # 3. Starting simulation is idempotent
        assert mgr.start_simulation() is True
        assert mgr.simulation_active is True
        assert mgr.start_simulation() is True
        assert mgr.simulation_active is True

        # 4. Stopping simulation is idempotent
        assert mgr.stop_simulation() is False
        assert mgr.simulation_active is False
        assert mgr.stop_simulation() is False
        assert mgr.simulation_active is False

        # 5. Clean shutdown
        mgr.start_host_monitoring()
        mgr.start_simulation()
        assert mgr.host_monitoring_active is True
        assert mgr.simulation_active is True
        await mgr.shutdown()
        assert mgr.host_monitoring_active is False
        assert mgr.simulation_active is False
        assert mgr._monitor_task is None
        assert mgr._simulator_task is None

    asyncio.run(_async_test())


def test_monitoring_and_simulation_combinations_and_status():
    """Test API controls and /stream/status for all 4 state combinations."""
    analyst_headers = {"X-API-Key": settings.ANALYST_API_KEY}

    # Case A: Host active=True, Sim active=False
    client.post("/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)
    client.post("/api/v1/simulation/toggle?active=false", headers=analyst_headers)
    st = client.get("/api/v1/stream/status").json()
    assert st["host_monitoring_active"] is True
    assert st["simulation_active"] is False

    # Case B: Host active=False, Sim active=True
    client.post("/api/v1/host/monitor/toggle?active=false", headers=analyst_headers)
    client.post("/api/v1/simulation/toggle?active=true", headers=analyst_headers)
    st = client.get("/api/v1/stream/status").json()
    assert st["host_monitoring_active"] is False
    assert st["simulation_active"] is True

    # Case C: Both active=True
    client.post("/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)
    client.post("/api/v1/simulation/toggle?active=true", headers=analyst_headers)
    st = client.get("/api/v1/stream/status").json()
    assert st["host_monitoring_active"] is True
    assert st["simulation_active"] is True

    # Case D: Both active=False
    client.post("/api/v1/host/monitor/toggle?active=false", headers=analyst_headers)
    client.post("/api/v1/simulation/toggle?active=false", headers=analyst_headers)
    st = client.get("/api/v1/stream/status").json()
    assert st["host_monitoring_active"] is False
    assert st["simulation_active"] is False

    # Restore default
    client.post("/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)


def test_monitoring_controls_authorization_and_csrf():
    """Ensure anonymous requests and browser requests without CSRF are rejected."""
    # 1. Anonymous post fails 401
    r1 = client.post("/api/v1/host/monitor/toggle?active=false")
    assert r1.status_code == 401
    r2 = client.post("/api/v1/simulation/toggle?active=true")
    assert r2.status_code == 401

    # 2. Browser session without CSRF token fails 403
    login_resp = client.post("/api/v1/auth/login", json={"api_key": settings.ADMIN_API_KEY})
    assert login_resp.status_code == 200
    session_cookie = login_resp.cookies.get("soc_session")

    # Attempt state change with session cookie but missing X-CSRF-Token header
    bad_req = client.post(
        "/api/v1/host/monitor/toggle?active=false",
        headers={"Cookie": f"soc_session={session_cookie}"}
    )
    assert bad_req.status_code == 403
    assert "CSRF" in bad_req.json().get("detail", "")
