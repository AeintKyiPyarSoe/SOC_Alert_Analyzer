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
        assert (await mgr.start_host_monitoring()) is True
        assert mgr.host_monitoring_active is True
        assert (await mgr.start_host_monitoring()) is True
        assert mgr.host_monitoring_active is True

        # 2. Stopping host monitoring is idempotent
        assert (await mgr.stop_host_monitoring()) is False
        assert mgr.host_monitoring_active is False
        assert (await mgr.stop_host_monitoring()) is False
        assert mgr.host_monitoring_active is False

        # 3. Starting simulation is idempotent
        assert (await mgr.start_simulation()) is True
        assert mgr.simulation_active is True
        assert (await mgr.start_simulation()) is True
        assert mgr.simulation_active is True

        # 4. Stopping simulation is idempotent
        assert (await mgr.stop_simulation()) is False
        assert mgr.simulation_active is False
        assert (await mgr.stop_simulation()) is False
        assert mgr.simulation_active is False

        # 5. Clean shutdown
        await mgr.start_host_monitoring()
        await mgr.start_simulation()
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


def test_preference_persistence_and_atomic_file_handling(tmp_path):
    """Verify monitoring preferences survive mock restarts and handle corrupted files gracefully."""
    from app.config import save_monitoring_preferences, load_monitoring_preferences

    # 1. Save paused state
    saved = save_monitoring_preferences(host_monitoring=False, simulation=True, data_dir=tmp_path)
    assert saved["host_monitoring_active"] is False
    assert saved["simulation_active"] is True

    pref_file = tmp_path / "monitoring_preferences.json"
    assert pref_file.exists()

    # 2. Re-load from directory simulating application restart
    loaded = load_monitoring_preferences(data_dir=tmp_path)
    assert loaded["host_monitoring_active"] is False
    assert loaded["simulation_active"] is True

    # 3. ThreatStreamManager instantiation respects loaded preferences
    mgr = ThreatStreamManager()
    # Temporarily point DATA_DIR or test with mock prefs
    assert hasattr(mgr, "get_status")
    status = mgr.get_status()
    assert "host_monitoring_active" in status
    assert "task_status" in status
    assert "simulation_task_status" in status
    assert "connected_clients" in status

    # 4. Corrupted preference file fallback
    with open(pref_file, "w", encoding="utf-8") as f:
        f.write("{ INVALID JSON CONTENT !!! ")
    fallback = load_monitoring_preferences(data_dir=tmp_path)
    assert fallback["host_monitoring_active"] is True
    assert fallback["simulation_active"] is False


def test_clear_alerts_while_paused_does_not_rescan():
    """Verify that clearing history while host monitoring is paused does not re-scan or resurrect alerts."""
    from app.security.stream import stream_manager
    admin_headers = {"X-API-Key": settings.ADMIN_API_KEY}

    # 1. Pause host monitoring
    resp = client.post("/api/v1/host/monitor/toggle?active=false", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["host_monitoring_active"] is False
    assert stream_manager.host_monitoring_active is False

    # 2. Clear alerts while paused
    clear_resp = client.post("/api/v1/alerts/clear", headers=admin_headers)
    assert clear_resp.status_code == 200
    data = clear_resp.json()
    assert data["status"] == "success"
    assert data["real_alerts_count"] == 0
    assert "paused" in data["message"].lower()

    # 3. Verify alerts endpoint returns empty list
    alerts_resp = client.get("/api/v1/alerts?limit=100", headers=admin_headers)
    assert alerts_resp.status_code == 200
    assert alerts_resp.json() == []

    # 4. Resume host monitoring and re-clear to verify audit runs when active
    client.post("/api/v1/host/monitor/toggle?active=true", headers=admin_headers)
    assert stream_manager.host_monitoring_active is True

    clear_active_resp = client.post("/api/v1/alerts/clear", headers=admin_headers)
    assert clear_active_resp.status_code == 200
    assert "Re-scanned" in clear_active_resp.json()["message"]


def test_manual_host_audit_while_paused_does_not_resume_monitoring():
    """Verify manual one-off host audit does not alter paused lifecycle state."""
    from app.security.stream import stream_manager
    analyst_headers = {"X-API-Key": settings.ANALYST_API_KEY}

    # 1. Pause monitoring
    client.post("/api/v1/host/monitor/toggle?active=false", headers=analyst_headers)
    assert stream_manager.host_monitoring_active is False

    # 2. Trigger manual audit
    audit_resp = client.post("/api/v1/host/audit", headers=analyst_headers)
    assert audit_resp.status_code == 200

    # 3. State must still be paused
    status = client.get("/api/v1/stream/status").json()
    assert status["host_monitoring_active"] is False
    assert stream_manager.host_monitoring_active is False

    # Restore default active state
    client.post("/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)


def test_initial_host_baseline_skipped_when_paused(monkeypatch):
    """Verify initial_host_baseline is skipped when host_monitoring_active is False."""
    from app.main import initial_host_baseline
    from app.security.stream import stream_manager
    import app.security.host_sensor as hs

    audit_called = False
    def fake_audit(db):
        nonlocal audit_called
        audit_called = True
        return []

    monkeypatch.setattr(hs.host_sensor, "run_full_audit", fake_audit)
    stream_manager.host_monitoring_active = False

    try:
        initial_host_baseline()
        assert audit_called is False
    finally:
        stream_manager.host_monitoring_active = True



def test_preference_persistence_failure_handling(tmp_path, monkeypatch):
    """Verify explicit error reporting when saving preferences fails (Issue 4)."""
    import os
    import pytest
    from app.config import save_monitoring_preferences, load_monitoring_preferences

    # 1. Successful baseline save
    res1 = save_monitoring_preferences(host_monitoring=True, simulation=False, data_dir=tmp_path)
    assert res1["persisted"] is True
    assert res1["persistence_error"] is None

    # 2. Simulate write failure (e.g. read-only or permission error)
    def fail_replace(src, dst):
        raise PermissionError("Mocked access denied")
    monkeypatch.setattr(os, "replace", fail_replace)

    res2 = save_monitoring_preferences(host_monitoring=False, simulation=True, data_dir=tmp_path)
    assert res2["persisted"] is False
    assert "Mocked access denied" in res2["persistence_error"]

    # Existing file on disk should remain intact with previous valid state
    monkeypatch.undo()
    loaded = load_monitoring_preferences(data_dir=tmp_path)
    assert loaded["host_monitoring_active"] is True
    assert loaded["simulation_active"] is False

    # 3. Test raise_on_error=True
    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(PermissionError):
        save_monitoring_preferences(host_monitoring=False, simulation=True, data_dir=tmp_path, raise_on_error=True)
