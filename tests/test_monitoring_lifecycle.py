import pytest
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


def test_task_unexpected_crash_reporting():
    """Verify stream_manager accurately reports ERROR when background task crashes unexpectedly."""
    from app.security.stream import stream_manager

    async def run_crash_test():
        async def crashing_coro():
            raise RuntimeError("Simulated unhandled sensor crash")

        task = asyncio.create_task(crashing_coro())
        try:
            await task
        except RuntimeError:
            pass

        stream_manager._monitor_task = task
        stream_manager.host_monitoring_active = True

        status = stream_manager.get_status()
        assert status["monitoring_state"] == "ERROR"
        assert status["task_status"] == "ERROR"
        assert "Simulated unhandled sensor crash" in status["task_error"]
        assert status["host_monitoring_active"] is False  # Must not falsely claim active when crashed!

        # Clean up
        stream_manager._monitor_task = None
        stream_manager.host_monitoring_active = True

    asyncio.run(run_crash_test())


def test_task_unexpected_clean_exit_reporting():
    """Verify stream_manager reports STOPPED when background task exits unexpectedly without exception."""
    from app.security.stream import stream_manager

    async def run_clean_exit_test():
        async def clean_exit_coro():
            return "finished unexpectedly"

        task = asyncio.create_task(clean_exit_coro())
        await task

        stream_manager._monitor_task = task
        stream_manager.host_monitoring_active = True

        status = stream_manager.get_status()
        assert status["monitoring_state"] == "STOPPED"
        assert status["task_status"] == "STOPPED"
        assert status["task_error"] is None
        assert status["host_monitoring_active"] is False  # Must not falsely claim active when stopped!

        # Clean up
        stream_manager._monitor_task = None
        stream_manager.host_monitoring_active = True

    asyncio.run(run_clean_exit_test())


def test_missing_task_reference_reporting():
    """Verify stream_manager reports STOPPED when host_monitoring_active is True but task is None."""
    from app.security.stream import stream_manager

    stream_manager._monitor_task = None
    stream_manager.host_monitoring_active = True

    status = stream_manager.get_status()
    assert status["monitoring_state"] == "STOPPED"
    assert status["task_status"] == "STOPPED"
    assert status["host_monitoring_active"] is False


def test_repeated_start_and_stop_idempotency():
    """Verify repeated starts and repeated stops are strictly idempotent."""
    async def run_idempotency():
        mgr = ThreatStreamManager()

        # Repeated start: only 1 task spawned
        await mgr.start_host_monitoring(persist=False)
        task1 = mgr._monitor_task
        assert task1 is not None and not task1.done()

        await mgr.start_host_monitoring(persist=False)
        task2 = mgr._monitor_task
        assert task1 is task2, "Repeated start must not replace running task!"

        # Repeated stop
        await mgr.stop_host_monitoring(persist=False)
        assert mgr._monitor_task is None
        assert mgr.host_monitoring_active is False

        # Second stop: no-op
        await mgr.stop_host_monitoring(persist=False)
        assert mgr._monitor_task is None
        assert mgr.host_monitoring_active is False

    asyncio.run(run_idempotency())


def test_simultaneous_toggle_serialization():
    """Verify concurrent toggles are serialized under lifecycle lock without race conditions."""
    async def run_concurrent_toggles():
        mgr = ThreatStreamManager()

        # Fire 5 concurrent start calls
        results = await asyncio.gather(
            mgr.start_host_monitoring(persist=False),
            mgr.start_host_monitoring(persist=False),
            mgr.start_host_monitoring(persist=False),
            mgr.start_host_monitoring(persist=False),
            mgr.start_host_monitoring(persist=False)
        )
        assert all(results)
        assert mgr.host_monitoring_active is True
        assert mgr._monitor_task is not None and not mgr._monitor_task.done()

        # Fire 5 concurrent stop calls
        stop_results = await asyncio.gather(
            mgr.stop_host_monitoring(persist=False),
            mgr.stop_host_monitoring(persist=False),
            mgr.stop_host_monitoring(persist=False),
            mgr.stop_host_monitoring(persist=False),
            mgr.stop_host_monitoring(persist=False)
        )
        assert not any(stop_results)
        assert mgr.host_monitoring_active is False
        assert mgr._monitor_task is None

    asyncio.run(run_concurrent_toggles())


def test_pause_during_audit_transaction_rollback(db_session, monkeypatch):
    """Verify that when pause occurs mid-audit, DB transaction is rolled back and in-flight alerts discarded."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.models.alert import Alert

    stream_manager.host_monitoring_active = True

    # Inject a step in audit_network_sockets that triggers a pause
    orig_audit_sockets = host_sensor.audit_network_sockets

    def pause_mid_audit():
        stream_manager.host_monitoring_active = False
        return orig_audit_sockets()

    monkeypatch.setattr(host_sensor, "audit_network_sockets", pause_mid_audit)

    alerts = host_sensor.run_full_audit(db_session, check_active=True)
    assert alerts == [], "In-flight alerts must be discarded when paused mid-audit!"
    # Verify no uncommitted alerts leaked into database
    assert db_session.query(Alert).count() == 0

    # Reset
    stream_manager.host_monitoring_active = True


# ==============================================================================
# PHASE 3: MANDATORY CANCELLATION TIMEOUT & QUIESCENCE REGRESSION TESTS (1-12)
# ==============================================================================

def test_pause_during_process_enumeration(db_session, monkeypatch):
    """1. Test cancellation during process enumeration immediately aborts and rolls back."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.models.alert import Alert

    stream_manager.host_monitoring_active = True
    gen = host_sensor.reset_cancellation()

    orig_audit_proc = host_sensor.audit_processes
    def cancel_during_proc():
        stream_manager.host_monitoring_active = False
        host_sensor.request_cancellation()
        return orig_audit_proc()

    monkeypatch.setattr(host_sensor, "audit_processes", cancel_during_proc)
    alerts = host_sensor.run_full_audit(db_session, check_active=True)
    assert alerts == [], "Expected zero alerts returned when cancelled during process enumeration"
    assert db_session.query(Alert).count() == 0, "No alerts should be persisted"
    stream_manager.host_monitoring_active = False


def test_pause_during_network_inspection(db_session, monkeypatch):
    """2. Test cancellation during network socket inspection cleanly rolls back."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.models.alert import Alert

    stream_manager.host_monitoring_active = True
    host_sensor.reset_cancellation()

    orig_audit_net = host_sensor.audit_network_sockets
    def cancel_during_net():
        stream_manager.host_monitoring_active = False
        host_sensor.request_cancellation()
        return orig_audit_net()

    monkeypatch.setattr(host_sensor, "audit_network_sockets", cancel_during_net)
    alerts = host_sensor.run_full_audit(db_session, check_active=True)
    assert alerts == []
    assert db_session.query(Alert).count() == 0
    stream_manager.host_monitoring_active = False


def test_pause_during_event_log_collection(db_session, monkeypatch):
    """3. Test cancellation during event-log collection cleanly rolls back."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.models.alert import Alert

    stream_manager.host_monitoring_active = True
    host_sensor.reset_cancellation()

    orig_audit_logs = host_sensor.audit_event_logs
    def cancel_during_logs():
        stream_manager.host_monitoring_active = False
        host_sensor.request_cancellation()
        return orig_audit_logs()

    monkeypatch.setattr(host_sensor, "audit_event_logs", cancel_during_logs)
    alerts = host_sensor.run_full_audit(db_session, check_active=True)
    assert alerts == []
    assert db_session.query(Alert).count() == 0
    stream_manager.host_monitoring_active = False


def test_pause_immediately_before_db_commit(db_session, monkeypatch):
    """4. Test cancellation immediately before database commit rolls back all staged entities."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.security.correlator import IncidentCorrelator
    from app.models.alert import Alert

    stream_manager.host_monitoring_active = True
    host_sensor.reset_cancellation()

    mock_event = {
        "source_type": "Host_Process_Sensor",
        "telemetry_origin": "HOST_TELEMETRY",
        "event_type": "suspicious_command",
        "description": "Pre-commit cancellation test alert",
        "timestamp": "2026-10-25 12:00:00",
        "severity": "HIGH",
        "risk_score": 75,
        "mitre_technique": "T1059"
    }

    monkeypatch.setattr(host_sensor, "audit_processes", lambda: [mock_event])
    monkeypatch.setattr(host_sensor, "audit_network_sockets", lambda: [])
    monkeypatch.setattr(host_sensor, "audit_startup_folder", lambda: [])
    monkeypatch.setattr(host_sensor, "audit_firewall_posture", lambda: [])
    monkeypatch.setattr(host_sensor, "audit_event_logs", lambda: [])

    orig_correlate = IncidentCorrelator.correlate_alerts
    def cancel_before_commit(db, window_seconds=None, commit=True):
        stream_manager.host_monitoring_active = False
        host_sensor.request_cancellation()
        return orig_correlate(db, window_seconds=window_seconds, commit=commit)

    monkeypatch.setattr(IncidentCorrelator, "correlate_alerts", cancel_before_commit)

    alerts = host_sensor.run_full_audit(db_session, check_active=True)
    assert alerts == [], "Staged alerts must be discarded when cancelled before commit"
    assert db_session.query(Alert).count() == 0, "No alerts may remain in DB"
    stream_manager.host_monitoring_active = False


def test_pause_during_incident_correlation(db_session, monkeypatch):
    """5. Test cancellation during incident correlation rolls back both alerts and incident records."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.security.correlator import IncidentCorrelator
    from app.models.alert import Alert
    from app.models.incident import Incident

    stream_manager.host_monitoring_active = True
    host_sensor.reset_cancellation()

    mock_event = {
        "source_type": "Host_Process_Sensor",
        "telemetry_origin": "HOST_TELEMETRY",
        "event_type": "suspicious_command",
        "description": "Mid-correlation cancellation test alert",
        "timestamp": "2026-10-25 12:00:00",
        "severity": "HIGH",
        "risk_score": 80,
        "mitre_technique": "T1059"
    }

    monkeypatch.setattr(host_sensor, "audit_processes", lambda: [mock_event])
    monkeypatch.setattr(host_sensor, "audit_network_sockets", lambda: [])
    monkeypatch.setattr(host_sensor, "audit_startup_folder", lambda: [])
    monkeypatch.setattr(host_sensor, "audit_firewall_posture", lambda: [])
    monkeypatch.setattr(host_sensor, "audit_event_logs", lambda: [])

    def cancel_in_correlator(db, window_seconds=None, commit=True):
        stream_manager.host_monitoring_active = False
        host_sensor.request_cancellation()
        return []

    monkeypatch.setattr(IncidentCorrelator, "correlate_alerts", cancel_in_correlator)

    alerts = host_sensor.run_full_audit(db_session, check_active=True)
    assert alerts == []
    assert db_session.query(Alert).count() == 0
    assert db_session.query(Incident).count() == 0
    stream_manager.host_monitoring_active = False


def test_pause_when_worker_blocked_times_out(monkeypatch):
    """6. Test stop operation when worker is blocked: cannot falsely report PAUSED."""
    async def _run():
        from app.security.stream import ThreatStreamManager
        from app.security.host_sensor import host_sensor

        mgr = ThreatStreamManager()
        # Simulate active worker blocked
        monkeypatch.setattr(type(host_sensor), "auto_scan_in_progress", property(lambda self: True))
        async def mock_wait_quiescence(timeout=5.0):
            return False

        monkeypatch.setattr(host_sensor, "wait_quiescence", mock_wait_quiescence)

        # Attempt to stop
        stopped = await mgr.stop_host_monitoring(persist=False, timeout=0.05)
        assert stopped is False

        # Status must accurately report incomplete transition / timeout, NOT PAUSED
        status = mgr.get_status()
        assert status["quiescence_confirmed"] is False
        assert status["monitoring_state"] == "PAUSING_TIMED_OUT"
        assert status["task_status"] == "TIMED_OUT"
        assert status["last_lifecycle_error"] is not None

        await mgr.shutdown()

    asyncio.run(_run())


def test_cancellation_timeout_preserves_task_reference(monkeypatch):
    """7. Test cancellation timeout preserves running task reference for diagnosis."""
    async def _run():
        from app.security.stream import ThreatStreamManager, TaskCancellationResult

        should_exit = False
        async def _stubborn_worker():
            while not should_exit:
                try:
                    await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    try:
                        asyncio.current_task().uncancel()
                    except Exception:
                        pass
                    try:
                        await asyncio.sleep(1.0)
                    except asyncio.CancelledError:
                        pass

        mgr = ThreatStreamManager()
        loop = asyncio.get_running_loop()
        task = loop.create_task(_stubborn_worker())
        await asyncio.sleep(0.01)
        mgr._monitor_task = task
        mgr.host_monitoring_active = True

        # Stop monitoring with short timeout
        stopped = await mgr.stop_host_monitoring(persist=False, timeout=0.05)
        assert stopped is False
        assert mgr._monitor_task is task, "Task reference must be preserved on cancellation timeout"
        assert not task.done(), "Task must still be running"

        status = mgr.get_status()
        assert status["monitoring_state"] == "PAUSING_TIMED_OUT"
        assert status["quiescence_confirmed"] is False

        # Cleanup
        should_exit = True
        await asyncio.sleep(0.05)
        await mgr.shutdown()

    asyncio.run(_run())


def test_repeated_pause_requests_after_timeout(monkeypatch):
    """8. Test repeated pause requests after timeout do not deadlock and remain safe."""
    async def _run():
        from app.security.stream import ThreatStreamManager
        from app.security.host_sensor import host_sensor

        mgr = ThreatStreamManager()
        monkeypatch.setattr(type(host_sensor), "auto_scan_in_progress", property(lambda self: True))
        async def mock_wait_quiescence(timeout=5.0):
            return False
        monkeypatch.setattr(host_sensor, "wait_quiescence", mock_wait_quiescence)

        # First pause attempt times out
        await mgr.stop_host_monitoring(persist=False, timeout=0.05)
        assert mgr.get_status()["monitoring_state"] == "PAUSING_TIMED_OUT"

        # Second pause attempt
        await mgr.stop_host_monitoring(persist=False, timeout=0.05)
        assert mgr.get_status()["monitoring_state"] == "PAUSING_TIMED_OUT"

        await mgr.shutdown()

    asyncio.run(_run())


def test_resume_prevented_while_worker_active(monkeypatch):
    """9. Test resume is rejected while previous audit worker remains active."""
    async def _run():
        from app.security.stream import ThreatStreamManager
        from app.security.host_sensor import host_sensor

        mgr = ThreatStreamManager()
        mgr.host_monitoring_active = False

        # Simulate previous worker still active
        monkeypatch.setattr(type(host_sensor), "auto_scan_in_progress", property(lambda self: True))

        resumed = await mgr.start_host_monitoring(persist=False)
        assert resumed is False, "Resume must be rejected while previous worker remains active"
        assert mgr.host_monitoring_active is False

        await mgr.shutdown()

    asyncio.run(_run())


def test_application_shutdown_during_blocked_scan(monkeypatch):
    """10. Test application shutdown cleanly executes without deadlock during a blocked scan."""
    async def _run():
        from app.security.stream import ThreatStreamManager
        from app.security.host_sensor import host_sensor

        mgr = ThreatStreamManager()
        # Simulate blocked quiescence on shutdown
        async def mock_quiescence(timeout=2.0):
            return False
        monkeypatch.setattr(host_sensor, "wait_quiescence", mock_quiescence)

        await mgr.shutdown()
        assert mgr.host_monitoring_active is False
        assert mgr._monitor_task is None

    asyncio.run(_run())


def test_recovery_after_worker_exits(monkeypatch):
    """11. Test clean recovery once blocked worker eventually exits."""
    async def _run():
        from app.security.stream import ThreatStreamManager
        from app.security.host_sensor import host_sensor

        mgr = ThreatStreamManager()

        # Step 1: Simulate timeout
        worker_active = True
        monkeypatch.setattr(type(host_sensor), "auto_scan_in_progress", property(lambda self: worker_active))
        async def mock_wait_quiescence(timeout=5.0):
            return not worker_active
        monkeypatch.setattr(host_sensor, "wait_quiescence", mock_wait_quiescence)

        await mgr.stop_host_monitoring(persist=False)
        assert mgr.get_status()["monitoring_state"] == "PAUSING_TIMED_OUT"

        # Step 2: Worker exits
        worker_active = False

        # Step 3: Check status reports clean PAUSED once quiescent
        status = mgr.get_status()
        assert status["monitoring_state"] == "PAUSED"

        # Step 4: Resume now succeeds cleanly
        res = await mgr.start_host_monitoring(persist=False)
        assert res is True
        assert mgr.host_monitoring_active is True

        await mgr.stop_host_monitoring(persist=False)
        await mgr.shutdown()

    asyncio.run(_run())


def test_no_automatic_alert_writes_after_confirmed_paused(db_session):
    """12. Test that no automatic alert writes can occur after confirmed PAUSED status."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager
    from app.models.alert import Alert

    stream_manager.host_monitoring_active = False
    host_sensor.request_cancellation()

    initial_alerts = db_session.query(Alert).count()

    # Attempt to run fast and full audits with check_active=True
    alerts_fast = host_sensor.run_fast_audit(db_session, check_active=True)
    alerts_full = host_sensor.run_full_audit(db_session, check_active=True)

    assert alerts_fast == []
    assert alerts_full == []
    assert db_session.query(Alert).count() == initial_alerts
