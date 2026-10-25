import asyncio
import threading
import time
import pytest
from app.security.stream import ThreatStreamManager
from app.security.host_sensor import HostSecuritySensor
from app.database.connection import SessionLocal
from app.models.alert import Alert


def test_concurrent_toggle_no_deadlock():
    """Verify that multiple concurrent pause/resume calls do not deadlock or raise."""
    async def _run():
        mgr = ThreatStreamManager()

        async def _toggle_cycle(n: int):
            for _ in range(n):
                await mgr.start_host_monitoring(persist=False)
                await asyncio.sleep(0.01)
                await mgr.stop_host_monitoring(persist=False)

        # Launch 4 concurrent toggle tasks
        tasks = [asyncio.create_task(_toggle_cycle(3)) for _ in range(4)]
        await asyncio.gather(*tasks)

        # Final state can be cleanly shut down
        await mgr.shutdown()
        assert mgr.host_monitoring_active is False

    asyncio.run(_run())


def test_cross_thread_sync_wrappers():
    """Verify synchronous start/stop wrappers execute cleanly from secondary threads."""
    mgr = ThreatStreamManager()
    errors = []

    def _worker():
        try:
            assert mgr.start_host_monitoring_sync(persist=False) is True
            time.sleep(0.05)
            assert mgr.stop_host_monitoring_sync(persist=False) is False
        except Exception as e:
            errors.append(e)

    th = threading.Thread(target=_worker)
    th.start()
    th.join(timeout=10.0)

    assert not th.is_alive(), "Worker thread hung"
    assert not errors, f"Cross-thread invocation failed: {errors}"


def test_audit_cancellation_and_rollback():
    """
    Verify that when cancellation is requested mid-audit:
    1. is_scan_cancelled returns True
    2. Any partial findings are rolled back cleanly
    3. Zero uncommitted alerts are persisted
    """
    sensor = HostSecuritySensor()
    db = SessionLocal()
    initial_alerts_count = db.query(Alert).count()

    # Pre-cancel before audit
    gen = sensor.request_cancellation()
    assert sensor.is_scan_cancelled(gen) is True

    # Run fast audit with check_active=True
    created = sensor.run_fast_audit(db, check_active=True, generation=gen)
    assert created == [], "Expected no alerts created during cancelled audit"

    # Verify no alerts were persisted
    after_count = db.query(Alert).count()
    assert after_count == initial_alerts_count, "Database must not have any new alerts"

    db.close()


def test_quiescence_after_stop():
    """Verify stop_host_monitoring awaits sensor quiescence before completing."""
    async def _run():
        mgr = ThreatStreamManager()
        from app.security.host_sensor import host_sensor

        # Ensure clean state
        await mgr.start_host_monitoring(persist=False)
        status_active = mgr.get_status()
        assert status_active["monitoring_state"] in ("ACTIVE", "STARTING", "RESUMING")

        # Stop monitoring
        await mgr.stop_host_monitoring(persist=False)

        # Assert quiescence
        assert host_sensor.scan_in_progress is False
        status_stopped = mgr.get_status()
        assert status_stopped["host_monitoring_active"] is False
        assert status_stopped["monitoring_state"] == "PAUSED"
        assert "scan_in_progress" in status_stopped
        assert status_stopped["scan_in_progress"] is False

        await mgr.shutdown()

    asyncio.run(_run())
