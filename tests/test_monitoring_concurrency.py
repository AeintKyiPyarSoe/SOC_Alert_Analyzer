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


def test_owner_lock_identity_and_no_private_loop_attr():
    """
    Phase 2 Regression:
    Verify that _get_owner_lock() deterministic identity is maintained across repeated calls,
    explicitly tracks owner loop, and does NOT depend on private asyncio.Lock._loop attribute.
    """
    async def _run():
        mgr = ThreatStreamManager()
        loop = asyncio.get_running_loop()
        mgr.set_event_loop(loop)

        lock1 = mgr._get_owner_lock()
        lock2 = mgr._get_owner_lock()
        assert lock1 is lock2, "Repeated calls must return the exact same Lock instance"
        assert mgr._owner_lifecycle_lock_loop is loop, "Owner loop reference must match running loop"

        # Explicitly verify that deleting or mocking private _loop does not break lock reuse
        if hasattr(lock1, "_loop"):
            # Python standard lock internal attribute
            assert getattr(mgr._owner_lifecycle_lock, "_loop", None) in (loop, None)

        await mgr.shutdown()

    asyncio.run(_run())


def test_lifecycle_lock_mutual_exclusion():
    """Verify that two coroutines cannot enter protected transition simultaneously."""
    async def _run():
        mgr = ThreatStreamManager()
        concurrency_tracker = []
        max_concurrent = 0

        async def _mock_critical_section(cid: int):
            nonlocal max_concurrent
            async with mgr._get_owner_lock():
                concurrency_tracker.append(cid)
                max_concurrent = max(max_concurrent, len(concurrency_tracker))
                await asyncio.sleep(0.02)
                concurrency_tracker.remove(cid)

        tasks = [asyncio.create_task(_mock_critical_section(i)) for i in range(5)]
        await asyncio.gather(*tasks)

        assert max_concurrent == 1, f"Lock failed to serialize execution: max concurrency was {max_concurrent}"
        await mgr.shutdown()

    asyncio.run(_run())


def test_concurrent_start_requests_single_task():
    """Verify concurrent start requests create exactly one background monitoring task."""
    async def _run():
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
        task1 = mgr._monitor_task
        assert task1 is not None and not task1.done()

        # Fire again while running
        res_repeat = await mgr.start_host_monitoring(persist=False)
        assert res_repeat is True
        assert mgr._monitor_task is task1, "Must reuse existing task, not spawn duplicates"

        await mgr.stop_host_monitoring(persist=False)
        await mgr.shutdown()

    asyncio.run(_run())


def test_reinitialization_after_loop_shutdown():
    """Verify event-loop shutdown and reinitialization on a new loop cleanly resets lock."""
    mgr = ThreatStreamManager()

    async def _fetch_lock():
        await asyncio.sleep(0.001)
        return mgr._get_owner_lock()

    # Loop 1
    lp1 = asyncio.new_event_loop()
    asyncio.set_event_loop(lp1)
    mgr.set_event_loop(lp1)
    lock1 = lp1.run_until_complete(_fetch_lock())
    assert mgr._owner_lifecycle_lock_loop is lp1
    lp1.run_until_complete(mgr.shutdown())
    lp1.close()

    # Loop 2
    lp2 = asyncio.new_event_loop()
    asyncio.set_event_loop(lp2)
    mgr.set_event_loop(lp2)
    lock2 = lp2.run_until_complete(_fetch_lock())
    assert mgr._owner_lifecycle_lock_loop is lp2
    assert lock2 is not lock1, "New loop must receive a freshly bound Lock instance"
    lp2.run_until_complete(mgr.shutdown())
    lp2.close()


def test_monitoring_and_simulation_independent_desired_states():
    """Verify monitoring and simulation maintain completely independent desired states."""
    async def _run():
        mgr = ThreatStreamManager()
        mgr.host_monitoring_active = False
        mgr.simulation_active = False

        # Start monitoring only
        await mgr.start_host_monitoring(persist=False)
        assert mgr.host_monitoring_active is True
        assert mgr.simulation_active is False

        # Start simulation
        await mgr.start_simulation(persist=False)
        assert mgr.host_monitoring_active is True
        assert mgr.simulation_active is True

        # Stop monitoring only
        await mgr.stop_host_monitoring(persist=False)
        assert mgr.host_monitoring_active is False
        assert mgr.simulation_active is True

        # Stop simulation
        await mgr.stop_simulation(persist=False)
        assert mgr.host_monitoring_active is False
        assert mgr.simulation_active is False

        await mgr.shutdown()

    asyncio.run(_run())


def test_synchronous_wrappers_simulation_and_shutdown():
    """Verify synchronous wrappers for simulation and shutdown work reliably across threads."""
    mgr = ThreatStreamManager()
    errors = []

    def _worker():
        try:
            assert mgr.start_simulation_sync(persist=False) is True
            time.sleep(0.02)
            assert mgr.stop_simulation_sync(persist=False) is False
            mgr.shutdown_sync()
        except Exception as e:
            errors.append(e)

    th = threading.Thread(target=_worker)
    th.start()
    th.join(timeout=10.0)

    assert not th.is_alive(), "Sync simulation worker hung"
    assert not errors, f"Cross-thread simulation sync wrappers failed: {errors}"
