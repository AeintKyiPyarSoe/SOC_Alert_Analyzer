import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone
import uuid

from app.security.simulator import generate_and_save_live_threat, live_threat_simulator_loop
from app.security.stream import stream_manager
from app.security.auth import User, Role
from app.database.connection import SessionLocal
from app.models.alert import Alert

def test_generate_and_save_live_threat_isolation():
    db = SessionLocal()
    try:
        # Pre-seed a genuine real host alert
        real_alert = Alert(
            id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            risk_score=95,
            event_type="host_lsass_dump",
            description="Mimikatz memory dump on host",
            source_type="Host_Sensor",
            telemetry_origin="HOST_TELEMETRY",
            status="OPEN"
        )
        db.add(real_alert)
        db.commit()

        # Generate simulated demo threat
        payload = generate_and_save_live_threat()

        assert payload["type"] == "LIVE_THREAT"
        assert payload["origin"] == "SIMULATED_DEMO"
        assert payload["alert"]["telemetry_origin"] == "SIMULATED_DEMO"

        # Demonstration stats MUST NOT count the genuine host alert!
        stats = payload["stats"]
        # The demo count should only reflect SIMULATED_DEMO alerts
        demo_count = db.query(Alert).filter(Alert.telemetry_origin == "SIMULATED_DEMO").count()
        assert stats["total_alerts"] == demo_count
        # The genuine host alert is excluded from demo stats
        all_count = db.query(Alert).count()
        assert all_count > demo_count
    finally:
        # Clean up
        db.query(Alert).filter(Alert.description == "Mimikatz memory dump on host").delete()
        db.commit()
        db.close()

@pytest.mark.anyio
async def test_live_threat_simulator_loop_cancellation():
    stream_manager.simulation_active = True
    task = asyncio.create_task(live_threat_simulator_loop())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    stream_manager.simulation_active = False

@pytest.mark.anyio
async def test_live_threat_simulator_loop_emits_when_active(monkeypatch):
    stream_manager.simulation_active = True
    mock_ws = AsyncMock()
    user = User(username="analyst_test", role=Role.ANALYST)
    stream_manager.active_connections[mock_ws] = user

    broadcast_mock = AsyncMock()
    monkeypatch.setattr(stream_manager, "broadcast", broadcast_mock)

    # Patch sleep to avoid waiting
    sleep_calls = 0
    async def fast_sleep(sec):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls >= 2:
            raise asyncio.CancelledError()

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)

    task = asyncio.create_task(live_threat_simulator_loop())
    with pytest.raises(asyncio.CancelledError):
        await task

    assert broadcast_mock.called
    stream_manager.active_connections.pop(mock_ws, None)
    stream_manager.simulation_active = False
