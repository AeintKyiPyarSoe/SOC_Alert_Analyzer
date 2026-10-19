import pytest
import asyncio
from unittest.mock import AsyncMock
from app.security.stream import ThreatStreamManager

def test_websocket_ping_pong(client):
    with client.websocket_connect("/ws/threats") as ws:
        # Send keepalive ping
        ws.send_text("ping")
        data = ws.receive_text()
        assert data == "pong"

def test_websocket_broadcast_with_origin_tag():
    manager = ThreatStreamManager()
    ws_mock = AsyncMock()

    async def run_broadcast_test():
        await manager.connect(ws_mock)
        assert len(manager.active_connections) == 1

        payload = {
            "type": "LIVE_THREAT",
            "origin": "HOST_TELEMETRY",
            "alert": {
                "description": "Suspicious process executed"
            }
        }

        await manager.broadcast(payload)
        ws_mock.send_json.assert_called_once_with(payload)

        await manager.disconnect(ws_mock)
        assert len(manager.active_connections) == 0

    asyncio.run(run_broadcast_test())

def test_stream_toggle_and_status(client):
    # Check initial status
    r = client.get("/api/v1/stream/status")
    assert r.status_code == 200
    assert "simulation_active" in r.json()

    # Toggle stream
    r = client.post("/api/v1/stream/toggle?active=false")
    assert r.status_code == 200
    assert r.json()["simulation_active"] is False

    # Restore
    r = client.post("/api/v1/stream/toggle?active=true")
    assert r.status_code == 200
    assert r.json()["simulation_active"] is True
