import pytest
import asyncio
from unittest.mock import AsyncMock
from app.security.stream import ThreatStreamManager

from starlette.websockets import WebSocketDisconnect
from app.config import settings

def test_websocket_ping_pong(client):
    client.cookies["soc_api_key"] = settings.ADMIN_API_KEY
    with client.websocket_connect(f"/ws/threats?token={settings.ADMIN_API_KEY}") as ws:
        # Send keepalive ping
        ws.send_text("ping")
        data = ws.receive_text()
        assert data == "pong"

def test_websocket_unauthenticated_rejected(unauthenticated_client):
    # Unauthenticated remote websocket connection should be rejected with 1008 Policy Violation
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect("/ws/threats") as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

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
