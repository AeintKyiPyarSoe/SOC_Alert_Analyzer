import pytest
import asyncio
from unittest.mock import AsyncMock
from app.security.stream import ThreatStreamManager
from app.security.auth import User, Role
from app.security.session import session_manager
from starlette.websockets import WebSocketDisconnect
from app.config import settings

def test_websocket_ping_pong_via_session_cookie(unauthenticated_client):
    # Establish session
    login_resp = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert login_resp.status_code == 200

    # Connect via session cookie
    with unauthenticated_client.websocket_connect("/ws/threats") as ws:
        ws.send_text("ping")
        data = ws.receive_text()
        assert data == "pong"

def test_websocket_ping_pong_via_single_use_ticket(unauthenticated_client):
    ticket = session_manager.create_ws_ticket(username="analyst", role="ANALYST")
    with unauthenticated_client.websocket_connect(f"/ws/threats?ticket={ticket}") as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"

    # Ticket consumption is single-use; subsequent connection with same ticket rejected
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect(f"/ws/threats?ticket={ticket}") as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

def test_websocket_unauthenticated_rejected(unauthenticated_client):
    # Unauthenticated remote websocket connection without session or ticket rejected
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect("/ws/threats") as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

def test_websocket_invalid_cross_origin_rejected(unauthenticated_client):
    ticket = session_manager.create_ws_ticket(username="admin", role="ADMIN")
    # Connection from untrusted foreign origin must be rejected with 1008
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect(
            f"/ws/threats?ticket={ticket}",
            headers={"Origin": "https://malicious-attacker-site.com"}
        ) as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

def test_websocket_broadcast_filters_real_threats_from_demo_clients():
    manager = ThreatStreamManager()
    authenticated_ws = AsyncMock()
    demo_ws = AsyncMock()

    auth_user = User(username="admin", role=Role.ADMIN)
    demo_user = User(username="demo_viewer", role=Role.VIEWER)

    async def run_filter_test():
        await manager.connect(authenticated_ws, user=auth_user)
        await manager.connect(demo_ws, user=demo_user)
        assert len(manager.active_connections) == 2

        # 1. Real host threat should only reach authenticated user
        real_payload = {
            "type": "REAL_THREAT",
            "origin": "HOST_TELEMETRY",
            "alert": {"description": "Real malicious process detected"}
        }
        await manager.broadcast(real_payload)
        authenticated_ws.send_json.assert_called_once_with(real_payload)
        demo_ws.send_json.assert_not_called()

        # 2. Simulated demo threat reaches both
        demo_payload = {
            "type": "LIVE_THREAT",
            "origin": "SIMULATED_DEMO",
            "alert": {"description": "Simulated port probe"}
        }
        await manager.broadcast(demo_payload)
        assert demo_ws.send_json.call_count == 1

        await manager.disconnect(authenticated_ws)
        await manager.disconnect(demo_ws)
        assert len(manager.active_connections) == 0

    asyncio.run(run_filter_test())

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
