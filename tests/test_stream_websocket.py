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

def test_websocket_origin_validation_unit_tests():
    """Unit test complete scheme, hostname, and port validation logic in is_allowed_origin."""
    from app.security.auth import is_allowed_origin

    # Positive: Native / non-browser client without Origin header
    assert is_allowed_origin(None) is True

    # Positive: Standard desktop launcher origins
    assert is_allowed_origin("http://127.0.0.1:8000") is True
    assert is_allowed_origin("http://localhost:8000") is True
    assert is_allowed_origin("http://localhost:8050") is True
    assert is_allowed_origin("http://localhost:8080") is True
    assert is_allowed_origin("http://127.0.0.1:80") is True
    assert is_allowed_origin("https://127.0.0.1:443") is True

    # Negative: Arbitrary localhost ports rejected
    assert is_allowed_origin("http://localhost:3000") is False
    assert is_allowed_origin("http://127.0.0.1:9999") is False
    assert is_allowed_origin("http://localhost:4567") is False

    # Negative: Untrusted cross-origins
    assert is_allowed_origin("https://evil-attacker.com") is False
    assert is_allowed_origin("http://192.168.1.100:8000") is False

    # Negative: Malformed or non-http/https origins
    assert is_allowed_origin("") is False
    assert is_allowed_origin("null") is False
    assert is_allowed_origin("javascript:alert(1)") is False
    assert is_allowed_origin("file:///etc/passwd") is False
    assert is_allowed_origin("ws://localhost:8000") is False

def test_websocket_rejects_arbitrary_localhost_ports(unauthenticated_client):
    ticket = session_manager.create_ws_ticket(username="admin", role="ADMIN")
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect(
            f"/ws/threats?ticket={ticket}",
            headers={"Origin": "http://localhost:3000"}
        ) as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

def test_websocket_accepts_legitimate_desktop_launcher_origin(unauthenticated_client):
    ticket = session_manager.create_ws_ticket(username="admin", role="ADMIN")
    with unauthenticated_client.websocket_connect(
        f"/ws/threats?ticket={ticket}",
        headers={"Origin": "http://127.0.0.1:8000"}
    ) as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"

def test_websocket_rejects_legacy_token_and_api_key_query_params(unauthenticated_client):
    """Verify that legacy ?token= and ?api_key= query parameters are rejected."""
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect(f"/ws/threats?token={settings.ADMIN_API_KEY}") as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with unauthenticated_client.websocket_connect(f"/ws/threats?api_key={settings.ADMIN_API_KEY}") as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

