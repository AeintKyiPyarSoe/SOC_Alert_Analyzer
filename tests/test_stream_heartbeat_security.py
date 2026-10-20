import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.stream import stream_manager
from app.security.session import session_manager
from app.config import settings

@pytest.mark.anyio
async def test_stream_heartbeat_sanitization_for_demo_clients(monkeypatch):
    """
    SECURITY REGRESSION TEST:
    Verify that genuine host HEARTBEAT messages broadcast by the host monitor
    are sanitized when delivered to demo viewers,
    preventing disclosure of real host specs, IP addresses, or platform details.
    """
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    client = TestClient(app)

    # 1. Connect demo WebSocket client
    with client.websocket_connect("/ws/threats", headers={"Origin": "http://127.0.0.1:8000"}) as ws:
        # 2. Broadcast a genuine sensitive HEARTBEAT containing private host telemetry
        sensitive_heartbeat = {
            "type": "HEARTBEAT",
            "origin": "HOST_TELEMETRY",
            "is_sensitive": True,
            "host_info": {
                "hostname": "prod-executive-laptop-09",
                "platform": "Windows 11 Enterprise x64",
                "os": "Windows",
                "cpu_percent": 78.4,
                "memory_percent": 82.1,
                "local_ips": ["10.200.1.45", "192.168.1.99"],
                "process_count": 284,
                "monitoring_active": True
            }
        }
        await stream_manager.broadcast(sensitive_heartbeat)

        # 3. Read message received by demo WebSocket client
        received = ws.receive_json()

        # CRITICAL ASSERTIONS:
        assert received["type"] == "HEARTBEAT"
        assert received.get("sanitized") is True
        # Real private host details MUST NOT be exposed!
        host_info = received["host_info"]
        assert host_info["hostname"] != "prod-executive-laptop-09"
        assert "10.200.1.45" not in host_info.get("local_ips", [])
        assert host_info["hostname"] == "demo-soc-sensor-01"

@pytest.mark.anyio
async def test_stream_heartbeat_delivered_raw_to_authenticated_analysts():
    """
    Verify that authenticated ANALYST clients receive genuine raw host telemetry heartbeats.
    """
    client = TestClient(app)

    # Obtain single-use WebSocket ticket for Analyst
    analyst_key = settings.ANALYST_API_KEY
    ticket_resp = client.post("/api/v1/auth/ws-ticket", headers={"X-API-Key": analyst_key})
    assert ticket_resp.status_code == 200
    ticket = ticket_resp.json()["ticket"]

    # Connect authenticated WebSocket client
    with client.websocket_connect(f"/ws/threats?ticket={ticket}", headers={"Origin": "http://127.0.0.1:8000"}) as ws:
        sensitive_heartbeat = {
            "type": "HEARTBEAT",
            "origin": "HOST_TELEMETRY",
            "is_sensitive": True,
            "host_info": {
                "hostname": "prod-executive-laptop-09",
                "platform": "Windows 11 Enterprise x64",
                "os": "Windows",
                "local_ips": ["10.200.1.45"],
                "monitoring_active": True
            }
        }
        await stream_manager.broadcast(sensitive_heartbeat)

        received = ws.receive_json()
        assert received["type"] == "HEARTBEAT"
        assert received.get("sanitized") is not True
        assert received["host_info"]["hostname"] == "prod-executive-laptop-09"

@pytest.mark.anyio
async def test_stream_real_threat_withheld_from_unprivileged_clients():
    """
    Verify that REAL_THREAT messages are completely withheld from unprivileged viewers.
    """
    client = TestClient(app)
    ticket = session_manager.create_ws_ticket(username="viewer_user", role="VIEWER")

    # 1. Connect unprivileged client
    with client.websocket_connect(f"/ws/threats?ticket={ticket}", headers={"Origin": "http://127.0.0.1:8000"}) as ws:
        # Broadcast real threat
        real_threat_payload = {
            "type": "REAL_THREAT",
            "origin": "HOST_TELEMETRY",
            "alert": {
                "description": "Procdump LSASS memory access",
                "telemetry_origin": "HOST_TELEMETRY"
            }
        }
        await stream_manager.broadcast(real_threat_payload)

        # Broadcast simulated demo threat
        demo_payload = {
            "type": "LIVE_THREAT",
            "origin": "SIMULATED_DEMO",
            "alert": {
                "description": "Synthetic demo attack",
                "telemetry_origin": "SIMULATED_DEMO"
            }
        }
        await stream_manager.broadcast(demo_payload)

        # Unauthenticated client should receive the demo payload directly, skipping the real threat
        received = ws.receive_json()
        assert received["type"] == "LIVE_THREAT"
        assert received["alert"]["description"] == "Synthetic demo attack"

@pytest.mark.anyio
async def test_stream_broadcast_malformed_messages_safe():
    """
    Verify that stream manager safely handles messages with missing or unexpected metadata.
    """
    # Empty message
    await stream_manager.broadcast({})

    # Missing origin and alert
    await stream_manager.broadcast({"type": "UNKNOWN_CUSTOM_TYPE"})

    # Non-dict or unexpected payload fields
    await stream_manager.broadcast({"type": "HEARTBEAT", "host_info": None})
