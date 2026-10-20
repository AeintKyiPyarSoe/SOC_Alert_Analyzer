import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

class ThreatStreamManager:
    """
    Manages WebSocket connections and broadcasts real-time threat telemetry
    with distinct origin tags (HOST_TELEMETRY, SIMULATED_DEMO, SECURITY_DRILL, HISTORICAL_LOG).
    Enforces authorization separation so unauthenticated, guest, or viewer clients never receive
    sensitive genuine host telemetry or unmasked host heartbeats.
    """

    def __init__(self):
        self.active_connections: Dict[WebSocket, Any] = {}
        self.host_monitoring_active: bool = True
        self.simulation_active: bool = False
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user: Optional[Any] = None):
        await websocket.accept()
        async with self._lock:
            self.active_connections[websocket] = user
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.pop(websocket, None)
        logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """
        Broadcast message safely, strictly filtering sensitive genuine host telemetry
        from unauthenticated, demo-only, or viewer clients.
        Delivers sanitized demonstration telemetry to unprivileged clients when appropriate.
        """
        dead_connections = []
        async with self._lock:
            current_connections = list(self.active_connections.items())

        msg_origin = message.get("origin") or message.get("alert", {}).get("telemetry_origin", "")
        msg_type = message.get("type", "")

        is_sensitive = (
            msg_origin in ("HOST_TELEMETRY", "REAL_THREAT")
            or msg_type in ("REAL_THREAT", "HOST_AUDIT", "HOST_TELEMETRY")
            or (msg_type == "HEARTBEAT" and not message.get("sanitized", False))
        )

        for connection, user in current_connections:
            # Determine client authorization
            is_privileged = False
            if user is not None:
                username = getattr(user, "username", "")
                role = getattr(user, "role", None)
                role_val = getattr(role, "value", str(role or "")).upper()
                if username not in ("anonymous", "demo_viewer") and role_val in ("ADMIN", "ANALYST"):
                    is_privileged = True

            # If sensitive genuine host telemetry, withhold or sanitize for unprivileged clients
            if is_sensitive and not is_privileged:
                if msg_type == "HEARTBEAT":
                    sanitized_heartbeat = {
                        "type": "HEARTBEAT",
                        "origin": "SIMULATED_DEMO",
                        "sanitized": True,
                        "host_info": {
                            "hostname": "demo-soc-sensor-01",
                            "platform": "Demo Security Environment",
                            "os": "Demonstration Telemetry",
                            "cpu_percent": 14.5,
                            "memory_percent": 38.2,
                            "process_count": 86,
                            "interfaces": ["eth0 (demo)"],
                            "listening_ports": [80, 443],
                            "monitoring_active": self.host_monitoring_active,
                            "simulation_active": self.simulation_active,
                            "sanitized": True,
                            "auth_required_notice": "Authentication required for live genuine host telemetry."
                        }
                    }
                    try:
                        await connection.send_json(sanitized_heartbeat)
                    except (WebSocketDisconnect, RuntimeError, Exception) as e:
                        logger.debug(f"Client disconnected during sanitized heartbeat broadcast: {e}")
                        dead_connections.append(connection)
                # Sensitive real threats or host audits are completely withheld from unprivileged viewers
                continue

            try:
                await connection.send_json(message)
            except (WebSocketDisconnect, RuntimeError, Exception) as e:
                logger.debug(f"Client disconnected during broadcast: {e}")
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    self.active_connections.pop(dead, None)

stream_manager = ThreatStreamManager()
