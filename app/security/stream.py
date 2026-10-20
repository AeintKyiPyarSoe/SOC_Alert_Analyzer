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
    sensitive genuine host telemetry.
    """

    def __init__(self):
        self.active_connections: Dict[WebSocket, Any] = {}
        self.simulation_active: bool = True
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
        """
        dead_connections = []
        async with self._lock:
            current_connections = list(self.active_connections.items())

        msg_origin = message.get("origin") or message.get("alert", {}).get("telemetry_origin", "")
        msg_type = message.get("type", "")
        is_sensitive = (msg_origin == "HOST_TELEMETRY" or msg_type == "REAL_THREAT")

        for connection, user in current_connections:
            # If sensitive genuine host telemetry, withhold unless authenticated as ADMIN or ANALYST
            if is_sensitive:
                if user is None:
                    continue
                username = getattr(user, "username", "")
                if username in ("anonymous", "demo_viewer"):
                    continue
                role = getattr(user, "role", None)
                role_val = getattr(role, "value", str(role or "")).upper()
                if role_val not in ("ADMIN", "ANALYST"):
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
