import asyncio
import logging
from typing import List, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

class ThreatStreamManager:
    """
    Manages WebSocket connections and broadcasts real-time threat telemetry
    with distinct origin tags (HOST_TELEMETRY, SIMULATED_DEMO, SECURITY_DRILL, IMPORTED_LOG).
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.simulation_active: bool = True
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """
        Broadcast message to all connected clients safely,
        pruning dead or timed-out sockets.
        """
        dead_connections = []
        async with self._lock:
            current_connections = list(self.active_connections)

        for connection in current_connections:
            try:
                await connection.send_json(message)
            except (WebSocketDisconnect, RuntimeError, Exception) as e:
                logger.debug(f"Client disconnected during broadcast: {e}")
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    if dead in self.active_connections:
                        self.active_connections.remove(dead)

stream_manager = ThreatStreamManager()
