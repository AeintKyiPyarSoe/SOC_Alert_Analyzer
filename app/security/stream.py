import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ThreatStreamManager:
    """Manages WebSocket connections and broadcasts real-time threat telemetry."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.simulation_active: bool = True
        self._simulator_task: asyncio.Task = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected web clients."""
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket client: {e}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

stream_manager = ThreatStreamManager()
