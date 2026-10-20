import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
from app.config import settings

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
        self.host_monitoring_active: bool = getattr(settings, "HOST_MONITORING_ENABLED", True)
        self.simulation_active: bool = getattr(settings, "SIMULATION_ENABLED", False)
        self._lock = asyncio.Lock()
        self._monitor_task: Optional[asyncio.Task] = None
        self._simulator_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None


    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """Record the application event loop for dependable task creation across threads."""
        self._loop = loop

    def start_host_monitoring(self) -> bool:
        """Start or resume real host security monitoring."""
        self.host_monitoring_active = True
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            if self._loop and self._loop.is_running():
                loop = self._loop

        if loop and (self._monitor_task is None or self._monitor_task.done()):
            from app.security.host_sensor import real_host_monitor_loop
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                current_loop = None

            if current_loop is loop:
                self._monitor_task = loop.create_task(real_host_monitor_loop())
            else:
                self._monitor_task = asyncio.run_coroutine_threadsafe(real_host_monitor_loop(), loop)
            logger.info("Spawned host monitor background task.")
        return self.host_monitoring_active

    def stop_host_monitoring(self) -> bool:
        """Pause real host security monitoring and cancel the running background task."""
        self.host_monitoring_active = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            self._monitor_task = None
            logger.info("Cancelled host monitor background task.")
        return self.host_monitoring_active

    def start_simulation(self) -> bool:
        """Start or resume demonstration threat simulation."""
        self.simulation_active = True
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            if self._loop and self._loop.is_running():
                loop = self._loop

        if loop and (self._simulator_task is None or self._simulator_task.done()):
            from app.security.simulator import live_threat_simulator_loop
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                current_loop = None

            if current_loop is loop:
                self._simulator_task = loop.create_task(live_threat_simulator_loop())
            else:
                self._simulator_task = asyncio.run_coroutine_threadsafe(live_threat_simulator_loop(), loop)
            logger.info("Spawned simulator background task.")
        return self.simulation_active

    def stop_simulation(self) -> bool:
        """Pause demonstration threat simulation and cancel the running background task."""
        self.simulation_active = False
        if self._simulator_task and not self._simulator_task.done():
            self._simulator_task.cancel()
            self._simulator_task = None
            logger.info("Cancelled simulator background task.")
        return self.simulation_active

    async def shutdown(self):
        """Cleanly cancel and await all background monitoring and simulation tasks."""
        self.host_monitoring_active = False
        self.simulation_active = False
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        tasks = []
        for t in (self._monitor_task, self._simulator_task):
            if t and not t.done():
                t.cancel()
                task_loop = getattr(t, "get_loop", lambda: None)()
                if current_loop and task_loop is current_loop:
                    tasks.append(t)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._monitor_task = None
        self._simulator_task = None
        logger.info("Cleanly shut down all background stream tasks.")

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
