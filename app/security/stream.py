import asyncio
import logging
import threading
from enum import Enum
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
from app.config import settings, load_monitoring_preferences, save_monitoring_preferences

logger = logging.getLogger(__name__)

class TaskCancellationResult(str, Enum):
    TERMINATED = "TERMINATED"
    TIMED_OUT = "TIMED_OUT"
    ALREADY_COMPLETED = "ALREADY_COMPLETED"
    FAILED = "FAILED"


class ThreatStreamManager:
    """
    Manages WebSocket connections and broadcasts real-time threat telemetry
    with distinct origin tags (HOST_TELEMETRY, SIMULATED_DEMO, SECURITY_DRILL, HISTORICAL_LOG).
    Enforces authorization separation so unauthenticated, guest, or viewer clients never receive
    sensitive genuine host telemetry or unmasked host heartbeats.

    Concurrency Architecture:
    ThreatStreamManager utilizes a single designated owner event loop (the active FastAPI/Uvicorn
    application event loop or a dedicated background daemon loop) for all lifecycle transitions.
    All mutations to monitoring and simulation states are serialized on this owner loop using
    an asyncio.Lock (_owner_lifecycle_lock). When lifecycle operations (start_host_monitoring,
    stop_host_monitoring, start_simulation, stop_simulation) are invoked from other threads or
    foreign event loops, they are safely dispatched to the owner loop via asyncio.run_coroutine_threadsafe.
    No synchronous threading locks are ever held across await boundaries, completely eliminating
    thread starvation and event loop deadlock hazards.
    """

    def __init__(self):
        self.active_connections: Dict[WebSocket, Any] = {}
        _prefs = load_monitoring_preferences()
        self.host_monitoring_active: bool = _prefs.get("host_monitoring_active", getattr(settings, "HOST_MONITORING_ENABLED", True))
        self.simulation_active: bool = _prefs.get("simulation_active", getattr(settings, "SIMULATION_ENABLED", False))
        self.last_persistence_status: Dict[str, Any] = {"persisted": True, "persistence_error": None}
        self._lock = asyncio.Lock()
        self._owner_lifecycle_lock: Optional[asyncio.Lock] = None
        self._owner_lifecycle_lock_loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread_lifecycle_init_lock = threading.Lock()
        self._monitor_task: Optional[asyncio.Task] = None
        self._simulator_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._bg_loop: Optional[asyncio.AbstractEventLoop] = None
        self._transition_state: Optional[str] = None
        self._sim_transition_state: Optional[str] = None
        self._transition_error: Optional[str] = None
        self._last_lifecycle_error: Optional[str] = None
        self._quiescence_confirmed: bool = True
        self._last_cancellation_result: Optional[TaskCancellationResult] = None

    def _get_owner_lock(self) -> asyncio.Lock:
        """
        Returns or creates an asyncio.Lock bound to the designated owner event loop.
        Explicitly tracks the owner event loop without relying on private asyncio.Lock._loop internals.
        Guarantees thread-safe and loop-safe initialization without holding any threading lock across awaits.
        """
        owner_loop = self._get_target_loop()
        with self._thread_lifecycle_init_lock:
            if (
                self._owner_lifecycle_lock is not None
                and self._owner_lifecycle_lock_loop is owner_loop
                and not owner_loop.is_closed()
            ):
                return self._owner_lifecycle_lock

            try:
                cur = asyncio.get_running_loop()
            except RuntimeError:
                cur = None

            if cur is owner_loop:
                self._owner_lifecycle_lock = asyncio.Lock()
            else:
                async def _make_lock():
                    return asyncio.Lock()
                fut = asyncio.run_coroutine_threadsafe(_make_lock(), owner_loop)
                self._owner_lifecycle_lock = fut.result(timeout=5.0)

            self._owner_lifecycle_lock_loop = owner_loop
            return self._owner_lifecycle_lock

    def _ensure_background_loop(self) -> asyncio.AbstractEventLoop:
        """Returns or provisions a dedicated persistent daemon event loop for background tasks."""
        if self._loop and self._loop.is_running():
            return self._loop
        if self._bg_loop and self._bg_loop.is_running():
            return self._bg_loop

        import threading
        ready_evt = threading.Event()

        def _runner():
            lp = asyncio.new_event_loop()
            asyncio.set_event_loop(lp)
            self._bg_loop = lp
            ready_evt.set()
            lp.run_forever()

        th = threading.Thread(target=_runner, daemon=True, name="soc-threat-stream-bg")
        th.start()
        ready_evt.wait(timeout=3.0)
        return self._bg_loop

    def _get_target_loop(self) -> asyncio.AbstractEventLoop:
        """Returns the registered application loop if active, or provisions the background loop."""
        if self._loop and self._loop.is_running() and not self._loop.is_closed():
            return self._loop
        try:
            cur = asyncio.get_running_loop()
            if self._loop is cur and cur.is_running() and not cur.is_closed():
                return cur
        except RuntimeError:
            pass
        return self._ensure_background_loop()

    def _spawn_task_on_loop(self, coro, loop: asyncio.AbstractEventLoop) -> asyncio.Task:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop is loop:
            return loop.create_task(coro)
        else:
            async def _spawn_helper():
                return loop.create_task(coro)
            fut = asyncio.run_coroutine_threadsafe(_spawn_helper(), loop)
            return fut.result(timeout=5.0)

    async def _cancel_and_await_task(self, task: Optional[asyncio.Task], timeout: float = 5.0) -> TaskCancellationResult:
        """
        Cancels and cleanly awaits completion of an asyncio Task across event loops.
        Returns explicit TaskCancellationResult (TERMINATED, TIMED_OUT, ALREADY_COMPLETED, FAILED)
        rather than suppressing timeout or failure exceptions.
        """
        if task is None or task.done():
            return TaskCancellationResult.ALREADY_COMPLETED

        task_loop = getattr(task, "get_loop", lambda: None)()
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop and current_loop is task_loop:
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
                return TaskCancellationResult.TERMINATED if task.done() else TaskCancellationResult.TIMED_OUT
            except (asyncio.CancelledError, TimeoutError, asyncio.TimeoutError):
                if task.done():
                    return TaskCancellationResult.TERMINATED
                logger.warning(f"Task cancellation timed out after {timeout}s: {task}")
                return TaskCancellationResult.TIMED_OUT
            except Exception as e:
                logger.error(f"Task cancellation finished with exception: {e}", exc_info=True)
                return TaskCancellationResult.FAILED if task.done() else TaskCancellationResult.TIMED_OUT
        elif task_loop and task_loop.is_running():
            async def _worker():
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=timeout)
                    return TaskCancellationResult.TERMINATED
                except (asyncio.CancelledError, TimeoutError, asyncio.TimeoutError):
                    return TaskCancellationResult.TERMINATED if task.done() else TaskCancellationResult.TIMED_OUT
                except Exception:
                    return TaskCancellationResult.FAILED if task.done() else TaskCancellationResult.TIMED_OUT

            fut = asyncio.run_coroutine_threadsafe(_worker(), task_loop)
            try:
                res = fut.result(timeout=timeout + 1.0)
                return res
            except Exception as e:
                logger.warning(f"Cross-loop cancellation future completed with: {e}")
                return TaskCancellationResult.TIMED_OUT if not task.done() else TaskCancellationResult.TERMINATED
        else:
            task.cancel()
            return TaskCancellationResult.TERMINATED if task.done() else TaskCancellationResult.TIMED_OUT

    def get_status(self) -> Dict[str, Any]:
        """
        Return authoritative monitoring and simulation lifecycle status.
        Single source of truth for both REST and WebSocket status checks.
        Accurately reports task failure, clean exit, and in-flight transitions,
        strictly preventing claiming ACTIVE or PAUSED when workers are active or timed out.
        """
        from app.security.host_sensor import host_sensor
        auto_scan_in_progress = getattr(host_sensor, "auto_scan_in_progress", False)
        scan_in_progress = getattr(host_sensor, "scan_in_progress", False)

        task_running = self._monitor_task is not None and not self._monitor_task.done()
        task_error = None
        if self._monitor_task is not None and self._monitor_task.done():
            try:
                exc = self._monitor_task.exception()
                if exc:
                    task_error = str(exc)
            except (asyncio.CancelledError, Exception):
                pass

        if self._transition_error == "PAUSING_TIMED_OUT":
            if not auto_scan_in_progress and not scan_in_progress and (self._monitor_task is None or self._monitor_task.done()):
                self._transition_error = None
                self._quiescence_confirmed = True
                self._last_lifecycle_error = None

        if self._transition_state:
            effective_state = self._transition_state
        elif self._transition_error:
            effective_state = self._transition_error
        elif not self.host_monitoring_active:
            if not self._quiescence_confirmed or auto_scan_in_progress:
                effective_state = "PAUSING_TIMED_OUT"
            else:
                effective_state = "PAUSED"
        elif task_error:
            effective_state = "ERROR"
        elif task_running:
            effective_state = "ACTIVE"
        else:
            effective_state = "STOPPED"

        sim_task_running = self._simulator_task is not None and not self._simulator_task.done()
        sim_task_error = None
        if self._simulator_task is not None and self._simulator_task.done():
            try:
                exc = self._simulator_task.exception()
                if exc:
                    sim_task_error = str(exc)
            except (asyncio.CancelledError, Exception):
                pass

        if task_running:
            task_status = "RUNNING"
        elif self._transition_error == "PAUSING_TIMED_OUT":
            task_status = "TIMED_OUT"
        elif task_error:
            task_status = "ERROR"
        elif not self.host_monitoring_active:
            task_status = "PAUSED" if self._quiescence_confirmed and not auto_scan_in_progress else "TIMED_OUT"
        else:
            task_status = "STOPPED"

        if sim_task_running:
            sim_status = "RUNNING"
        elif sim_task_error:
            sim_status = "ERROR"
        elif not self.simulation_active:
            sim_status = "PAUSED"
        else:
            sim_status = "STOPPED"

        return {
            "host_monitoring_active": (effective_state == "ACTIVE"),
            "monitoring_state": effective_state,
            "desired_active": self.host_monitoring_active,
            "simulation_active": self.simulation_active,
            "task_status": task_status,
            "task_error": task_error,
            "last_lifecycle_error": self._last_lifecycle_error,
            "quiescence_confirmed": self._quiescence_confirmed,
            "cancellation_result": self._last_cancellation_result.value if self._last_cancellation_result else None,
            "simulation_task_status": sim_status,
            "simulation_task_error": sim_task_error,
            "scan_in_progress": scan_in_progress,
            "auto_scan_in_progress": auto_scan_in_progress,
            "connected_clients": len(self.active_connections),
            "persisted": self.last_persistence_status.get("persisted", True),
            "persistence_error": self.last_persistence_status.get("persistence_error"),
        }

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """Record the application event loop for dependable task creation across threads."""
        with self._thread_lifecycle_init_lock:
            if self._loop is not loop:
                self._loop = loop
                if self._owner_lifecycle_lock_loop is not loop:
                    self._owner_lifecycle_lock = None
                    self._owner_lifecycle_lock_loop = None

    async def start_host_monitoring(self, persist: bool = True) -> bool:
        """Start or resume real host security monitoring idempotently."""
        target_loop = self._get_target_loop()
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop is not target_loop and target_loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._start_host_monitoring_impl(persist), target_loop)
            return await asyncio.wrap_future(fut)
        return await self._start_host_monitoring_impl(persist)

    async def _start_host_monitoring_impl(self, persist: bool = True) -> bool:
        async with self._get_owner_lock():
            from app.security.host_sensor import host_sensor
            # Prevent starting a new scan generation while previous worker remains active
            if getattr(host_sensor, "auto_scan_in_progress", False):
                logger.warning("Cannot start host monitoring while previous audit worker is still active.")
                return False

            # Idempotent start: if already active and background task is running, return immediately
            if self.host_monitoring_active and self._monitor_task is not None and not self._monitor_task.done():
                return True

            self._transition_state = "RESUMING" if not self.host_monitoring_active else "STARTING"
            self._transition_error = None
            try:
                host_sensor.reset_cancellation()

                self.host_monitoring_active = True
                self._quiescence_confirmed = True
                self._last_lifecycle_error = None
                if persist:
                    try:
                        res = save_monitoring_preferences(host_monitoring=True, simulation=self.simulation_active)
                        self.last_persistence_status = {
                            "persisted": res.get("persisted", True),
                            "persistence_error": res.get("persistence_error")
                        }
                    except Exception as e:
                        self.last_persistence_status = {"persisted": False, "persistence_error": str(e)}
                        logger.warning(f"Failed to persist host monitoring preference: {e}")

                loop = self._get_target_loop()
                if loop and (self._monitor_task is None or self._monitor_task.done()):
                    from app.security.host_sensor import real_host_monitor_loop
                    self._monitor_task = self._spawn_task_on_loop(real_host_monitor_loop(), loop)
                    logger.info("Spawned host monitor background task.")
            finally:
                self._transition_state = None
            return self.host_monitoring_active

    async def stop_host_monitoring(self, persist: bool = True, timeout: float = 5.0) -> bool:
        """
        Pause real host security monitoring idempotently, serialize lifecycle transitions,
        and cleanly await cancellation of the running background task before returning.
        """
        target_loop = self._get_target_loop()
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop is not target_loop and target_loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._stop_host_monitoring_impl(persist, timeout=timeout), target_loop)
            return await asyncio.wrap_future(fut)
        return await self._stop_host_monitoring_impl(persist, timeout=timeout)

    async def _stop_host_monitoring_impl(self, persist: bool = True, timeout: float = 5.0) -> bool:
        async with self._get_owner_lock():
            from app.security.host_sensor import host_sensor
            auto_in_prog = getattr(host_sensor, "auto_scan_in_progress", False)
            # Idempotent stop: if already paused, no task is running, quiescent, and no prior timeout
            if (
                not self.host_monitoring_active
                and (self._monitor_task is None or self._monitor_task.done())
                and not auto_in_prog
                and self._quiescence_confirmed
                and not self._transition_error
            ):
                self._monitor_task = None
                self._quiescence_confirmed = True
                self._transition_error = None
                return False

            self._transition_state = "PAUSING"
            try:
                host_sensor.request_cancellation()

                self.host_monitoring_active = False
                if persist:
                    try:
                        res = save_monitoring_preferences(host_monitoring=False, simulation=self.simulation_active)
                        self.last_persistence_status = {
                            "persisted": res.get("persisted", True),
                            "persistence_error": res.get("persistence_error")
                        }
                    except Exception as e:
                        self.last_persistence_status = {"persisted": False, "persistence_error": str(e)}
                        logger.warning(f"Failed to persist host monitoring preference: {e}")

                task = self._monitor_task
                cancel_res = TaskCancellationResult.ALREADY_COMPLETED
                if task and not task.done():
                    cancel_res = await self._cancel_and_await_task(task, timeout=timeout)
                    self._last_cancellation_result = cancel_res
                    logger.info(f"Host monitor task cancellation result: {cancel_res.value}")

                # Wait for running audit worker to reach quiescence
                quiescent = await host_sensor.wait_quiescence(timeout=timeout)

                timed_out = (cancel_res == TaskCancellationResult.TIMED_OUT) or (not quiescent) or (task is not None and not task.done())
                if timed_out:
                    self._last_lifecycle_error = (
                        f"Stop timeout: task_cancel={cancel_res.value}, quiescent={quiescent}"
                    )
                    self._transition_error = "PAUSING_TIMED_OUT"
                    self._quiescence_confirmed = False
                    logger.warning(
                        f"Host security sensor did not reach full quiescence within 5.0s on stop ({self._last_lifecycle_error})."
                    )
                    if task and task.done():
                        self._monitor_task = None
                    return False
                else:
                    self._monitor_task = None
                    self._transition_error = None
                    self._quiescence_confirmed = True
                    self._last_lifecycle_error = None
                    return False
            finally:
                self._transition_state = None

    async def start_simulation(self, persist: bool = True) -> bool:
        """Start or resume demonstration threat simulation idempotently."""
        target_loop = self._get_target_loop()
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop is not target_loop and target_loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._start_simulation_impl(persist), target_loop)
            return await asyncio.wrap_future(fut)
        return await self._start_simulation_impl(persist)

    async def _start_simulation_impl(self, persist: bool = True) -> bool:
        async with self._get_owner_lock():
            if self.simulation_active and self._simulator_task is not None and not self._simulator_task.done():
                return True

            self._sim_transition_state = "RESUMING" if not self.simulation_active else "STARTING"
            try:
                self.simulation_active = True
                if persist:
                    try:
                        res = save_monitoring_preferences(host_monitoring=self.host_monitoring_active, simulation=True)
                        self.last_persistence_status = {
                            "persisted": res.get("persisted", True),
                            "persistence_error": res.get("persistence_error")
                        }
                    except Exception as e:
                        self.last_persistence_status = {"persisted": False, "persistence_error": str(e)}
                        logger.warning(f"Failed to persist simulation preference: {e}")

                loop = self._get_target_loop()
                if loop and (self._simulator_task is None or self._simulator_task.done()):
                    from app.security.simulator import live_threat_simulator_loop
                    self._simulator_task = self._spawn_task_on_loop(live_threat_simulator_loop(), loop)
                    logger.info("Spawned simulator background task.")
            finally:
                self._sim_transition_state = None
            return self.simulation_active

    async def stop_simulation(self, persist: bool = True) -> bool:
        """Pause demonstration threat simulation idempotently and cancel the running background task."""
        target_loop = self._get_target_loop()
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop is not target_loop and target_loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._stop_simulation_impl(persist), target_loop)
            return await asyncio.wrap_future(fut)
        return await self._stop_simulation_impl(persist)

    async def _stop_simulation_impl(self, persist: bool = True) -> bool:
        async with self._get_owner_lock():
            if not self.simulation_active and (self._simulator_task is None or self._simulator_task.done()):
                self._simulator_task = None
                return False

            self._sim_transition_state = "PAUSING"
            try:
                self.simulation_active = False
                if persist:
                    try:
                        res = save_monitoring_preferences(host_monitoring=self.host_monitoring_active, simulation=False)
                        self.last_persistence_status = {
                            "persisted": res.get("persisted", True),
                            "persistence_error": res.get("persistence_error")
                        }
                    except Exception as e:
                        self.last_persistence_status = {"persisted": False, "persistence_error": str(e)}
                        logger.warning(f"Failed to persist simulation preference: {e}")

                task = self._simulator_task
                if task and not task.done():
                    await self._cancel_and_await_task(task)
                    logger.info("Cancelled and awaited simulator background task.")
                self._simulator_task = None
            finally:
                self._sim_transition_state = None
            return self.simulation_active

    def start_host_monitoring_sync(self, persist: bool = True) -> bool:
        """Synchronous wrapper for starting host monitoring across threads."""
        target_loop = self._loop if (self._loop and self._loop.is_running()) else None
        if not target_loop:
            target_loop = self._bg_loop if (self._bg_loop and self._bg_loop.is_running()) else None

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if target_loop and target_loop.is_running():
            if current_loop is target_loop:
                raise RuntimeError("Cannot synchronously block inside the target event loop")
            fut = asyncio.run_coroutine_threadsafe(self.start_host_monitoring(persist), target_loop)
            return fut.result(timeout=10)

        if current_loop and current_loop.is_running():
            bg = self._ensure_background_loop()
            fut = asyncio.run_coroutine_threadsafe(self.start_host_monitoring(persist), bg)
            return fut.result(timeout=10)

        return asyncio.run(self.start_host_monitoring(persist))

    def stop_host_monitoring_sync(self, persist: bool = True) -> bool:
        """Synchronous wrapper for stopping host monitoring across threads."""
        target_loop = self._loop if (self._loop and self._loop.is_running()) else None
        if not target_loop:
            target_loop = self._bg_loop if (self._bg_loop and self._bg_loop.is_running()) else None

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if target_loop and target_loop.is_running():
            if current_loop is target_loop:
                raise RuntimeError("Cannot synchronously block inside the target event loop")
            fut = asyncio.run_coroutine_threadsafe(self.stop_host_monitoring(persist), target_loop)
            return fut.result(timeout=10)

        if current_loop and current_loop.is_running():
            bg = self._ensure_background_loop()
            fut = asyncio.run_coroutine_threadsafe(self.stop_host_monitoring(persist), bg)
            return fut.result(timeout=10)

        return asyncio.run(self.stop_host_monitoring(persist))

    def start_simulation_sync(self, persist: bool = True) -> bool:
        """Synchronous wrapper for starting simulation across threads."""
        target_loop = self._loop if (self._loop and self._loop.is_running()) else None
        if not target_loop:
            target_loop = self._bg_loop if (self._bg_loop and self._bg_loop.is_running()) else None

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if target_loop and target_loop.is_running():
            if current_loop is target_loop:
                raise RuntimeError("Cannot synchronously block inside the target event loop")
            fut = asyncio.run_coroutine_threadsafe(self.start_simulation(persist), target_loop)
            return fut.result(timeout=10)

        if current_loop and current_loop.is_running():
            bg = self._ensure_background_loop()
            fut = asyncio.run_coroutine_threadsafe(self.start_simulation(persist), bg)
            return fut.result(timeout=10)

        return asyncio.run(self.start_simulation(persist))

    def stop_simulation_sync(self, persist: bool = True) -> bool:
        """Synchronous wrapper for stopping simulation across threads."""
        target_loop = self._loop if (self._loop and self._loop.is_running()) else None
        if not target_loop:
            target_loop = self._bg_loop if (self._bg_loop and self._bg_loop.is_running()) else None

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if target_loop and target_loop.is_running():
            if current_loop is target_loop:
                raise RuntimeError("Cannot synchronously block inside the target event loop")
            fut = asyncio.run_coroutine_threadsafe(self.stop_simulation(persist), target_loop)
            return fut.result(timeout=10)

        if current_loop and current_loop.is_running():
            bg = self._ensure_background_loop()
            fut = asyncio.run_coroutine_threadsafe(self.stop_simulation(persist), bg)
            return fut.result(timeout=10)

        return asyncio.run(self.stop_simulation(persist))

    def shutdown_sync(self):
        """Synchronous wrapper for shutting down all streaming and monitoring tasks."""
        target_loop = self._loop if (self._loop and self._loop.is_running()) else None
        if not target_loop:
            target_loop = self._bg_loop if (self._bg_loop and self._bg_loop.is_running()) else None

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if target_loop and target_loop.is_running():
            if current_loop is target_loop:
                raise RuntimeError("Cannot synchronously block inside the target event loop")
            fut = asyncio.run_coroutine_threadsafe(self.shutdown(), target_loop)
            return fut.result(timeout=10)

        if current_loop and current_loop.is_running():
            bg = self._ensure_background_loop()
            fut = asyncio.run_coroutine_threadsafe(self.shutdown(), bg)
            return fut.result(timeout=10)

        return asyncio.run(self.shutdown())

    async def shutdown(self):
        """Cleanly cancel and await all background monitoring and simulation tasks without overwriting persisted preferences."""
        try:
            from app.security.host_sensor import host_sensor
            host_sensor.request_cancellation()
        except Exception:
            pass

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
        with self._thread_lifecycle_init_lock:
            self._owner_lifecycle_lock = None
            self._owner_lifecycle_lock_loop = None
        try:
            from app.security.host_sensor import host_sensor
            quiescent = await host_sensor.wait_quiescence(timeout=2.0)
            if not quiescent:
                logger.warning("Host security sensor did not reach full quiescence within 2.0s on shutdown.")
        except Exception:
            pass
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
