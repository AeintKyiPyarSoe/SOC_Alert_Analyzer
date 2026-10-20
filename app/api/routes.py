import uuid
import threading
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_, func

from app.config import settings
from app.database.connection import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.alert import (
    AlertResponse, AlertStatusUpdate, DashboardStats
)
from app.schemas.incident import (
    IncidentResponse, IncidentDetailResponse, IncidentStatusUpdate
)
from app.parsers import get_parser, detect_source_type
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator
from app.security.remediation import get_remediation_guidance
from app.security.mitre_mapper import MitreMapper
from app.security.auth import get_current_user, require_role, validate_token, Role, User
from app.security.session import session_manager
from app.security.upload_security import SecureUploadHandler
from app.security.stream import stream_manager

router = APIRouter()
logger = logging.getLogger(__name__)


class SecurityAuditTrail:
    """Thread-safe security audit trail for administrative operations."""
    def __init__(self, max_entries: int = 1000):
        self._entries: list = []
        self._lock = threading.Lock()
        self._max = max_entries

    def record(self, action: str, actor: str, role: str, client_ip: str, details: str = ""):
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "actor": actor,
                "role": role,
                "client_ip": client_ip,
                "details": details
            }
            self._entries.insert(0, entry)
            if len(self._entries) > self._max:
                self._entries.pop()

    def get_logs(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._entries[:limit])

audit_trail = SecurityAuditTrail()


# -------------------------------------------------------------
# REST API: Authentication & Session Management
# -------------------------------------------------------------

class LoginRequest(BaseModel):
    api_key: str

@router.get("/auth/me")
def get_auth_profile(request: Request, user: User = Depends(get_current_user)):
    """Inspect caller's current authentication identity, role, environment mode, and CSRF token."""
    csrf_token = None
    session_token = request.cookies.get("soc_session")
    if session_token:
        session = session_manager.get_session(session_token)
        if session:
            csrf_token = session.csrf_token

    return {
        "authenticated": user.username not in ("anonymous", "demo_viewer"),
        "username": user.username,
        "role": user.role.value,
        "demo_mode": settings.DEMO_MODE,
        "auth_enabled": settings.AUTH_ENABLED,
        "csrf_token": csrf_token
    }

@router.post("/auth/login")
def login_route(payload: LoginRequest, request: Request, response: Response):
    """
    Authenticate browser session with an API key, issuing an HttpOnly opaque session cookie
    and CSRF token. The raw API key is never placed in cookies or sent back to JavaScript.
    Protected by IP rate limiting and security audit logging.
    """
    client_ip = request.client.host if request.client else "unknown"

    # 1. Rate Limiting Check
    is_locked, remaining = session_manager.is_rate_limited(client_ip)
    if is_locked:
        audit_trail.record("AUTH_LOCKED_OUT", "anonymous", "NONE", client_ip, f"Blocked: {remaining}s remaining")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Temporarily locked out. Please retry in {remaining} seconds."
        )

    user = validate_token(payload.api_key)
    if not user:
        session_manager.record_login_attempt(client_ip, success=False)
        audit_trail.record("AUTH_LOGIN_FAILED", "anonymous", "NONE", client_ip, "Invalid API key attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key. Please check your credentials."
        )

    session_manager.record_login_attempt(client_ip, success=True)
    audit_trail.record("AUTH_LOGIN_SUCCESS", user.username, user.role.value, client_ip, "Session established")

    # Invalidate previous session token if rotating
    old_session = request.cookies.get("soc_session")
    if old_session:
        session_manager.revoke_session(old_session)

    session_token, csrf_token = session_manager.create_session(
        username=user.username,
        role=user.role.value,
        expiry_seconds=settings.SESSION_EXPIRY_SECONDS
    )

    # Set secure opaque session cookie
    response.set_cookie(
        key="soc_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_EXPIRY_SECONDS,
        path="/"
    )
    # Set CSRF cookie readable by frontend JavaScript for double-submit header
    response.set_cookie(
        key="soc_csrf",
        value=csrf_token,
        httponly=False,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_EXPIRY_SECONDS,
        path="/"
    )
    # Clear legacy plain API key cookie
    response.delete_cookie(key="soc_api_key", path="/")

    return {
        "status": "success",
        "username": user.username,
        "role": user.role.value,
        "csrf_token": csrf_token
    }

@router.post("/auth/logout")
def logout_route(request: Request, response: Response):
    """Revoke authenticated session on server and clear browser session cookies. Requires valid CSRF protection for active sessions."""
    session_token = request.cookies.get("soc_session")
    if session_token:
        session = session_manager.get_session(session_token.strip())
        if session:
            # Active browser session requires CSRF token verification
            client_csrf = request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")
            if not session_manager.validate_csrf(session, client_csrf):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF validation failed: Invalid or missing CSRF token."
                )
            session_manager.revoke_session(session_token.strip())

    response.delete_cookie(key="soc_session", path="/")
    response.delete_cookie(key="soc_csrf", path="/")
    response.delete_cookie(key="soc_api_key", path="/")
    return {
        "status": "success",
        "message": "Logged out successfully."
    }

@router.post("/auth/ws-ticket")
def request_websocket_ticket(user: User = Depends(get_current_user)):
    """
    Generate a short-lived single-use connection ticket for secure WebSocket handshakes.
    Eliminates long-lived keys in WebSocket URL query strings.
    """
    if user.username in ("anonymous", "demo_viewer") and not settings.DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to request a WebSocket connection ticket."
        )
    ticket = session_manager.create_ws_ticket(user.username, user.role.value)
    return {"ticket": ticket}

# -------------------------------------------------------------
# REST API: Alerts
# -------------------------------------------------------------

@router.post("/alerts/upload", status_code=status.HTTP_201_CREATED)
async def upload_log_file(
    file: UploadFile = File(...),
    source_type: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST))
):
    """
    Ingest a security log file with strict size enforcement, content validation,
    normalization, explainable risk scoring, and incident correlation.
    Requires ANALYST or ADMIN role.
    """
    # Securely read and validate file (size limit, magic bytes, encoding, path traversal)
    safe_filename, content = await SecureUploadHandler.read_and_validate_file(file)

    # Determine or auto-detect parser
    if not source_type or source_type.lower() == "auto":
        detected_source = detect_source_type(content)
    else:
        detected_source = source_type

    try:
        parser = get_parser(detected_source)
        raw_events = parser.parse(content)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Error parsing log file: {str(e)}"
        )

    if not raw_events:
        raise HTTPException(
            status_code=422,
            detail="No valid security alerts could be extracted from the uploaded file."
        )

    # Enforce maximum event count to prevent denial of service and memory exhaustion
    if len(raw_events) > settings.MAX_EVENTS_PER_UPLOAD:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded log file extracted {len(raw_events)} events, which exceeds the limit of {settings.MAX_EVENTS_PER_UPLOAD} events per upload."
        )

    # Normalize and persist alerts using bounded memory batches with recurrence tracking
    total_ingested = 0
    batch_chunk: List[Alert] = []
    batch_size = getattr(settings, "DB_BATCH_SIZE", 250)
    dedup_window = getattr(settings, "DEDUP_WINDOW_SECONDS", 300)

    # In-memory index of active candidate alerts for intra-batch recurrence deduplication:
    # Key: (origin, event_type, description, source_type, source_ip, destination_ip, username)
    # Value: List[Alert]
    active_candidates: dict = {}

    def _get_candidate_key(norm: dict, orig: str) -> tuple:
        return (
            orig,
            norm["event_type"],
            norm["description"],
            norm["source_type"],
            norm.get("source_ip"),
            norm.get("destination_ip"),
            norm.get("username"),
        )

    try:
        for raw_ev in raw_events:
            raw_ev.setdefault("telemetry_origin", "HISTORICAL_LOG")
            normalized = AlertNormalizer.normalize(raw_ev)
            ev_ts = normalized["timestamp"]
            if ev_ts.tzinfo is None:
                ev_ts = ev_ts.replace(tzinfo=timezone.utc)
            origin = normalized.get("telemetry_origin") or "HISTORICAL_LOG"

            window_start = ev_ts - timedelta(seconds=dedup_window)
            window_end = ev_ts + timedelta(seconds=dedup_window)
            cand_key = _get_candidate_key(normalized, origin)

            existing: Optional[Alert] = None

            # 1. Intra-batch fast lookup: Check in-memory active candidates from this ingestion run
            if cand_key in active_candidates:
                for cand in reversed(active_candidates[cand_key]):
                    c_first = cand.first_seen or cand.timestamp
                    if c_first.tzinfo is None:
                        c_first = c_first.replace(tzinfo=timezone.utc)
                    c_last = cand.last_seen or cand.timestamp
                    if c_last.tzinfo is None:
                        c_last = c_last.replace(tzinfo=timezone.utc)
                    if c_last >= window_start and c_first <= window_end:
                        existing = cand
                        break

            # 2. Database query fallback: If not matched in-memory, query database for pre-existing alerts
            if existing is None:
                origin_filter = (
                    or_(Alert.telemetry_origin == origin, Alert.telemetry_origin.is_(None))
                    if origin == "HISTORICAL_LOG"
                    else (Alert.telemetry_origin == origin)
                )
                existing = db.query(Alert).filter(
                    origin_filter,
                    Alert.event_type == normalized["event_type"],
                    Alert.description == normalized["description"],
                    Alert.source_type == normalized["source_type"],
                    Alert.source_ip == normalized.get("source_ip"),
                    Alert.destination_ip == normalized.get("destination_ip"),
                    Alert.username == normalized.get("username"),
                    Alert.status == "OPEN",
                    or_(
                        Alert.last_seen >= window_start,
                        and_(Alert.last_seen.is_(None), Alert.timestamp >= window_start)
                    ),
                    or_(
                        Alert.first_seen <= window_end,
                        and_(Alert.first_seen.is_(None), Alert.timestamp <= window_end)
                    )
                ).order_by(
                    desc(func.coalesce(Alert.last_seen, Alert.timestamp))
                ).first()

                if existing is not None:
                    active_candidates.setdefault(cand_key, []).append(existing)

            if existing is not None:
                existing.occurrence_count = (existing.occurrence_count or 1) + 1
                curr_first = existing.first_seen or existing.timestamp or ev_ts
                if curr_first.tzinfo is None:
                    curr_first = curr_first.replace(tzinfo=timezone.utc)
                curr_last = existing.last_seen or existing.timestamp or ev_ts
                if curr_last.tzinfo is None:
                    curr_last = curr_last.replace(tzinfo=timezone.utc)
                existing.first_seen = min(curr_first, ev_ts)
                existing.last_seen = max(curr_last, ev_ts)
                total_ingested += 1
                continue

            alert = Alert(
                id=uuid.uuid4(),
                timestamp=normalized["timestamp"],
                is_valid_timestamp=normalized["is_valid_timestamp"],
                source_type=normalized["source_type"],
                telemetry_origin=normalized["telemetry_origin"],
                event_type=normalized["event_type"],
                description=normalized["description"],
                source_ip=normalized["source_ip"],
                destination_ip=normalized["destination_ip"],
                source_port=normalized["source_port"],
                destination_port=normalized["destination_port"],
                username=normalized["username"],
                severity=normalized["severity"],
                risk_score=normalized["risk_score"],
                mitre_technique=normalized["mitre_technique"],
                status="OPEN",
                raw_log=normalized.get("raw_log"),
                occurrence_count=1,
                first_seen=normalized["timestamp"],
                last_seen=normalized["timestamp"]
            )
            db.add(alert)
            batch_chunk.append(alert)
            active_candidates.setdefault(cand_key, []).append(alert)
            total_ingested += 1

            # Periodically flush in bounded batches to balance memory and I/O
            if len(batch_chunk) >= batch_size:
                db.flush()
                batch_chunk.clear()

        # Final flush for any remaining batched alerts before correlation
        if batch_chunk:
            db.flush()
            batch_chunk.clear()

        # Trigger Incident Correlation within the protected transaction
        incidents = IncidentCorrelator.correlate_alerts(db)

        # Commit entire atomic transaction (alerts + incidents)
        db.commit()

    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        logger.error(f"Error during alert ingestion from '{safe_filename}': {exc}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Database transaction failure during alert ingestion: {str(exc)}"
        )

    return {
        "status": "success",
        "message": f"Successfully ingested {total_ingested} alerts from '{safe_filename}'.",
        "source_type_used": detected_source,
        "alerts_count": total_ingested,
        "incidents_created": len(incidents)
    }

@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)"),
    source_type: Optional[str] = Query(None, description="Filter by source tool (Wazuh, Suricata, Linux_Auth)"),
    origin: Optional[str] = Query(None, description="Filter by telemetry origin (HOST_TELEMETRY, HISTORICAL_LOG, SIMULATED_DEMO, SECURITY_DRILL)"),
    search: Optional[str] = Query(None, description="Search across IP, username, description"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Retrieve normalized alerts with multi-attribute filtering and pagination."""
    query = db.query(Alert)

    # Protect sensitive genuine host alerts from unauthenticated anonymous users
    if user.username in ("anonymous", "demo_viewer"):
        query = query.filter(Alert.telemetry_origin == "SIMULATED_DEMO")

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status_filter:
        query = query.filter(Alert.status == status_filter.upper())
    if source_type:
        query = query.filter(Alert.source_type.ilike(f"%{source_type}%"))
    if origin:
        query = query.filter(Alert.telemetry_origin == origin.upper())
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Alert.source_ip.ilike(s),
                Alert.destination_ip.ilike(s),
                Alert.username.ilike(s),
                Alert.description.ilike(s),
                Alert.event_type.ilike(s)
            )
        )

    alerts = query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit).all()
    return alerts

@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Retrieve single alert with full plain-language investigation guidance."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    if user.username in ("anonymous", "demo_viewer") and alert.telemetry_origin != "SIMULATED_DEMO":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view genuine telemetry forensic details."
        )

    guidance = get_remediation_guidance(alert.event_type, alert.description)
    mitre_info = MitreMapper.get_details(alert.mitre_technique)

    alert_resp = AlertResponse.model_validate(alert)
    if user.username in ("anonymous", "demo_viewer"):
        alert_resp.raw_log = None

    return {
        "alert": alert_resp,
        "guidance": guidance,
        "mitre_details": mitre_info
    }

@router.patch("/alerts/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST))
):
    """Transition alert through investigation lifecycle states. Requires ANALYST or ADMIN role."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert

@router.delete("/alerts/{alert_id}", status_code=status.HTTP_200_OK)
def delete_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMIN))
):
    """Permanently delete an individual alert record. Requires ADMIN role."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    db.delete(alert)
    db.commit()
    return {
        "status": "success",
        "message": f"Alert '{alert_id}' deleted successfully."
    }

# -------------------------------------------------------------
# REST API: Incidents
# -------------------------------------------------------------

@router.get("/incidents", response_model=List[IncidentResponse])
def get_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Retrieve correlated incidents list with pagination."""
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    # Protect sensitive genuine incidents from unauthenticated anonymous users
    if user.username in ("anonymous", "demo_viewer"):
        query = query.filter(~Incident.alerts.any(Alert.telemetry_origin != "SIMULATED_DEMO"))
    incidents = query.order_by(desc(Incident.risk_score), desc(Incident.last_seen)).offset(offset).limit(limit).all()
    return incidents

@router.get("/incidents/{incident_id}")
def get_incident_detail(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Retrieve incident details including member alerts and remediation checklist."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if user.username in ("anonymous", "demo_viewer"):
        has_real_alerts = any(a.telemetry_origin != "SIMULATED_DEMO" for a in incident.alerts)
        if has_real_alerts:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to view genuine incident telemetry."
            )

    guidance = get_remediation_guidance(incident.title, incident.description)
    mitre_info = MitreMapper.get_details(incident.mitre_technique)

    return {
        "incident": IncidentDetailResponse.model_validate(incident),
        "guidance": guidance,
        "mitre_details": mitre_info
    }

@router.patch("/incidents/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST))
):
    """Update status of an incident and cascade to linked alerts. Requires ANALYST or ADMIN role."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    incident.status = payload.status
    for alert in incident.alerts:
        alert.status = payload.status

    db.commit()
    db.refresh(incident)
    return incident

# -------------------------------------------------------------
# REST API: Dashboard Stats (SQL-Level Aggregation)
# -------------------------------------------------------------

@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Calculate aggregated metrics using high-performance SQL group-by queries.
    Enforces user-aware authorization: anonymous/demo clients only receive statistics
    derived from SIMULATED_DEMO telemetry, preventing exposure of private operational metrics.
    """
    if user.username in ("anonymous", "demo_viewer"):
        base_q = db.query(Alert).filter(Alert.telemetry_origin == "SIMULATED_DEMO")
        incidents_q = db.query(Incident).filter(~Incident.alerts.any(Alert.telemetry_origin != "SIMULATED_DEMO"))
        total_incidents = incidents_q.with_entities(func.count(Incident.id)).scalar() or 0
    else:
        base_q = db.query(Alert)
        if not settings.DEMO_MODE:
            base_q = base_q.filter(Alert.telemetry_origin != "SIMULATED_DEMO")
            total_incidents = db.query(func.count(Incident.id)).filter(
                Incident.alerts.any(Alert.telemetry_origin != "SIMULATED_DEMO")
            ).scalar() or 0
        else:
            total_incidents = db.query(func.count(Incident.id)).scalar() or 0

    total_alerts = base_q.with_entities(func.count(Alert.id)).scalar() or 0

    sev_rows = base_q.with_entities(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    sev_map = {row[0]: row[1] for row in sev_rows}

    status_rows = base_q.with_entities(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    status_map = {row[0]: row[1] for row in status_rows}

    return DashboardStats(
        total_alerts=total_alerts,
        critical_count=sev_map.get("CRITICAL", 0),
        high_count=sev_map.get("HIGH", 0),
        medium_count=sev_map.get("MEDIUM", 0),
        low_count=sev_map.get("LOW", 0),
        open_count=status_map.get("OPEN", 0),
        investigating_count=status_map.get("INVESTIGATING", 0),
        resolved_count=status_map.get("RESOLVED", 0),
        false_positive_count=status_map.get("FALSE_POSITIVE", 0),
        total_incidents=total_incidents
    )

# -------------------------------------------------------------
# REST API: Telemetry & Simulation Controls
# -------------------------------------------------------------

@router.post("/host/monitor/toggle")
async def toggle_host_monitor(
    active: bool = Query(...),
    user: User = Depends(require_role(Role.ANALYST))
):
    """Enable or pause genuine host security monitoring. Requires ANALYST or ADMIN role."""
    if active:
        stream_manager.start_host_monitoring()
    else:
        stream_manager.stop_host_monitoring()
    return {
        "status": "success",
        "host_monitoring_active": stream_manager.host_monitoring_active
    }

@router.post("/simulation/toggle")
async def toggle_simulation(
    active: bool = Query(...),
    user: User = Depends(require_role(Role.ANALYST))
):
    """Enable or pause synthetic demonstration threat simulation. Requires ANALYST or ADMIN role."""
    if active:
        stream_manager.start_simulation()
    else:
        stream_manager.stop_simulation()
    return {
        "status": "success",
        "simulation_active": stream_manager.simulation_active
    }

@router.post("/stream/toggle")
async def toggle_stream_backward_compat(
    active: bool = Query(...),
    user: User = Depends(require_role(Role.ANALYST))
):
    """Backward-compatible toggle controlling synthetic threat simulation. Requires ANALYST or ADMIN role."""
    if active:
        stream_manager.start_simulation()
    else:
        stream_manager.stop_simulation()
    return {
        "status": "success",
        "simulation_active": stream_manager.simulation_active
    }

@router.get("/stream/status")
def get_stream_status():
    """Check whether real-time host monitoring and simulation are actively running."""
    return {
        "host_monitoring_active": stream_manager.host_monitoring_active,
        "simulation_active": stream_manager.simulation_active,
        "connected_clients": len(stream_manager.active_connections)
    }

# -------------------------------------------------------------
# REST API: Real-World Host Sensor & Telemetry
# -------------------------------------------------------------

@router.get("/host/status")
def get_host_sensor_status(user: User = Depends(get_current_user)):
    """Retrieve live hardware, OS, network, and security posture of the current machine."""
    from app.security.stream import stream_manager
    if user.username in ("anonymous", "demo_viewer"):
        return {
            "hostname": "demo-soc-sensor-01",
            "platform": "Demo Security Environment",
            "os": "Demonstration Telemetry",
            "cpu_percent": 14.5,
            "memory_percent": 38.2,
            "process_count": 86,
            "interfaces": ["eth0 (demo)"],
            "listening_ports": [80, 443],
            "sanitized": True,
            "monitoring_active": stream_manager.host_monitoring_active,
            "auth_required_notice": "Authentication required for live genuine host telemetry."
        }
    from app.security.host_sensor import host_sensor
    return host_sensor.get_host_info()

@router.post("/host/audit")
def trigger_host_security_audit(
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST))
):
    """
    Execute an immediate security audit of the local machine.
    Requires ANALYST or ADMIN role.
    """
    from app.security.host_sensor import host_sensor
    created = host_sensor.run_full_audit(db)
    incidents = IncidentCorrelator.correlate_alerts(db)

    return {
        "status": "success",
        "message": f"Host security audit complete. Found {len(created)} anomalous findings.",
        "findings_count": len(created),
        "incidents_created": len(incidents),
        "host": host_sensor.get_host_info()
    }

@router.post("/host/drill")
def trigger_host_test_drill(
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST))
):
    """
    Generate an intentional, labeled [TEST DRILL] alert to evaluate triage playbooks.
    Requires ANALYST or ADMIN role.
    """
    from app.security.host_sensor import host_sensor
    return host_sensor.run_test_drill(db)

@router.post("/alerts/clear")
def clear_all_alerts(
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMIN))
):
    """
    Clear all alerts and incidents, and immediately re-scan the host for genuine live threats.
    Requires elevated ADMIN role.
    """
    from app.models.incident import IncidentAlert
    from app.security.host_sensor import host_sensor
    db.query(IncidentAlert).delete()
    db.query(Incident).delete()
    db.query(Alert).delete()
    db.commit()

    host_sensor.seen_signatures.clear()
    created = host_sensor.run_full_audit(db)
    incidents = IncidentCorrelator.correlate_alerts(db)

    audit_trail.record("ALERTS_CLEARED", user.username, user.role.value, "internal", "Cleared all alerts and re-scanned baseline")

    return {
        "status": "success",
        "message": f"All historical records cleared. Re-scanned host system: {len(created)} genuine findings.",
        "real_alerts_count": len(created),
        "incidents_created": len(incidents)
    }

@router.get("/audit/logs")
def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(require_role(Role.ADMIN))
):
    """
    Retrieve security audit trails.
    Requires elevated ADMIN role.
    """
    logs = audit_trail.get_logs(limit)
    return {
        "status": "success",
        "count": len(logs),
        "logs": logs
    }

@router.post("/sample-data/load/{dataset_type}")
def load_sample_dataset_route(
    dataset_type: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST))
):
    """Helper route to inject sample files directly for fast demonstration. Requires ANALYST role."""
    import sys
    from pathlib import Path
    from app.parsers.wazuh import WazuhParser
    from app.parsers.suricata import SuricataParser
    from app.parsers.linux_auth import LinuxAuthParser

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        root_sample_dir = Path(sys._MEIPASS) / "sample_data"
    else:
        root_sample_dir = Path(__file__).resolve().parent.parent.parent / "sample_data"
    created = []

    if dataset_type == "wazuh":
        path = root_sample_dir / "wazuh" / "wazuh_alerts.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Wazuh sample file missing.")
        content_txt = path.read_text(encoding="utf-8")
        raw_events = WazuhParser().parse(content_txt)
    elif dataset_type == "suricata":
        path = root_sample_dir / "suricata" / "suricata_eve.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Suricata sample file missing.")
        content_txt = path.read_text(encoding="utf-8")
        raw_events = SuricataParser().parse(content_txt)
    elif dataset_type in ("linux", "linux_auth"):
        path = root_sample_dir / "linux" / "auth.log"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Linux auth sample file missing.")
        content_txt = path.read_text(encoding="utf-8")
        raw_events = LinuxAuthParser().parse(content_txt)
    else:
        raise HTTPException(status_code=400, detail="Invalid dataset type.")

    for raw in raw_events:
        raw.setdefault("telemetry_origin", "HISTORICAL_LOG")
        norm = AlertNormalizer.normalize(raw)
        alert = Alert(
            id=uuid.uuid4(),
            occurrence_count=1,
            first_seen=norm["timestamp"],
            last_seen=norm["timestamp"],
            **norm
        )
        db.add(alert)
        created.append(alert)

    db.commit()
    incidents = IncidentCorrelator.correlate_alerts(db)

    return {
        "status": "success",
        "message": f"Successfully loaded {len(created)} sample {dataset_type} alerts.",
        "alerts_count": len(created),
        "incidents_created": len(incidents)
    }

