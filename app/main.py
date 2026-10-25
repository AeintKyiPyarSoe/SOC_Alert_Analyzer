import os
import sys
import uuid
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

logger = logging.getLogger(__name__)

import asyncio
from fastapi import FastAPI, Request, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, func

from app.config import settings
from app.database.connection import init_db, get_db, SessionLocal
from app.models.alert import Alert
from app.models.incident import Incident
from app.api.routes import router as api_router
from app.security.remediation import get_remediation_guidance
from app.security.mitre_mapper import MitreMapper
from app.parsers.wazuh import WazuhParser
from app.parsers.suricata import SuricataParser
from app.parsers.linux_auth import LinuxAuthParser
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator
from app.security.stream import stream_manager
from app.security.host_sensor import host_sensor, real_host_monitor_loop
from app.security.simulator import live_threat_simulator_loop
from app.security.auth import require_role, Role, User, authenticate_websocket, get_current_user
from app.security.logging_filter import setup_security_logging

# Initialize hardened log redaction at module load time
setup_security_logging()

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    BASE_DIR = Path(sys._MEIPASS) / "app"
else:
    BASE_DIR = Path(__file__).resolve().parent

def initial_host_baseline():
    """Runs a baseline security audit on the local machine on startup if database is empty and monitoring is active."""
    if not stream_manager.host_monitoring_active:
        logger.info("Skipping initial host baseline audit because host monitoring is paused/disabled.")
        return
    db = SessionLocal()
    try:
        if db.query(Alert).count() == 0:
            host_sensor.run_full_audit(db)
    except Exception as e:
        db.rollback()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure security logging filters are attached to running server loggers
    setup_security_logging()
    # Startup: initialize database tables & audit local host baseline
    stream_manager.set_event_loop(asyncio.get_running_loop())
    init_db()
    # Authoritative configuration initialization for monitoring and simulation respecting persisted preferences
    if stream_manager.host_monitoring_active:
        initial_host_baseline()
        await stream_manager.start_host_monitoring(persist=False)
    else:
        await stream_manager.stop_host_monitoring(persist=False)

    if stream_manager.simulation_active:
        await stream_manager.start_simulation(persist=False)
    else:
        await stream_manager.stop_simulation(persist=False)

    yield

    await stream_manager.shutdown()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=("*" not in settings.ALLOWED_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
)

_asset_hash_cache: dict = {}

def get_asset_fingerprint(asset_rel_path: str) -> str:
    """
    Computes a content hash fingerprint for a static asset relative to BASE_DIR / 'static'.
    Caches the fingerprint based on file mtime for high performance.
    """
    clean = asset_rel_path.lstrip("/").replace("static/", "", 1) if asset_rel_path.startswith("static/") or asset_rel_path.startswith("/static/") else asset_rel_path.lstrip("/")
    target = BASE_DIR / "static" / clean
    if not target.exists() or not target.is_file():
        return settings.VERSION

    try:
        mtime = target.stat().st_mtime
        if clean in _asset_hash_cache:
            cached_mtime, cached_hash = _asset_hash_cache[clean]
            if cached_mtime == mtime:
                return cached_hash

        import hashlib
        h = hashlib.sha256()
        with open(target, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        digest = h.hexdigest()[:12]
        _asset_hash_cache[clean] = (mtime, digest)
        return digest
    except Exception:
        return settings.VERSION

def versioned_static(asset_rel_path: str) -> str:
    """
    Generates fingerprinted URL for static assets (e.g. /static/css/styles.css?v=abcdef123456).
    Guarantees browser cache invalidation upon asset updates while preserving normal HTTP 304 behavior.
    """
    clean = asset_rel_path.lstrip("/").replace("static/", "", 1) if asset_rel_path.startswith("static/") or asset_rel_path.startswith("/static/") else asset_rel_path.lstrip("/")
    fp = get_asset_fingerprint(clean)
    return f"/static/{clean}?v={fp}"

# Defensive Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )

    path = request.url.path
    if path.startswith("/static/"):
        # For fingerprinted static assets: allow caching with revalidation
        response.headers.setdefault("Cache-Control", "public, max-age=86400, stale-while-revalidate=3600")
    elif path.startswith("/api/v1/"):
        # Sensitive API telemetry: never store in shared caches
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
    elif path in ("/", "/alerts", "/incidents", "/reports/mitre", "/upload"):
        # HTML document views: must revalidate so users automatically receive updated asset versions
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

    return response

# Static files & Jinja2 Templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["get_stream_status"] = lambda: stream_manager.get_status()
templates.env.globals["versioned_static"] = versioned_static

# Mount API routes
app.include_router(api_router, prefix=settings.API_V1_STR, tags=["Security Telemetry API"])

# -------------------------------------------------------------
# WebSocket: Real-Time Threat Stream
# -------------------------------------------------------------

@app.websocket("/ws/threats")
async def websocket_threats_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket connection for live threat feeds with authentication."""
    user = await authenticate_websocket(websocket)
    if not user:
        await websocket.close(code=1008)  # 1008 Policy Violation
        return

    await stream_manager.connect(websocket, user=user)
    try:
        while True:
            # Keep socket alive and accept ping/commands from client
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await stream_manager.disconnect(websocket)
    except Exception:
        await stream_manager.disconnect(websocket)


# -------------------------------------------------------------
# Web UI Endpoints
# -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard_view(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Render main defensive SOC dashboard with role-based telemetry protection."""
    is_guest = user.username in ("anonymous", "demo_viewer")

    if is_guest:
        # In unauthenticated guest mode, strictly isolate genuine telemetry
        alerts_q = db.query(Alert).filter(Alert.telemetry_origin == "SIMULATED_DEMO")
        incidents_q = db.query(Incident).filter(~Incident.alerts.any(Alert.telemetry_origin != "SIMULATED_DEMO"))
        alerts = alerts_q.order_by(desc(Alert.timestamp)).limit(100).all()
        incidents = incidents_q.order_by(desc(Incident.risk_score), desc(Incident.last_seen)).limit(50).all()

        total_alerts = alerts_q.count()
        total_incidents = incidents_q.count()
        sev_counts = dict(alerts_q.with_entities(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
        status_counts = dict(alerts_q.with_entities(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())

        stats = {
            "total_alerts": total_alerts,
            "critical_count": sev_counts.get("CRITICAL", 0),
            "high_count": sev_counts.get("HIGH", 0),
            "medium_count": sev_counts.get("MEDIUM", 0),
            "low_count": sev_counts.get("LOW", 0),
            "open_count": status_counts.get("OPEN", 0),
            "investigating_count": status_counts.get("INVESTIGATING", 0),
            "resolved_count": status_counts.get("RESOLVED", 0),
            "total_incidents": total_incidents
        }

        # Do not expose internal host infrastructure details to unauthenticated visitors
        host_info = {
            "os": "Protected Host",
            "hostname": "REDACTED",
            "architecture": "Protected",
            "cpu_usage_percent": 0,
            "memory_usage_percent": 0,
            "local_ips": [],
            "process_count": 0,
            "monitoring_active": False
        }
    else:
        # Authenticated Analyst / Admin / Local Operator
        total_alerts_count = db.query(func.count(Alert.id)).scalar() or 0
        if total_alerts_count == 0 and stream_manager.host_monitoring_active:
            try:
                host_sensor.run_full_audit(db)
            except Exception:
                pass

        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        total_incidents = db.query(func.count(Incident.id)).scalar() or 0

        sev_counts = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
        status_counts = dict(db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())

        stats = {
            "total_alerts": total_alerts,
            "critical_count": sev_counts.get("CRITICAL", 0),
            "high_count": sev_counts.get("HIGH", 0),
            "medium_count": sev_counts.get("MEDIUM", 0),
            "low_count": sev_counts.get("LOW", 0),
            "open_count": status_counts.get("OPEN", 0),
            "investigating_count": status_counts.get("INVESTIGATING", 0),
            "resolved_count": status_counts.get("RESOLVED", 0),
            "total_incidents": total_incidents
        }

        alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(100).all()
        incidents = db.query(Incident).order_by(desc(Incident.risk_score), desc(Incident.last_seen)).limit(50).all()
        host_info = host_sensor.get_host_info()

    # Serialize alerts with playbooks and MITRE mappings
    serialized_alerts = []
    for a in alerts:
        guidance = get_remediation_guidance(a.event_type, a.description)
        mitre_info = MitreMapper.get_details(a.mitre_technique) if a.mitre_technique else None
        serialized_alerts.append({
            "id": str(a.id),
            "title": a.description,
            "source_type": a.source_type,
            "telemetry_origin": a.telemetry_origin,
            "event_type": a.event_type,
            "rule_id": str(a.id)[:8],
            "severity": a.severity,
            "risk_score": a.risk_score,
            "source_ip": a.source_ip,
            "source_port": a.source_port,
            "destination_ip": a.destination_ip,
            "destination_port": a.destination_port,
            "device": a.username or host_info.get("hostname", "Protected"),
            "username": a.username,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "status": a.status,
            "what_happened": guidance["what_happened"],
            "why_suspicious": guidance["why_suspicious"],
            "score_explanation": f"Score {a.risk_score}/100: Host behavioral risk evaluation",
            "mitre": {
                "technique": a.mitre_technique,
                "name": mitre_info["name"],
                "tactic": mitre_info["tactic"],
                "url": mitre_info["url"]
            } if a.mitre_technique and mitre_info else None,
            "actions": guidance["recommended_actions"],
            "raw_log": a.raw_log or a.description
        })

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_page": "dashboard",
            "stats": stats,
            "alerts": alerts,
            "serialized_alerts": serialized_alerts,
            "incidents": incidents,
            "host_info": host_info,
            "stream_status": stream_manager.get_status(),
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )

@app.get("/alerts", response_class=HTMLResponse)
def alerts_view(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Render search & filter alerts catalog with pagination."""
    query = db.query(Alert)

    # Protect sensitive genuine host alerts from unauthenticated anonymous users
    if user.username in ("anonymous", "demo_viewer"):
        query = query.filter(Alert.telemetry_origin == "SIMULATED_DEMO")

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status:
        query = query.filter(Alert.status == status.upper())
    if source:
        query = query.filter(Alert.source_type.ilike(f"%{source}%"))
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

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "active_page": "alerts",
            "alerts": alerts,
            "current_severity": severity,
            "current_status": status,
            "current_source": source,
            "current_search": search,
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )

@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_investigation_view(
    alert_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Render single alert investigation playbook."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    if user.username in ("anonymous", "demo_viewer") and alert.telemetry_origin != "SIMULATED_DEMO":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view genuine telemetry forensic details."
        )

    guidance = get_remediation_guidance(alert.event_type, alert.description)
    mitre_details = MitreMapper.get_details(alert.mitre_technique)

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={
            "active_page": "alerts",
            "item": alert,
            "is_incident": False,
            "guidance": guidance,
            "mitre_details": mitre_details,
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )

@app.get("/incidents", response_class=HTMLResponse)
def incidents_view(
    request: Request,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Render correlated incidents list with pagination."""
    query = db.query(Incident)

    # Protect sensitive genuine incidents from unauthenticated anonymous users
    if user.username in ("anonymous", "demo_viewer"):
        query = query.filter(~Incident.alerts.any(Alert.telemetry_origin != "SIMULATED_DEMO"))

    if status:
        query = query.filter(Incident.status == status.upper())
    incidents = query.order_by(desc(Incident.risk_score), desc(Incident.last_seen)).offset(offset).limit(limit).all()

    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "active_page": "incidents",
            "incidents": incidents,
            "current_status": status,
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )

@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_investigation_view(
    incident_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Render incident investigation page with member alerts."""
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
    mitre_details = MitreMapper.get_details(incident.mitre_technique)

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={
            "active_page": "incidents",
            "item": incident,
            "is_incident": True,
            "guidance": guidance,
            "mitre_details": mitre_details,
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )

@app.get("/upload", response_class=HTMLResponse)
def upload_view(request: Request, user: User = Depends(get_current_user)):
    """Render telemetry import view."""
    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={
            "active_page": "upload",
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )

@app.get("/reports/mitre", response_class=HTMLResponse)
def mitre_report_view(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Render interactive MITRE ATT&CK Matrix visualization and threat summary report."""
    is_guest = user.username in ("anonymous", "demo_viewer")
    query = db.query(Alert)
    if is_guest:
        query = query.filter(Alert.telemetry_origin == "SIMULATED_DEMO")
    alerts = query.order_by(desc(Alert.timestamp)).all()
    summary = MitreMapper.generate_summary_report(alerts)

    return templates.TemplateResponse(
        request=request,
        name="mitre_report.html",
        context={
            "active_page": "mitre",
            "summary": summary,
            "demo_mode": settings.DEMO_MODE,
            "user": user
        }
    )
