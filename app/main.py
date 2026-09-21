import os
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

import asyncio
from fastapi import FastAPI, Request, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

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
import sys
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator
from app.security.stream import stream_manager
from app.security.host_sensor import host_sensor, real_host_monitor_loop

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    BASE_DIR = Path(sys._MEIPASS) / "app"
else:
    BASE_DIR = Path(__file__).resolve().parent

def initial_host_baseline():
    """Runs a baseline security audit on the local machine on startup if database is empty."""
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
    # Startup: initialize database tables & audit local host baseline
    init_db()
    initial_host_baseline()
    # Start continuous real host security monitor
    monitor_task = asyncio.create_task(real_host_monitor_loop())
    yield
    monitor_task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Static files & Jinja2 Templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Mount API routes
app.include_router(api_router, prefix=settings.API_V1_STR, tags=["Security Telemetry API"])

# -------------------------------------------------------------
# WebSocket: Real-Time Threat Stream
# -------------------------------------------------------------

@app.websocket("/ws/threats")
async def websocket_threats_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket connection for live threat feeds."""
    await stream_manager.connect(websocket)
    try:
        while True:
            # Keep socket alive and accept ping/commands from client
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        stream_manager.disconnect(websocket)

@app.post("/api/v1/stream/toggle")
def toggle_stream(active: bool = Query(...)):
    """Enable or pause the real-time background threat simulator."""
    stream_manager.simulation_active = active
    return {
        "status": "success",
        "simulation_active": stream_manager.simulation_active
    }

@app.get("/api/v1/stream/status")
def get_stream_status():
    """Check whether real-time simulation is actively broadcasting."""
    return {
        "simulation_active": stream_manager.simulation_active,
        "connected_clients": len(stream_manager.active_connections)
    }

# -------------------------------------------------------------
# Web UI Endpoints
# -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard_view(request: Request, db: Session = Depends(get_db)):
    """Render main defensive SOC dashboard."""
    alerts = db.query(Alert).order_by(desc(Alert.timestamp)).all()
    
    # If starting on a clean machine/laptop, immediately run full host audit
    if len(alerts) == 0:
        try:
            host_sensor.run_full_audit(db)
            alerts = db.query(Alert).order_by(desc(Alert.timestamp)).all()
        except Exception:
            pass

    incidents = db.query(Incident).order_by(desc(Incident.risk_score), desc(Incident.last_seen)).all()

    stats = {
        "total_alerts": len(alerts),
        "critical_count": sum(1 for a in alerts if a.severity == "CRITICAL"),
        "high_count": sum(1 for a in alerts if a.severity == "HIGH"),
        "medium_count": sum(1 for a in alerts if a.severity == "MEDIUM"),
        "low_count": sum(1 for a in alerts if a.severity == "LOW"),
        "open_count": sum(1 for a in alerts if a.status == "OPEN"),
        "investigating_count": sum(1 for a in alerts if a.status == "INVESTIGATING"),
        "resolved_count": sum(1 for a in alerts if a.status == "RESOLVED"),
        "total_incidents": len(incidents)
    }

    # Serialize real laptop alerts with investigation playbooks and MITRE details
    serialized_alerts = []
    for a in alerts:
        guidance = get_remediation_guidance(a.event_type, a.description)
        mitre_info = MitreMapper.get_details(a.mitre_technique) if a.mitre_technique else None
        serialized_alerts.append({
            "id": str(a.id),
            "title": a.description,
            "source_type": a.source_type,
            "event_type": a.event_type,
            "rule_id": str(a.id)[:8],
            "severity": a.severity,
            "risk_score": a.risk_score,
            "source_ip": a.source_ip,
            "source_port": a.source_port,
            "destination_ip": a.destination_ip,
            "destination_port": a.destination_port,
            "device": a.username or host_sensor.hostname,
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
            "host_info": host_sensor.get_host_info()
        }
    )

@app.get("/alerts", response_class=HTMLResponse)
def alerts_view(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Render search & filter alerts catalog."""
    query = db.query(Alert)

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

    alerts = query.order_by(desc(Alert.timestamp)).all()

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "active_page": "alerts",
            "alerts": alerts,
            "current_severity": severity,
            "current_status": status,
            "current_source": source,
            "current_search": search
        }
    )

@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_investigation_view(alert_id: uuid.UUID, request: Request, db: Session = Depends(get_db)):
    """Render single alert investigation playbook."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

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
            "mitre_details": mitre_details
        }
    )

@app.get("/incidents", response_class=HTMLResponse)
def incidents_view(
    request: Request,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Render correlated incidents list."""
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status.upper())
    incidents = query.order_by(desc(Incident.risk_score), desc(Incident.last_seen)).all()

    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "active_page": "incidents",
            "incidents": incidents,
            "current_status": status
        }
    )

@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_investigation_view(incident_id: uuid.UUID, request: Request, db: Session = Depends(get_db)):
    """Render incident investigation page with member alerts."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

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
            "mitre_details": mitre_details
        }
    )

@app.get("/upload", response_class=HTMLResponse)
def upload_view(request: Request):
    """Render telemetry import view."""
    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={"active_page": "upload"}
    )

@app.post("/api/v1/sample-data/load/{dataset_type}")
def load_sample_dataset_route(dataset_type: str, db: Session = Depends(get_db)):
    """Helper route to inject sample files directly for fast demonstration."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        root_sample_dir = Path(sys._MEIPASS) / "sample_data"
    else:
        root_sample_dir = BASE_DIR.parent / "sample_data"
    created = []

    if dataset_type == "wazuh":
        path = root_sample_dir / "wazuh" / "wazuh_alerts.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Wazuh sample file missing.")
        content = path.read_text(encoding="utf-8")
        raw_events = WazuhParser().parse(content)
    elif dataset_type == "suricata":
        path = root_sample_dir / "suricata" / "suricata_eve.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Suricata sample file missing.")
        content = path.read_text(encoding="utf-8")
        raw_events = SuricataParser().parse(content)
    elif dataset_type in ("linux", "linux_auth"):
        path = root_sample_dir / "linux" / "auth.log"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Linux auth sample file missing.")
        content = path.read_text(encoding="utf-8")
        raw_events = LinuxAuthParser().parse(content)
    else:
        raise HTTPException(status_code=400, detail="Invalid dataset type.")

    for raw in raw_events:
        norm = AlertNormalizer.normalize(raw)
        alert = Alert(id=uuid.uuid4(), **norm)
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
