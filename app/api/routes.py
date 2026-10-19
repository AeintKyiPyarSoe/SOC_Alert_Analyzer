import uuid
from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, func

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
from app.security.upload_security import SecureUploadHandler

router = APIRouter()

# -------------------------------------------------------------
# REST API: Authentication & Session Management
# -------------------------------------------------------------

class LoginRequest(BaseModel):
    api_key: str

@router.get("/auth/me")
def get_auth_profile(user: User = Depends(get_current_user)):
    """Inspect caller's current authentication identity, role, and environment mode."""
    return {
        "authenticated": user.username not in ("anonymous", "demo_viewer"),
        "username": user.username,
        "role": user.role.value,
        "demo_mode": settings.DEMO_MODE,
        "auth_enabled": settings.AUTH_ENABLED
    }

@router.post("/auth/login")
def login_route(payload: LoginRequest, response: Response):
    """Authenticate browser session with an API key, issuing an HttpOnly session cookie."""
    user = validate_token(payload.api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key. Please check your credentials."
        )
    response.set_cookie(
        key="soc_api_key",
        value=payload.api_key.strip(),
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,
        path="/"
    )
    return {
        "status": "success",
        "username": user.username,
        "role": user.role.value
    }

@router.post("/auth/logout")
def logout_route(response: Response):
    """Clear authenticated session cookie."""
    response.delete_cookie(key="soc_api_key", path="/")
    return {
        "status": "success",
        "message": "Logged out successfully."
    }

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

    # Normalize and persist alerts using bounded memory batches
    total_ingested = 0
    batch = []
    for raw_ev in raw_events:
        raw_ev.setdefault("telemetry_origin", "HISTORICAL_LOG")
        normalized = AlertNormalizer.normalize(raw_ev)
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
            raw_log=normalized.get("raw_log")
        )
        batch.append(alert)
        if len(batch) >= settings.DB_BATCH_SIZE:
            db.add_all(batch)
            db.flush()
            total_ingested += len(batch)
            batch = []

    if batch:
        db.add_all(batch)
        db.flush()
        total_ingested += len(batch)

    db.commit()

    # Trigger Incident Correlation
    incidents = IncidentCorrelator.correlate_alerts(db)

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
    db: Session = Depends(get_db)
):
    """Retrieve normalized alerts with multi-attribute filtering and pagination."""
    query = db.query(Alert)

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
def get_alert_detail(alert_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieve single alert with full plain-language investigation guidance."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    guidance = get_remediation_guidance(alert.event_type, alert.description)
    mitre_info = MitreMapper.get_details(alert.mitre_technique)

    return {
        "alert": AlertResponse.model_validate(alert),
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
    db: Session = Depends(get_db)
):
    """Retrieve correlated incidents list with pagination."""
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    incidents = query.order_by(desc(Incident.risk_score), desc(Incident.last_seen)).offset(offset).limit(limit).all()
    return incidents

@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieve incident details including member alerts and remediation checklist."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

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
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Calculate aggregated metrics using high-performance SQL group-by queries."""
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0

    sev_rows = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    sev_map = {row[0]: row[1] for row in sev_rows}

    status_rows = db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
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
# REST API: Real-World Host Sensor & Telemetry
# -------------------------------------------------------------

@router.get("/host/status")
def get_host_sensor_status():
    """Retrieve live hardware, OS, network, and security posture of the current machine."""
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

    return {
        "status": "success",
        "message": f"All historical records cleared. Re-scanned host system: {len(created)} genuine findings.",
        "real_alerts_count": len(created),
        "incidents_created": len(incidents)
    }
