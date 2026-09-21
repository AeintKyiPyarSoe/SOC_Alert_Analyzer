import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

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

router = APIRouter()

# -------------------------------------------------------------
# REST API: Alerts
# -------------------------------------------------------------

@router.post("/alerts/upload", status_code=status.HTTP_201_CREATED)
async def upload_log_file(
    file: UploadFile = File(...),
    source_type: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Ingest a security log file (Wazuh, Suricata, or Linux auth),
    normalize records, calculate risk, map MITRE tactics, and correlate incidents.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected for upload.")

    # Validate file extension
    valid_exts = (".json", ".log", ".txt", ".eve", ".xml", ".csv")
    if not any(file.filename.lower().endswith(ext) for ext in valid_exts):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file format. Supported extensions: {', '.join(valid_exts)}"
        )

    try:
        content_bytes = await file.read()
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Determine or auto-detect parser
    if not source_type or source_type.lower() == "auto":
        detected_source = detect_source_type(content)
    else:
        detected_source = source_type

    try:
        parser = get_parser(detected_source)
        raw_events = parser.parse(content)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error parsing log file: {str(e)}")

    if not raw_events:
        raise HTTPException(
            status_code=422,
            detail="No valid security alerts could be extracted from the uploaded file."
        )

    # Normalize and persist alerts
    created_alerts = []
    for raw_ev in raw_events:
        normalized = AlertNormalizer.normalize(raw_ev)
        alert = Alert(
            id=uuid.uuid4(),
            timestamp=normalized["timestamp"],
            source_type=normalized["source_type"],
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
        db.add(alert)
        created_alerts.append(alert)

    db.commit()

    # Trigger Incident Correlation
    incidents = IncidentCorrelator.correlate_alerts(db)

    return {
        "status": "success",
        "message": f"Successfully ingested {len(created_alerts)} alerts from '{file.filename}'.",
        "source_type_used": detected_source,
        "alerts_count": len(created_alerts),
        "incidents_created": len(incidents)
    }

@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)"),
    source_type: Optional[str] = Query(None, description="Filter by source tool (Wazuh, Suricata, Linux_Auth)"),
    search: Optional[str] = Query(None, description="Search across IP, username, description"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieve normalized alerts with multi-attribute filtering."""
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status_filter:
        query = query.filter(Alert.status == status_filter.upper())
    if source_type:
        query = query.filter(Alert.source_type.ilike(f"%{source_type}%"))
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
    db: Session = Depends(get_db)
):
    """Transition alert through investigation lifecycle states."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert

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
    """Retrieve correlated incidents list."""
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
    db: Session = Depends(get_db)
):
    """Update status of an incident and cascade to linked alerts."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    incident.status = payload.status
    # Cascade status to all linked member alerts
    for alert in incident.alerts:
        alert.status = payload.status

    db.commit()
    db.refresh(incident)
    return incident

# -------------------------------------------------------------
# REST API: Dashboard Stats
# -------------------------------------------------------------

@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Calculate aggregated metrics for dashboard KPI cards."""
    alerts = db.query(Alert).all()
    incidents_count = db.query(Incident).count()

    total_alerts = len(alerts)
    critical_count = sum(1 for a in alerts if a.severity == "CRITICAL")
    high_count = sum(1 for a in alerts if a.severity == "HIGH")
    medium_count = sum(1 for a in alerts if a.severity == "MEDIUM")
    low_count = sum(1 for a in alerts if a.severity == "LOW")

    open_count = sum(1 for a in alerts if a.status == "OPEN")
    investigating_count = sum(1 for a in alerts if a.status == "INVESTIGATING")
    resolved_count = sum(1 for a in alerts if a.status == "RESOLVED")
    false_positive_count = sum(1 for a in alerts if a.status == "FALSE_POSITIVE")

    return DashboardStats(
        total_alerts=total_alerts,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        open_count=open_count,
        investigating_count=investigating_count,
        resolved_count=resolved_count,
        false_positive_count=false_positive_count,
        total_incidents=incidents_count
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
def trigger_host_security_audit(db: Session = Depends(get_db)):
    """
    Execute an immediate, comprehensive security audit of the local machine.
    Audits running processes, listening sockets, firewall posture, and Windows/Linux event logs.
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
def trigger_host_test_drill(db: Session = Depends(get_db)):
    """
    Generate an intentional, labeled [TEST DRILL] alert to evaluate triage playbooks
    and verify real-time notifications safely.
    """
    from app.security.host_sensor import host_sensor
    return host_sensor.run_test_drill(db)

@router.post("/alerts/clear")
def clear_all_alerts(db: Session = Depends(get_db)):
    """
    Clear all alerts and incidents, and immediately re-scan the host for genuine live threats.
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
