import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.security.host_sensor import HostSecuritySensor
from app.schemas.alert import AlertResponse


def test_first_occurrence_recurrence_initialization(db_session: Session):
    sensor = HostSecuritySensor()
    t0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    raw = [{
        "timestamp": t0.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "suspicious_command",
        "description": "powershell.exe -w hidden -enc test1",
        "source_ip": "127.0.0.1",
        "severity": "HIGH",
        "telemetry_origin": "HOST_TELEMETRY"
    }]

    created = sensor._ingest_events(raw, db_session)
    assert len(created) == 1
    alert = created[0]
    assert alert.occurrence_count == 1
    assert alert.first_seen is not None
    assert alert.last_seen is not None
    assert alert.first_seen.replace(tzinfo=timezone.utc) == t0
    assert alert.last_seen.replace(tzinfo=timezone.utc) == t0


def test_repeated_occurrence_within_window_increments_count(db_session: Session):
    sensor = HostSecuritySensor()
    t0 = datetime.now(timezone.utc) - timedelta(seconds=20)
    t1 = datetime.now(timezone.utc) - timedelta(seconds=5)

    raw1 = [{
        "timestamp": t0.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "masquerading_binary",
        "description": "svchost.exe executing from C:\\Users\\Public\\svchost.exe",
        "source_ip": "127.0.0.1",
        "severity": "CRITICAL",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    created1 = sensor._ingest_events(raw1, db_session)
    assert len(created1) == 1
    alert_id = created1[0].id

    # Second arrival of identical alert within dedup window
    raw2 = [{
        "timestamp": t1.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "masquerading_binary",
        "description": "svchost.exe executing from C:\\Users\\Public\\svchost.exe",
        "source_ip": "127.0.0.1",
        "severity": "CRITICAL",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    created2 = sensor._ingest_events(raw2, db_session)
    assert len(created2) == 0  # Deduplicated into existing

    # Verify existing alert in database updated
    refreshed = db_session.query(Alert).filter(Alert.id == alert_id).first()
    assert refreshed.occurrence_count == 2
    assert refreshed.first_seen.replace(tzinfo=timezone.utc) == t0
    assert refreshed.last_seen.replace(tzinfo=timezone.utc) == t1


def test_multiple_repeated_occurrences(db_session: Session):
    sensor = HostSecuritySensor()
    base_t = datetime.now(timezone.utc) - timedelta(seconds=60)
    event_data = {
        "timestamp": base_t.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "ransomware_indicator",
        "description": "vssadmin delete shadows /all /quiet",
        "source_ip": "10.0.0.5",
        "severity": "CRITICAL",
        "telemetry_origin": "HOST_TELEMETRY"
    }

    sensor._ingest_events([event_data], db_session)
    alert = db_session.query(Alert).filter(
        Alert.description == "vssadmin delete shadows /all /quiet",
        Alert.source_ip == "10.0.0.5"
    ).first()
    assert alert.occurrence_count == 1

    # Ingest 4 more times
    for i in range(1, 5):
        next_t = base_t + timedelta(seconds=i * 5)
        event_data["timestamp"] = next_t.isoformat()
        sensor._ingest_events([event_data], db_session)

    db_session.refresh(alert)
    assert alert.occurrence_count == 5


def test_repetition_outside_window_creates_new_alert(db_session: Session):
    sensor = HostSecuritySensor()
    # Alert from 10 minutes ago (beyond default 300s dedup window)
    t_old = datetime.now(timezone.utc) - timedelta(seconds=600)
    raw_old = [{
        "timestamp": t_old.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "web_shell",
        "description": "w3wp.exe spawned cmd.exe (shell execution)",
        "source_ip": "192.168.1.100",
        "severity": "CRITICAL",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    created_old = sensor._ingest_events(raw_old, db_session)
    assert len(created_old) == 1

    # New occurrence right now
    t_now = datetime.now(timezone.utc)
    raw_now = [{
        "timestamp": t_now.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "web_shell",
        "description": "w3wp.exe spawned cmd.exe (shell execution)",
        "source_ip": "192.168.1.100",
        "severity": "CRITICAL",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    created_now = sensor._ingest_events(raw_now, db_session)
    assert len(created_now) == 1  # Should create a distinct alert since outside window
    assert created_now[0].id != created_old[0].id
    assert created_now[0].occurrence_count == 1


def test_distinct_hosts_not_merged(db_session: Session):
    sensor = HostSecuritySensor()
    t = datetime.now(timezone.utc)
    raw = [
        {
            "timestamp": t.isoformat(),
            "source_type": "Host_Process_Sensor",
            "event_type": "lolbin_execution",
            "description": "certutil -urlcache download",
            "source_ip": "10.0.0.10",
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        },
        {
            "timestamp": t.isoformat(),
            "source_type": "Host_Process_Sensor",
            "event_type": "lolbin_execution",
            "description": "certutil -urlcache download",
            "source_ip": "10.0.0.20",  # Different host
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        }
    ]

    created = sensor._ingest_events(raw, db_session)
    assert len(created) == 2
    assert created[0].source_ip != created[1].source_ip
    assert created[0].occurrence_count == 1
    assert created[1].occurrence_count == 1


def test_out_of_order_timestamps_boundary_handling(db_session: Session):
    sensor = HostSecuritySensor()
    t_middle = datetime.now(timezone.utc) - timedelta(seconds=20)
    t_early = datetime.now(timezone.utc) - timedelta(seconds=50)
    t_late = datetime.now(timezone.utc) - timedelta(seconds=5)

    # 1. Ingest middle timestamp first
    raw1 = [{
        "timestamp": t_middle.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "shadow_copy_access",
        "description": "wmic shadowcopy delete attempted",
        "source_ip": "127.0.0.1",
        "severity": "HIGH",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    c1 = sensor._ingest_events(raw1, db_session)
    alert = c1[0]

    # 2. Ingest older timestamp (arrived out of order)
    raw_old = [{
        "timestamp": t_early.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "shadow_copy_access",
        "description": "wmic shadowcopy delete attempted",
        "source_ip": "127.0.0.1",
        "severity": "HIGH",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    sensor._ingest_events(raw_old, db_session)
    db_session.refresh(alert)
    assert alert.occurrence_count == 2
    assert alert.first_seen.replace(tzinfo=timezone.utc) == t_early
    assert alert.last_seen.replace(tzinfo=timezone.utc) == t_middle  # last_seen did not move backwards!

    # 3. Ingest later timestamp
    raw_late = [{
        "timestamp": t_late.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "shadow_copy_access",
        "description": "wmic shadowcopy delete attempted",
        "source_ip": "127.0.0.1",
        "severity": "HIGH",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    sensor._ingest_events(raw_late, db_session)
    db_session.refresh(alert)
    assert alert.occurrence_count == 3
    assert alert.first_seen.replace(tzinfo=timezone.utc) == t_early
    assert alert.last_seen.replace(tzinfo=timezone.utc) == t_late


def test_alert_response_serialization_compatibility(db_session: Session):
    """Ensure Pydantic AlertResponse schema serializes recurrence fields cleanly."""
    t = datetime.now(timezone.utc)
    alert = Alert(
        id=uuid.uuid4(),
        timestamp=t,
        source_type="Wazuh",
        telemetry_origin="HISTORICAL_LOG",
        event_type="test_event",
        description="Test recurrence schema serialization",
        severity="LOW",
        risk_score=10,
        status="OPEN",
        occurrence_count=7,
        first_seen=t - timedelta(minutes=2),
        last_seen=t
    )
    db_session.add(alert)
    db_session.commit()

    serialized = AlertResponse.model_validate(alert)
    assert serialized.occurrence_count == 7
    assert serialized.first_seen is not None
    assert serialized.last_seen is not None
    assert serialized.id == alert.id
