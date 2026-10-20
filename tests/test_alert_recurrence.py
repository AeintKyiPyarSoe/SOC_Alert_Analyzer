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


def test_distinct_destination_ips_not_merged(db_session: Session):
    """Verify that alerts with different destination IPs are never merged."""
    sensor = HostSecuritySensor()
    t = datetime.now(timezone.utc)
    raw = [
        {
            "timestamp": t.isoformat(),
            "source_type": "Firewall",
            "event_type": "outbound_c2_attempt",
            "description": "Suspicious outbound traffic to external IP",
            "source_ip": "10.0.0.5",
            "destination_ip": "198.51.100.1",
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        },
        {
            "timestamp": t.isoformat(),
            "source_type": "Firewall",
            "event_type": "outbound_c2_attempt",
            "description": "Suspicious outbound traffic to external IP",
            "source_ip": "10.0.0.5",
            "destination_ip": "203.0.113.2",  # Different destination
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        }
    ]

    created = sensor._ingest_events(raw, db_session)
    assert len(created) == 2
    assert created[0].destination_ip != created[1].destination_ip
    assert created[0].occurrence_count == 1
    assert created[1].occurrence_count == 1


def test_distinct_usernames_not_merged(db_session: Session):
    """Verify that alerts involving different user accounts are never merged."""
    sensor = HostSecuritySensor()
    t = datetime.now(timezone.utc)
    raw = [
        {
            "timestamp": t.isoformat(),
            "source_type": "Linux_Auth",
            "event_type": "ssh_brute_force",
            "description": "Repeated SSH authentication failure",
            "source_ip": "192.168.1.50",
            "username": "root",
            "severity": "HIGH",
            "telemetry_origin": "HISTORICAL_LOG"
        },
        {
            "timestamp": t.isoformat(),
            "source_type": "Linux_Auth",
            "event_type": "ssh_brute_force",
            "description": "Repeated SSH authentication failure",
            "source_ip": "192.168.1.50",
            "username": "deploy_user",  # Different username
            "severity": "HIGH",
            "telemetry_origin": "HISTORICAL_LOG"
        }
    ]

    created = sensor._ingest_events(raw, db_session)
    assert len(created) == 2
    assert created[0].username != created[1].username
    assert created[0].occurrence_count == 1
    assert created[1].occurrence_count == 1


def test_intra_batch_repeated_events_deduplicated_monotonically(db_session: Session):
    """Verify that multiple identical events within the same ingestion call are deduplicated."""
    sensor = HostSecuritySensor()
    base_t = datetime.now(timezone.utc) - timedelta(seconds=15)
    t1 = base_t
    t2 = base_t + timedelta(seconds=2)
    t3 = base_t + timedelta(seconds=5)

    raw_batch = [
        {
            "timestamp": t1.isoformat(),
            "source_type": "Host_Process_Sensor",
            "event_type": "burst_cmd_execution",
            "description": "powershell.exe -enc burst_test",
            "source_ip": "127.0.0.1",
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        },
        {
            "timestamp": t2.isoformat(),
            "source_type": "Host_Process_Sensor",
            "event_type": "burst_cmd_execution",
            "description": "powershell.exe -enc burst_test",
            "source_ip": "127.0.0.1",
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        },
        {
            "timestamp": t3.isoformat(),
            "source_type": "Host_Process_Sensor",
            "event_type": "burst_cmd_execution",
            "description": "powershell.exe -enc burst_test",
            "source_ip": "127.0.0.1",
            "severity": "HIGH",
            "telemetry_origin": "HOST_TELEMETRY"
        }
    ]

    created = sensor._ingest_events(raw_batch, db_session)
    assert len(created) == 1
    alert = created[0]
    assert alert.occurrence_count == 3
    assert alert.first_seen.replace(tzinfo=timezone.utc) == t1
    assert alert.last_seen.replace(tzinfo=timezone.utc) == t3


def test_resolved_and_false_positive_alerts_do_not_merge(db_session: Session):
    """Verify that an incoming event does NOT merge into a previously RESOLVED or FALSE_POSITIVE alert."""
    sensor = HostSecuritySensor()
    t_prev = datetime.now(timezone.utc) - timedelta(seconds=30)
    resolved_alert = Alert(
        id=uuid.uuid4(),
        timestamp=t_prev,
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="resolved_test_event",
        description="Suspicious activity previously resolved",
        source_ip="10.0.0.99",
        severity="MEDIUM",
        status="RESOLVED",
        occurrence_count=1,
        first_seen=t_prev,
        last_seen=t_prev
    )
    db_session.add(resolved_alert)
    db_session.commit()

    # Ingest event with identical attributes while old alert is RESOLVED
    t_new = datetime.now(timezone.utc) - timedelta(seconds=5)
    raw = [{
        "timestamp": t_new.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "resolved_test_event",
        "description": "Suspicious activity previously resolved",
        "source_ip": "10.0.0.99",
        "severity": "MEDIUM",
        "telemetry_origin": "HOST_TELEMETRY"
    }]
    created = sensor._ingest_events(raw, db_session)
    assert len(created) == 1
    new_alert = created[0]

    assert new_alert.id != resolved_alert.id
    assert new_alert.status == "OPEN"
    assert new_alert.occurrence_count == 1

    # Verify resolved alert remains untouched
    db_session.refresh(resolved_alert)
    assert resolved_alert.occurrence_count == 1
    assert resolved_alert.status == "RESOLVED"


def test_none_vs_explicit_field_isolation(db_session: Session):
    """Verify that None/NULL fields and explicitly populated fields never accidentally cross-match."""
    sensor = HostSecuritySensor()
    t = datetime.now(timezone.utc) - timedelta(seconds=10)

    # 1. Base alert with destination_ip=None, username=None
    base_raw = [{
        "timestamp": t.isoformat(),
        "source_type": "Firewall",
        "event_type": "field_isolation_test",
        "description": "Port scan detected",
        "source_ip": "192.168.1.10",
        "destination_ip": None,
        "username": None,
        "severity": "LOW",
        "telemetry_origin": "HISTORICAL_LOG"
    }]
    created_base = sensor._ingest_events(base_raw, db_session)
    assert len(created_base) == 1
    base_alert = created_base[0]

    # 2. Event with same source_ip and description, but explicit destination_ip
    dest_event = [{
        "timestamp": t.isoformat(),
        "source_type": "Firewall",
        "event_type": "field_isolation_test",
        "description": "Port scan detected",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.254",
        "username": None,
        "severity": "LOW",
        "telemetry_origin": "HISTORICAL_LOG"
    }]
    created_dest = sensor._ingest_events(dest_event, db_session)
    assert len(created_dest) == 1
    assert created_dest[0].id != base_alert.id

    # 3. Event with same attributes as base (both None) -> MUST match base alert
    match_event = [{
        "timestamp": (t + timedelta(seconds=2)).isoformat(),
        "source_type": "Firewall",
        "event_type": "field_isolation_test",
        "description": "Port scan detected",
        "source_ip": "192.168.1.10",
        "destination_ip": None,
        "username": None,
        "severity": "LOW",
        "telemetry_origin": "HISTORICAL_LOG"
    }]
    created_match = sensor._ingest_events(match_event, db_session)
    assert len(created_match) == 0  # Deduplicated into base_alert
    db_session.refresh(base_alert)
    assert base_alert.occurrence_count == 2


def test_legacy_null_first_seen_and_last_seen_handled_gracefully(db_session: Session):
    """Verify that legacy records with null first_seen/last_seen are safely recovered during recurrence."""
    sensor = HostSecuritySensor()
    t_legacy = datetime.now(timezone.utc) - timedelta(seconds=60)
    legacy = Alert(
        id=uuid.uuid4(),
        timestamp=t_legacy,
        source_type="Host_Process_Sensor",
        telemetry_origin="HOST_TELEMETRY",
        event_type="legacy_null_ts_test",
        description="Legacy event with null boundaries",
        source_ip="127.0.0.1",
        severity="MEDIUM",
        status="OPEN",
        occurrence_count=1,
        first_seen=None,
        last_seen=None
    )
    db_session.add(legacy)
    db_session.commit()

    t_new = datetime.now(timezone.utc) - timedelta(seconds=10)
    raw = [{
        "timestamp": t_new.isoformat(),
        "source_type": "Host_Process_Sensor",
        "event_type": "legacy_null_ts_test",
        "description": "Legacy event with null boundaries",
        "source_ip": "127.0.0.1",
        "severity": "MEDIUM",
        "telemetry_origin": "HOST_TELEMETRY"
    }]

    created = sensor._ingest_events(raw, db_session)
    assert len(created) == 0  # Successfully merged
    db_session.refresh(legacy)
    assert legacy.occurrence_count == 2
    assert legacy.first_seen.replace(tzinfo=timezone.utc) == t_legacy
    assert legacy.last_seen.replace(tzinfo=timezone.utc) == t_new


def test_whitespace_and_empty_username_normalized_to_none(db_session: Session):
    """Verify that empty/whitespace usernames normalize to None and deduplicate properly."""
    sensor = HostSecuritySensor()
    t = datetime.now(timezone.utc) - timedelta(seconds=20)
    raw1 = [{
        "timestamp": t.isoformat(),
        "source_type": "Linux_Auth",
        "event_type": "empty_user_test",
        "description": "Auth attempt without user",
        "source_ip": "10.0.0.40",
        "username": "   ",
        "severity": "LOW",
        "telemetry_origin": "HISTORICAL_LOG"
    }]
    c1 = sensor._ingest_events(raw1, db_session)
    assert len(c1) == 1
    assert c1[0].username is None

    raw2 = [{
        "timestamp": (t + timedelta(seconds=5)).isoformat(),
        "source_type": "Linux_Auth",
        "event_type": "empty_user_test",
        "description": "Auth attempt without user",
        "source_ip": "10.0.0.40",
        "username": "",
        "severity": "LOW",
        "telemetry_origin": "HISTORICAL_LOG"
    }]
    c2 = sensor._ingest_events(raw2, db_session)
    assert len(c2) == 0  # Merged!
    db_session.refresh(c1[0])
    assert c1[0].occurrence_count == 2
