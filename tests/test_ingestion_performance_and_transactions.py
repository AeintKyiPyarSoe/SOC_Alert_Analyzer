import json
import io
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.config import settings
from app.security.correlator import IncidentCorrelator

def test_ingestion_duplicate_events_in_same_import(client, db_session: Session):
    """Verify that multiple duplicate events within a single import file deduplicate into a single alert."""
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": (t0 + timedelta(seconds=i * 5)).isoformat(),
            "source_type": "Wazuh",
            "event_type": "intra_batch_dedup_test",
            "description": "Repeated intrusion attempt intra-batch",
            "source_ip": "192.168.10.50",
            "destination_ip": "10.0.0.1",
            "username": "root",
            "severity": "HIGH",
            "telemetry_origin": "HISTORICAL_LOG"
        }
        for i in range(10)
    ]

    payload = json.dumps(events).encode("utf-8")
    res = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("intra_batch.json", io.BytesIO(payload), "application/json")},
        data={"source_type": "generic"}
    )
    assert res.status_code == 201
    assert res.json()["alerts_count"] == 10

    alerts = db_session.query(Alert).filter(Alert.event_type == "intra_batch_dedup_test").all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.occurrence_count == 10
    assert alert.first_seen.replace(tzinfo=timezone.utc) == t0
    assert alert.last_seen.replace(tzinfo=timezone.utc) == t0 + timedelta(seconds=45)


def test_ingestion_recurrence_across_separate_imports(client, db_session: Session):
    """Verify that duplicate events across separate upload batches properly match and increment recurrence."""
    t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    # First import: 1 event
    file1_events = [{
        "timestamp": t0.isoformat(),
        "source_type": "Wazuh",
        "event_type": "cross_batch_recurrence_test",
        "description": "Cross-batch attack pattern",
        "source_ip": "10.10.10.10",
        "destination_ip": "10.0.0.2",
        "username": "admin",
        "severity": "CRITICAL",
        "telemetry_origin": "HISTORICAL_LOG"
    }]
    res1 = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("file1.json", io.BytesIO(json.dumps(file1_events).encode("utf-8")), "application/json")},
        data={"source_type": "generic"}
    )
    assert res1.status_code == 201
    assert res1.json()["alerts_count"] == 1

    # Second import: 3 events arriving within recurrence window
    file2_events = [
        {
            "timestamp": (t0 + timedelta(seconds=i * 30)).isoformat(),
            "source_type": "Wazuh",
            "event_type": "cross_batch_recurrence_test",
            "description": "Cross-batch attack pattern",
            "source_ip": "10.10.10.10",
            "destination_ip": "10.0.0.2",
            "username": "admin",
            "severity": "CRITICAL",
            "telemetry_origin": "HISTORICAL_LOG"
        }
        for i in range(1, 4)
    ]
    res2 = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("file2.json", io.BytesIO(json.dumps(file2_events).encode("utf-8")), "application/json")},
        data={"source_type": "generic"}
    )
    assert res2.status_code == 201
    assert res2.json()["alerts_count"] == 3

    # Total in DB: still exactly 1 alert, with occurrence_count == 4
    alerts = db_session.query(Alert).filter(Alert.event_type == "cross_batch_recurrence_test").all()
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 4
    assert alerts[0].first_seen.replace(tzinfo=timezone.utc) == t0
    assert alerts[0].last_seen.replace(tzinfo=timezone.utc) == t0 + timedelta(seconds=90)


def test_ingestion_malformed_records_atomic_rollback(client, db_session: Session):
    """Verify that malformed log content returns 422 and commits no alerts."""
    malformed_payload = b'{"timestamp": "2026-09-01T12:00:00Z", "unclosed_json": '
    res = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("corrupt.json", io.BytesIO(malformed_payload), "application/json")},
        data={"source_type": "generic"}
    )
    assert res.status_code == 422
    assert "Error parsing log file" in res.json()["detail"] or "No valid security alerts" in res.json()["detail"]

    # Verify database remains clean
    alert_count = db_session.query(Alert).count()
    assert alert_count == 0


def test_ingestion_database_failure_atomic_rollback(client, db_session: Session, monkeypatch):
    """Verify that a database failure midway through ingestion triggers an atomic rollback."""
    t0 = datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": (t0 + timedelta(seconds=i)).isoformat(),
            "source_type": "Wazuh",
            "event_type": "rollback_test_event",
            "description": f"Rollback test description {i}",
            "source_ip": f"192.168.100.{i}",
            "severity": "MEDIUM",
            "telemetry_origin": "HISTORICAL_LOG"
        }
        for i in range(10)
    ]

    # Monkeypatch IncidentCorrelator.correlate_alerts to simulate a database failure before final commit
    def mock_correlate_failure(db):
        raise RuntimeError("Simulated database failure during correlation")

    monkeypatch.setattr(IncidentCorrelator, "correlate_alerts", mock_correlate_failure)

    res = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("failing_batch.json", io.BytesIO(json.dumps(events).encode("utf-8")), "application/json")},
        data={"source_type": "generic"}
    )
    assert res.status_code == 500
    assert "Database transaction failure" in res.json()["detail"]

    # Crucial assertion: Atomic rollback ensured 0 alerts were committed
    persisted = db_session.query(Alert).filter(Alert.event_type == "rollback_test_event").all()
    assert len(persisted) == 0


def test_ingestion_large_batch_chunking(client, db_session: Session, monkeypatch):
    """Verify that large batches spanning multiple DB_BATCH_SIZE chunk boundaries persist accurately."""
    monkeypatch.setattr(settings, "DB_BATCH_SIZE", 50)
    t0 = datetime(2026, 9, 1, 16, 0, 0, tzinfo=timezone.utc)

    # 300 events across 10 distinct patterns (30 occurrences each)
    events = []
    for i in range(300):
        pat_id = i % 10
        events.append({
            "timestamp": (t0 + timedelta(seconds=i * 2)).isoformat(),
            "source_type": "Wazuh",
            "event_type": f"batch_chunk_test_{pat_id}",
            "description": f"Batch chunk pattern {pat_id}",
            "source_ip": f"10.0.1.{pat_id}",
            "severity": "HIGH",
            "telemetry_origin": "HISTORICAL_LOG"
        })

    payload = json.dumps(events).encode("utf-8")
    res = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("chunk_300.json", io.BytesIO(payload), "application/json")},
        data={"source_type": "generic"}
    )
    assert res.status_code == 201
    assert res.json()["alerts_count"] == 300

    # Verify all 10 patterns were deduplicated to exactly 10 alerts in DB
    alerts = db_session.query(Alert).filter(Alert.event_type.like("batch_chunk_test_%")).all()
    assert len(alerts) == 10
    for a in alerts:
        assert a.occurrence_count == 30


def test_ingestion_intra_batch_events_outside_dedup_window(client, db_session: Session):
    """Verify that intra-batch events exceeding the recurrence window create distinct alerts."""
    t0 = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)
    t_distant = t0 + timedelta(minutes=30)  # 30 minutes later (beyond 300s dedup window)

    events = [
        # Window 1: 2 events
        {
            "timestamp": t0.isoformat(),
            "source_type": "Linux_Auth",
            "event_type": "burst_gap_test",
            "description": "Burst auth failure with time gap",
            "source_ip": "172.16.5.10",
            "username": "service_account",
            "telemetry_origin": "HISTORICAL_LOG"
        },
        {
            "timestamp": (t0 + timedelta(seconds=20)).isoformat(),
            "source_type": "Linux_Auth",
            "event_type": "burst_gap_test",
            "description": "Burst auth failure with time gap",
            "source_ip": "172.16.5.10",
            "username": "service_account",
            "telemetry_origin": "HISTORICAL_LOG"
        },
        # Window 2: 2 events (30 mins later)
        {
            "timestamp": t_distant.isoformat(),
            "source_type": "Linux_Auth",
            "event_type": "burst_gap_test",
            "description": "Burst auth failure with time gap",
            "source_ip": "172.16.5.10",
            "username": "service_account",
            "telemetry_origin": "HISTORICAL_LOG"
        },
        {
            "timestamp": (t_distant + timedelta(seconds=20)).isoformat(),
            "source_type": "Linux_Auth",
            "event_type": "burst_gap_test",
            "description": "Burst auth failure with time gap",
            "source_ip": "172.16.5.10",
            "username": "service_account",
            "telemetry_origin": "HISTORICAL_LOG"
        }
    ]

    payload = json.dumps(events).encode("utf-8")
    res = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("gap_events.json", io.BytesIO(payload), "application/json")},
        data={"source_type": "generic"}
    )
    assert res.status_code == 201
    assert res.json()["alerts_count"] == 4

    alerts = db_session.query(Alert).filter(
        Alert.event_type == "burst_gap_test"
    ).order_by(Alert.timestamp.asc()).all()

    assert len(alerts) == 2
    assert alerts[0].occurrence_count == 2
    assert alerts[0].first_seen.replace(tzinfo=timezone.utc) == t0
    assert alerts[0].last_seen.replace(tzinfo=timezone.utc) == t0 + timedelta(seconds=20)

    assert alerts[1].occurrence_count == 2
    assert alerts[1].first_seen.replace(tzinfo=timezone.utc) == t_distant
    assert alerts[1].last_seen.replace(tzinfo=timezone.utc) == t_distant + timedelta(seconds=20)
