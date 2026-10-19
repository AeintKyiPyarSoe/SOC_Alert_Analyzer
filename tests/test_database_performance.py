import uuid
from datetime import datetime, timezone, timedelta
from app.models.alert import Alert
from app.models.incident import Incident

def test_sql_aggregation_dashboard_stats(client, db_session):
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Insert precise severity distribution
    alerts_data = [
        ("CRITICAL", "OPEN"),
        ("CRITICAL", "INVESTIGATING"),
        ("HIGH", "OPEN"),
        ("HIGH", "RESOLVED"),
        ("MEDIUM", "FALSE_POSITIVE"),
        ("LOW", "OPEN"),
    ]

    for sev, stat in alerts_data:
        db_session.add(Alert(
            id=uuid.uuid4(),
            timestamp=base_time,
            source_type="Wazuh",
            event_type="test_event",
            description=f"Test {sev} alert",
            severity=sev,
            status=stat
        ))
    db_session.commit()

    res = client.get("/api/v1/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()

    assert stats["total_alerts"] == 6
    assert stats["critical_count"] == 2
    assert stats["high_count"] == 2
    assert stats["medium_count"] == 1
    assert stats["low_count"] == 1

    assert stats["open_count"] == 3
    assert stats["investigating_count"] == 1
    assert stats["resolved_count"] == 1
    assert stats["false_positive_count"] == 1

def test_alerts_pagination(client, db_session):
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Insert 15 alerts
    for i in range(15):
        db_session.add(Alert(
            id=uuid.uuid4(),
            timestamp=base_time + timedelta(seconds=i),
            source_type="Suricata",
            event_type="network_scan",
            description=f"Scan #{i}",
            severity="LOW",
            status="OPEN"
        ))
    db_session.commit()

    # Page 1: limit 5, offset 0
    p1 = client.get("/api/v1/alerts?limit=5&offset=0").json()
    assert len(p1) == 5

    # Page 2: limit 5, offset 5
    p2 = client.get("/api/v1/alerts?limit=5&offset=5").json()
    assert len(p2) == 5

    # Ensure pages are completely distinct
    p1_ids = {a["id"] for a in p1}
    p2_ids = {a["id"] for a in p2}
    assert len(p1_ids.intersection(p2_ids)) == 0

def test_database_indexes_registered():
    alert_idx_names = {idx.name for idx in Alert.__table__.indexes}
    assert "idx_alerts_status_timestamp" in alert_idx_names
    assert "idx_alerts_severity_timestamp" in alert_idx_names
    assert "idx_alerts_origin_timestamp" in alert_idx_names

    inc_idx_names = {idx.name for idx in Incident.__table__.indexes}
    assert "idx_incidents_status_last_seen" in inc_idx_names
    assert "idx_incidents_risk_last_seen" in inc_idx_names
