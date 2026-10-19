import uuid
from datetime import datetime, timezone, timedelta
from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.security.correlator import IncidentCorrelator

def test_correlator_merges_across_multiple_uploads(db_session):
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Batch 1: First upload of 3 alerts
    for i in range(3):
        alert = Alert(
            id=uuid.uuid4(),
            timestamp=base_time + timedelta(seconds=i * 20),
            source_type="Wazuh",
            event_type="ssh_authentication_failure",
            description="sshd: Failed password for root",
            source_ip="198.51.100.99",
            destination_ip="192.168.1.10",
            severity="MEDIUM",
            risk_score=45,
            status="OPEN"
        )
        db_session.add(alert)
    db_session.commit()

    # Correlate Batch 1
    incidents_b1 = IncidentCorrelator.correlate_alerts(db_session, window_seconds=300)
    assert len(incidents_b1) == 1
    inc_1 = incidents_b1[0]
    assert inc_1.alert_count == 3
    inc_1_id = inc_1.id

    # Batch 2: Second upload with 2 more alerts within the 5-minute sliding window (e.g. 2 minutes later)
    for i in range(2):
        alert2 = Alert(
            id=uuid.uuid4(),
            timestamp=base_time + timedelta(minutes=2, seconds=i * 15),
            source_type="Wazuh",
            event_type="ssh_authentication_failure",
            description="sshd: Failed password for root",
            source_ip="198.51.100.99",
            destination_ip="192.168.1.10",
            severity="MEDIUM",
            risk_score=45,
            status="OPEN"
        )
        db_session.add(alert2)
    db_session.commit()

    # Correlate Batch 2 - should merge into the EXISTING incident rather than creating a duplicate
    incidents_b2 = IncidentCorrelator.correlate_alerts(db_session, window_seconds=300)
    
    # Should still only have 1 incident in total, and the updated incident has id == inc_1_id
    all_incidents = db_session.query(Incident).all()
    assert len(all_incidents) == 1
    updated_incident = all_incidents[0]
    assert updated_incident.id == inc_1_id
    assert updated_incident.alert_count == 5
    assert len(updated_incident.alerts) == 5

def test_correlator_skips_when_no_unlinked_alerts(db_session):
    # Running correlator on an empty DB returns empty list without error
    res = IncidentCorrelator.correlate_alerts(db_session)
    assert res == []

def test_correlator_separates_distinct_event_types(db_session):
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Alert of type A
    a1 = Alert(
        id=uuid.uuid4(),
        timestamp=base_time,
        source_type="Suricata",
        event_type="network_scan",
        description="Port scan",
        source_ip="203.0.113.10",
        severity="LOW",
        risk_score=35,
        status="OPEN"
    )
    # Alert of type B from same IP
    a2 = Alert(
        id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=10),
        source_type="Suricata",
        event_type="exploit_attempt",
        description="Log4j exploit",
        source_ip="203.0.113.10",
        severity="HIGH",
        risk_score=75,
        status="OPEN"
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    incidents = IncidentCorrelator.correlate_alerts(db_session, window_seconds=300)
    assert len(incidents) == 2
