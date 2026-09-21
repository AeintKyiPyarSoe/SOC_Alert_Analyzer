import uuid
from datetime import datetime, timezone, timedelta
from app.models.alert import Alert
from app.models.incident import Incident
from app.security.correlator import IncidentCorrelator

def test_incident_correlator_groups_events(db_session):
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Insert 5 alerts within 1 minute from same source IP
    for i in range(5):
        alert = Alert(
            id=uuid.uuid4(),
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="Linux_Auth",
            event_type="ssh_authentication_failure",
            description="Failed password for root",
            source_ip="192.168.1.45",
            destination_ip="192.168.1.10",
            severity="MEDIUM",
            risk_score=50,
            status="OPEN"
        )
        db_session.add(alert)

    db_session.commit()

    # Correlate
    incidents = IncidentCorrelator.correlate_alerts(db_session, window_seconds=300)
    assert len(incidents) == 1

    incident = incidents[0]
    assert incident.alert_count == 5
    assert "192.168.1.45" in incident.title
    assert len(incident.alerts) == 5
