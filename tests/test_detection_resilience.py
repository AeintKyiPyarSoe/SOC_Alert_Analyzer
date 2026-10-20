import uuid
from datetime import datetime, timezone, timedelta
from app.security.risk_engine import RiskEngine
from app.security.mitre_mapper import MitreMapper
from app.parsers.suricata import SuricataParser
from app.security.correlator import IncidentCorrelator
from app.models.alert import Alert

def test_risk_engine_nan_inf_handling():
    """Verify that RiskEngine handles NaN, Inf, and invalid confidence without raising exceptions."""
    score, sev, breakdown = RiskEngine.calculate_risk(
        event_type="windows_suspicious_process",
        source_type="Host_Process_Sensor",
        detection_confidence=float("nan")
    )
    assert 0 <= score <= 100
    assert breakdown["confidence_modifier"] == 0

    score_inf, _, breakdown_inf = RiskEngine.calculate_risk(
        event_type="windows_suspicious_process",
        source_type="Host_Process_Sensor",
        detection_confidence=float("inf")
    )
    assert 0 <= score_inf <= 100
    assert breakdown_inf["confidence_modifier"] == 0

def test_risk_engine_none_and_empty_inputs():
    """Verify that RiskEngine handles None or empty event_type and negative parameters safely."""
    score, sev, _ = RiskEngine.calculate_risk(
        event_type=None,
        source_type=None,
        raw_level="invalid_level",
        frequency_count=-10
    )
    assert 0 <= score <= 100
    assert sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

def test_suricata_parser_anti_false_positive():
    """Verify that words like 'paradox' or 'msdos' in signatures do NOT trigger denial_of_service."""
    parser = SuricataParser()
    eve_log = (
        '{"timestamp": "2026-03-20T10:00:00.000000+0000", "event_type": "alert", '
        '"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_port": 1234, "dest_port": 80, '
        '"alert": {"action": "allowed", "signature": "ET INFO Paradox Database Connection", "severity": 3}}\n'
        '{"timestamp": "2026-03-20T10:00:01.000000+0000", "event_type": "alert", '
        '"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_port": 1235, "dest_port": 80, '
        '"alert": {"action": "allowed", "signature": "SURICATA STREAM SYN flood detected", "severity": 1}}\n'
    )
    events = parser.parse(eve_log)
    assert len(events) == 2
    # First event should NOT be denial of service (should be network_anomaly)
    assert events[0]["event_type"] != "denial_of_service"
    # Second event is genuinely a flood
    assert events[1]["event_type"] == "denial_of_service"

def test_mitre_mapper_anti_false_positive():
    """Verify that benign phrases do not trigger false ATT&CK technique mappings."""
    # Benign word 'shadows' should NOT map to T1490 (Inhibit System Recovery)
    assert MitreMapper.map_event("audit_log", "User reviewed shadows document") != "T1490"

    # Benign 'antivirus scan completed' should NOT map to T1046 (Network Service Discovery)
    assert MitreMapper.map_event("endpoint_status", "Antivirus scan completed normally") != "T1046"

    # Benign 'standard user privilege' should NOT map to T1548 (Abuse Elevation Control Mechanism)
    assert MitreMapper.map_event("user_login", "User granted standard user privilege") != "T1548"

    # Uncertain / unknown event should map to None
    assert MitreMapper.map_event("unknown_custom_telemetry", "routine diagnostic pulse") is None

def test_correlator_out_of_order_clustering():
    """Verify that _cluster_by_time correctly clusters alerts when timestamps arrive out of order."""
    base_time = datetime(2026, 3, 20, 12, 0, 0, tzinfo=timezone.utc)
    
    # Create mock Alert objects out-of-order
    a1 = Alert(id=uuid.uuid4(), timestamp=base_time + timedelta(seconds=120), is_valid_timestamp=True, event_type="test")
    a2 = Alert(id=uuid.uuid4(), timestamp=base_time, is_valid_timestamp=True, event_type="test")
    a3 = Alert(id=uuid.uuid4(), timestamp=base_time + timedelta(seconds=60), is_valid_timestamp=True, event_type="test")
    a4 = Alert(id=uuid.uuid4(), timestamp=base_time + timedelta(seconds=900), is_valid_timestamp=True, event_type="test")  # Outside 300s window

    clusters = IncidentCorrelator._cluster_by_time([a1, a2, a3, a4], timedelta(seconds=300))
    # Should produce 2 clusters: {a2, a3, a1} within 300s, and {a4} separated
    assert len(clusters) == 2
    assert len(clusters[0]) == 3
    assert len(clusters[1]) == 1
    # Check that items inside cluster are sorted chronologically
    assert clusters[0][0].timestamp < clusters[0][1].timestamp < clusters[0][2].timestamp
