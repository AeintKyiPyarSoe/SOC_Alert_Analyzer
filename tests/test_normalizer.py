from datetime import datetime, timezone
from app.security.normalizer import AlertNormalizer

def test_normalize_alert():
    raw_event = {
        "source_type": "Wazuh",
        "timestamp": "2026-09-10T10:00:00Z",
        "event_type": "ssh_authentication_failure",
        "description": "sshd: Failed authentication attempt",
        "source_ip": "198.51.100.45",
        "destination_ip": "192.168.1.10",
        "source_port": "54321",
        "destination_port": "22",
        "username": "root",
        "rule_level": 10
    }

    norm = AlertNormalizer.normalize(raw_event)
    assert norm["source_type"] == "Wazuh"
    assert norm["event_type"] == "ssh_authentication_failure"
    assert norm["source_ip"] == "198.51.100.45"
    assert norm["destination_ip"] == "192.168.1.10"
    assert norm["source_port"] == 54321
    assert norm["destination_port"] == 22
    assert norm["username"] == "root"
    assert norm["status"] == "OPEN"
    assert norm["mitre_technique"] == "T1110"
    assert norm["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert isinstance(norm["risk_score"], int)
    assert 0 <= norm["risk_score"] <= 100

def test_normalize_invalid_fields():
    raw_event = {
        "source_type": "Suricata",
        "timestamp": "invalid-timestamp",
        "event_type": "network_scan",
        "description": "Port scan sweep",
        "source_ip": "invalid-ip-string",
        "source_port": "not-a-port"
    }
    norm = AlertNormalizer.normalize(raw_event)
    assert norm["source_ip"] is None
    assert norm["source_port"] is None
    assert isinstance(norm["timestamp"], datetime)
