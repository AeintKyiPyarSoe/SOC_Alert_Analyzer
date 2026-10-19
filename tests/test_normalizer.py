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
    assert norm["is_valid_timestamp"] is True

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
    # Invalid timestamp must be explicitly identified rather than silently ignored
    assert norm["is_valid_timestamp"] is False
    assert "[INVALID_TIMESTAMP_DETECTED" in norm["raw_log"]

def test_normalize_multi_format_timestamps():
    # 1. Syslog format
    r_syslog = AlertNormalizer.normalize({"timestamp": "Sep 10 10:00:00", "description": "test"})
    assert r_syslog["is_valid_timestamp"] is True

    # 2. Apache format
    r_apache = AlertNormalizer.normalize({"timestamp": "10/Sep/2026:10:00:00 +0000", "description": "test"})
    assert r_apache["is_valid_timestamp"] is True

    # 3. Numeric Epoch timestamp
    r_epoch = AlertNormalizer.normalize({"timestamp": 1725962400, "description": "test"})
    assert r_epoch["is_valid_timestamp"] is True

    # 4. Null / Missing timestamp explicitly marked invalid
    r_null = AlertNormalizer.normalize({"timestamp": None, "description": "test"})
    assert r_null["is_valid_timestamp"] is False

def test_normalize_vague_description_synthesized():
    # Vague or missing descriptions must be enriched with context rather than "Security Event Detected"
    raw_event = {
        "event_type": "windows_failed_logon",
        "description": "Security Event Detected",
        "username": "Administrator",
        "source_ip": "192.168.1.55",
        "destination_port": "445",
        "source_type": "Windows_Event"
    }
    norm = AlertNormalizer.normalize(raw_event)
    assert norm["description"] != "Security Event Detected"
    assert "Windows Failed Logon activity detected" in norm["description"]
    assert "user account 'Administrator'" in norm["description"]
    assert "192.168.1.55" in norm["description"]
    assert "port 445" in norm["description"]

