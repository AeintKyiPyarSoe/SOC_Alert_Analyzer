from app.security.host_sensor import HostSecuritySensor, host_sensor
from app.models.alert import Alert

def test_host_info():
    sensor = HostSecuritySensor()
    info = sensor.get_host_info()
    assert info["hostname"] != ""
    assert info["os"] != ""
    assert info["process_count"] > 0
    assert "cpu_usage_percent" in info
    assert "memory_usage_percent" in info

def test_host_audit_processes():
    sensor = HostSecuritySensor()
    # audit_processes should execute without throwing any exception
    events = sensor.audit_processes()
    assert isinstance(events, list)

def test_host_audit_sockets():
    sensor = HostSecuritySensor()
    # audit_network_sockets should execute without throwing any exception
    events = sensor.audit_network_sockets()
    assert isinstance(events, list)

def test_host_audit_firewall():
    sensor = HostSecuritySensor()
    # audit_firewall_posture should execute without throwing any exception
    events = sensor.audit_firewall_posture()
    assert isinstance(events, list)

def test_host_test_drill(db_session):
    sensor = HostSecuritySensor()
    res = sensor.run_test_drill(db_session)
    assert res["status"] == "success"
    assert "alert" in res
    assert "[TEST DRILL]" in res["alert"]["description"]

    # Verify saved in DB
    alerts = db_session.query(Alert).all()
    assert len(alerts) >= 1

def test_host_audit_new_processes():
    sensor = HostSecuritySensor()
    # Reset known_pids to empty to simulate detecting current running processes
    sensor.known_pids = set()
    events = sensor.audit_new_processes()
    assert isinstance(events, list)
    assert len(sensor.known_pids) > 0

def test_host_audit_startup_folder():
    sensor = HostSecuritySensor()
    events = sensor.audit_startup_folder()
    assert isinstance(events, list)

def test_host_run_fast_audit(db_session):
    sensor = HostSecuritySensor()
    created = sensor.run_fast_audit(db_session)
    assert isinstance(created, list)

