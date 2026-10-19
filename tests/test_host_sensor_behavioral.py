from unittest.mock import MagicMock
from app.security.host_sensor import HostSecuritySensor

def test_behavioral_web_shell_parent_child():
    sensor = HostSecuritySensor()
    # Mock web server parent spawning cmd.exe
    parent_mock = MagicMock()
    parent_mock.name.return_value = "w3wp.exe"

    proc_mock = MagicMock()
    proc_mock.pid = 9991
    proc_mock.name.return_value = "cmd.exe"
    proc_mock.exe.return_value = "C:\\Windows\\System32\\cmd.exe"
    proc_mock.cmdline.return_value = ["cmd.exe", "/c", "whoami"]
    proc_mock.username.return_value = "IIS_IUSRS"
    proc_mock.parent.return_value = parent_mock

    events = sensor._analyze_single_process(proc_mock)
    assert len(events) >= 1
    web_shell_events = [e for e in events if e["event_type"] == "web_shell_probe"]
    assert len(web_shell_events) == 1
    ev = web_shell_events[0]
    assert ev["mitre_technique"] == "T1505.003"
    assert ev["telemetry_origin"] == "HOST_TELEMETRY"
    assert "Web server 'w3wp.exe' spawned command interpreter 'cmd.exe'" in ev["description"]

def test_behavioral_maldoc_parent_child():
    sensor = HostSecuritySensor()
    # Mock MS Word parent spawning powershell.exe
    parent_mock = MagicMock()
    parent_mock.name.return_value = "winword.exe"

    proc_mock = MagicMock()
    proc_mock.pid = 9992
    proc_mock.name.return_value = "powershell.exe"
    proc_mock.exe.return_value = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    proc_mock.cmdline.return_value = ["powershell.exe", "-nop", "-w", "hidden", "-c", "iex(downloadstring)"]
    proc_mock.username.return_value = "john_doe"
    proc_mock.parent.return_value = parent_mock

    events = sensor._analyze_single_process(proc_mock)
    assert len(events) >= 1
    maldoc_events = [e for e in events if e["mitre_technique"] == "T1204.002"]
    assert len(maldoc_events) == 1
    assert maldoc_events[0]["telemetry_origin"] == "HOST_TELEMETRY"

def test_behavioral_ransomware_shadow_deletion():
    sensor = HostSecuritySensor()
    proc_mock = MagicMock()
    proc_mock.pid = 9993
    proc_mock.name.return_value = "vssadmin.exe"
    proc_mock.exe.return_value = "C:\\Windows\\System32\\vssadmin.exe"
    proc_mock.cmdline.return_value = ["vssadmin.exe", "delete", "shadows", "/all", "/quiet"]
    proc_mock.username.return_value = "SYSTEM"
    proc_mock.parent.return_value = None

    events = sensor._analyze_single_process(proc_mock)
    ransom_events = [e for e in events if e["mitre_technique"] == "T1490"]
    assert len(ransom_events) == 1
    assert "Inhibit System Recovery" in ransom_events[0]["description"]

def test_behavioral_masquerading_system_binary():
    sensor = HostSecuritySensor()
    sensor.os_type = "Windows"
    proc_mock = MagicMock()
    proc_mock.pid = 9994
    proc_mock.name.return_value = "svchost.exe"
    # Malicious masqueraded svchost executing out of user Downloads folder
    proc_mock.exe.return_value = "C:\\Users\\Victim\\Downloads\\svchost.exe"
    proc_mock.cmdline.return_value = ["svchost.exe"]
    proc_mock.username.return_value = "Victim"
    proc_mock.parent.return_value = None

    events = sensor._analyze_single_process(proc_mock)
    masq_events = [e for e in events if e["mitre_technique"] == "T1036.005"]
    assert len(masq_events) == 1
    assert "running outside System32" in masq_events[0]["description"]

def test_drill_telemetry_origin_separation(db_session):
    sensor = HostSecuritySensor()
    res = sensor.run_test_drill(db_session)
    assert res["status"] == "success"
    assert res["alert"]["telemetry_origin"] == "SECURITY_DRILL"
