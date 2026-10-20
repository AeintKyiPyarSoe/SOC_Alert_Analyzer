from unittest.mock import MagicMock
from app.security.host_sensor import HostSecuritySensor

def create_mock_proc(pid, name, exe, cmdline, parent_name=None):
    p = MagicMock()
    p.pid = pid
    p.name.return_value = name
    p.exe.return_value = exe
    p.cmdline.return_value = cmdline
    p.username.return_value = "SYSTEM"

    if parent_name:
        parent = MagicMock()
        parent.name.return_value = parent_name
        p.parent.return_value = parent
    else:
        p.parent.return_value = None
    return p

def test_behavioral_detection_evaluation_metrics():
    """
    Evaluates detection rules against an expanded curated dataset of labeled malicious
    and benign process execution scenarios. Reports precision and recall.
    Note: This is a controlled synthetic test benchmark to evaluate rule regression,
    not a statistical measurement of real-world production accuracy.
    """
    sensor = HostSecuritySensor()
    sensor.seen_signatures.clear()

    # Expanded Labeled Dataset: (mock_proc, is_malicious, label_id)
    dataset = [
        # Malicious Cases (Ground Truth = True) [10 Scenarios]
        (create_mock_proc(1001, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", ["cmd.exe", "/c", "whoami"], parent_name="w3wp.exe"), True, "web_shell_w3wp"),
        (create_mock_proc(1002, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-nop", "-w", "hidden"], parent_name="winword.exe"), True, "maldoc_word"),
        (create_mock_proc(1003, "vssadmin.exe", "C:\\Windows\\System32\\vssadmin.exe", ["vssadmin.exe", "delete", "shadows", "/all", "/quiet"]), True, "shadow_purge"),
        (create_mock_proc(1004, "svchost.exe", "C:\\Users\\Public\\svchost.exe", ["svchost.exe"]), True, "masquerading_svchost"),
        (create_mock_proc(1005, "mimikatz.exe", "C:\\Tools\\mimikatz.exe", ["mimikatz.exe"]), True, "offensive_mimikatz"),
        (create_mock_proc(1006, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "-enc", "SQBFAFgA"]), True, "encoded_ps"),
        (create_mock_proc(1007, "chisel.exe", "C:\\Users\\Public\\chisel.exe", ["chisel.exe", "client", "10.0.0.1:8000"]), True, "tunneling_chisel"),
        (create_mock_proc(1008, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "-nop", "-c", "downloadstring"]), True, "cradle_download"),
        (create_mock_proc(1009, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", ["cmd.exe", "/c", "calc.exe"], parent_name="excel.exe"), True, "maldoc_excel"),
        (create_mock_proc(1010, "payload.exe", "C:\\Users\\Victim\\AppData\\Local\\Temp\\payload.exe", ["payload.exe"]), True, "temp_execution"),

        # Benign Cases (Ground Truth = False) [10 Scenarios]
        (create_mock_proc(2001, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", ["chrome.exe"], parent_name="explorer.exe"), False, "browser"),
        (create_mock_proc(2002, "code.exe", "C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", ["Code.exe"], parent_name="ide"), False, "ide"),
        (create_mock_proc(2003, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", ["svchost.exe", "-k", "netsvcs"], parent_name="services.exe"), False, "legitimate_svchost_system32"),
        (create_mock_proc(2004, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "Get-Process"], parent_name="explorer.exe"), False, "legitimate_ps"),
        (create_mock_proc(2005, "notepad.exe", "C:\\Windows\\System32\\notepad.exe", ["notepad.exe", "notes.txt"], parent_name="explorer.exe"), False, "text_editor"),
        (create_mock_proc(2006, "python.exe", "C:\\Python313\\python.exe", ["python.exe", "manage.py", "runserver"], parent_name="cmd.exe"), False, "dev_server"),
        (create_mock_proc(2007, "Teams_updater.exe", "C:\\Users\\User\\AppData\\Local\\Temp\\Teams_updater.exe", ["Teams_updater.exe", "--check"]), False, "benign_temp_updater"),
        (create_mock_proc(2008, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "C:\\Scripts\\backup.ps1"], parent_name="explorer.exe"), False, "admin_ps_script"),
        (create_mock_proc(2009, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", ["C:\\Windows\\System32\\lsass.exe"], parent_name="wininit.exe"), False, "legitimate_lsass"),
        (create_mock_proc(2010, "node.exe", "C:\\Program Files\\nodejs\\node.exe", ["node.exe", "server.js"], parent_name="cmd.exe"), False, "node_runtime"),
    ]

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for proc, is_malicious, label in dataset:
        sensor.seen_signatures.clear()
        events = sensor._analyze_single_process(proc)
        detected = len(events) > 0

        if is_malicious and detected:
            tp += 1
        elif is_malicious and not detected:
            fn += 1
        elif not is_malicious and detected:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy = (tp + tn) / len(dataset)

    # Verification on expanded benchmark suite (10 TP, 10 TN)
    assert tp == 10, f"Expected 10 True Positives, got {tp}"
    assert fp == 0, f"Expected 0 False Positives, got {fp}"
    assert fn == 0, f"Expected 0 False Negatives, got {fn}"
    assert tn == 10, f"Expected 10 True Negatives, got {tn}"

    assert precision == 1.0, f"Precision should be 1.0, got {precision}"
    assert recall == 1.0, f"Recall should be 1.0, got {recall}"
    assert accuracy == 1.0, f"Accuracy should be 1.0, got {accuracy}"

def test_eval_false_positive_edge_cases_and_suppression():
    """Verify that ambiguous benign commands, alternate valid system directories, and suppressions do not trigger false alarms."""
    sensor = HostSecuritySensor()

    edge_cases = [
        # SysWOW64 Windows system binary path
        create_mock_proc(3001, "svchost.exe", "C:\\Windows\\SysWOW64\\svchost.exe", ["svchost.exe", "-k", "secsvcs"], parent_name="services.exe"),
        # Ambiguous command string containing "shadow" in harmless context
        create_mock_proc(3002, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "Get-ChildItem", "C:\\ShadowBackups"]),
        # Application running from user directory (not temp, not system binary)
        create_mock_proc(3003, "slack.exe", "C:\\Users\\Alice\\AppData\\Local\\Programs\\Slack\\slack.exe", ["slack.exe"]),
    ]

    for p in edge_cases:
        sensor.seen_signatures.clear()
        events = sensor._analyze_single_process(p)
        assert len(events) == 0, f"False positive detected on edge case: {p.name()}"

    # Verify configurable process suppression allowlist
    sensor.seen_signatures.clear()
    HostSecuritySensor.PROCESS_SUPPRESSIONS.add("mimikatz.exe")
    suppressed_proc = create_mock_proc(3004, "mimikatz.exe", "C:\\Tools\\mimikatz.exe", ["mimikatz.exe"])
    events = sensor._analyze_single_process(suppressed_proc)
    assert len(events) == 0, "Suppressed process should not produce alert events"
    HostSecuritySensor.PROCESS_SUPPRESSIONS.remove("mimikatz.exe")

