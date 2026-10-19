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
    Evaluates detection rules against a curated dataset of labeled malicious
    and benign process execution scenarios. Reports precision and recall.
    """
    sensor = HostSecuritySensor()
    # Ensure fresh signatures for test
    sensor.seen_signatures.clear()

    # Labeled Dataset: (mock_proc, is_malicious, label_id)
    dataset = [
        # Malicious Cases (Ground Truth = True)
        (create_mock_proc(1001, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", ["cmd.exe", "/c", "whoami"], parent_name="w3wp.exe"), True, "web_shell"),
        (create_mock_proc(1002, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-nop", "-w", "hidden"], parent_name="winword.exe"), True, "maldoc"),
        (create_mock_proc(1003, "vssadmin.exe", "C:\\Windows\\System32\\vssadmin.exe", ["vssadmin.exe", "delete", "shadows", "/all", "/quiet"]), True, "shadow_purge"),
        (create_mock_proc(1004, "svchost.exe", "C:\\Users\\Public\\svchost.exe", ["svchost.exe"]), True, "masquerading"),
        (create_mock_proc(1005, "mimikatz.exe", "C:\\Tools\\mimikatz.exe", ["mimikatz.exe"]), True, "offensive_tool"),
        (create_mock_proc(1006, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "-enc", "SQBFAFgA"]), True, "encoded_ps"),

        # Benign Cases (Ground Truth = False)
        (create_mock_proc(2001, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", ["chrome.exe"], parent_name="explorer.exe"), False, "browser"),
        (create_mock_proc(2002, "code.exe", "C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", ["Code.exe"], parent_name="explorer.exe"), False, "ide"),
        (create_mock_proc(2003, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", ["svchost.exe", "-k", "netsvcs"], parent_name="services.exe"), False, "legitimate_svchost"),
        (create_mock_proc(2004, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "Get-Process"], parent_name="explorer.exe"), False, "legitimate_ps"),
        (create_mock_proc(2005, "notepad.exe", "C:\\Windows\\System32\\notepad.exe", ["notepad.exe", "notes.txt"], parent_name="explorer.exe"), False, "text_editor"),
        (create_mock_proc(2006, "python.exe", "C:\\Python313\\python.exe", ["python.exe", "manage.py", "runserver"], parent_name="cmd.exe"), False, "dev_server"),
    ]

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for proc, is_malicious, label in dataset:
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

    # Verification: High fidelity detection on standard test scenarios
    assert tp == 6, f"Expected 6 True Positives, got {tp}"
    assert fp == 0, f"Expected 0 False Positives, got {fp}"
    assert fn == 0, f"Expected 0 False Negatives, got {fn}"
    assert tn == 6, f"Expected 6 True Negatives, got {tn}"

    assert precision == 1.0, f"Precision should be 1.0, got {precision}"
    assert recall == 1.0, f"Recall should be 1.0, got {recall}"
    assert accuracy == 1.0, f"Accuracy should be 1.0, got {accuracy}"
