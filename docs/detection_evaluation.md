# Detection Evaluation & Quality Benchmark

This document provides empirical evaluation evidence, testing methodologies, and performance metrics for the behavioral threat detection engine in **SOC Alert Analyzer**.

---

## 1. Evaluation Methodology & Ground Truth

To measure detection fidelity and avoid unverified claims, detection rules are evaluated using automated test harness suites ([`tests/detection_eval/test_eval_host_behavioral.py`](../tests/detection_eval/test_eval_host_behavioral.py)).

### Test Dataset Composition
- **Malicious Evaluation Scenarios**: 6 curated attack patterns based on real-world MITRE ATT&CK techniques (Web Shell execution, malicious document macro chains, ransomware shadow copy deletion, system binary masquerading, offensive tool execution, and encoded PowerShell cradles).
- **Benign Evaluation Scenarios**: 6 representative benign workstation processes (browser execution, IDE development servers, legitimate `svchost.exe` services in `System32`, administrative PowerShell commands, text editors, and development runtimes).

---

## 2. Benchmark Results & Confusion Matrix

| Metric | Measured Value | Formulation | Notes |
| :--- | :---: | :--- | :--- |
| **True Positives (TP)** | 6 | Correctly identified malicious processes | 100% of tested attacks detected |
| **False Positives (FP)** | 0 | Benign processes incorrectly flagged | 0 benign processes misidentified |
| **True Negatives (TN)** | 6 | Correctly ignored benign processes | Normal activity permitted |
| **False Negatives (FN)** | 0 | Malicious processes missed | No missed detections in test suite |
| **Precision** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | High fidelity, low alert fatigue |
| **Recall (Sensitivity)** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | Comprehensive coverage of defined rules |
| **Accuracy** | **1.00 (100%)** | $\frac{\text{TP} + \text{TN}}{\text{Total}}$ | Overall benchmark score |

---

## 3. Per-Rule Breakdown

| Detection Rule | MITRE Technique | Tested Indicators | Result |
| :--- | :---: | :--- | :---: |
| **Web Shell Execution** | `T1505.003` | `w3wp.exe` spawning `cmd.exe` | **TP** |
| **Malicious Office Macro** | `T1204.002` | `winword.exe` spawning hidden `powershell.exe` | **TP** |
| **Ransomware Backup Purge** | `T1490` | `vssadmin.exe delete shadows /all /quiet` | **TP** |
| **Process Masquerading** | `T1036.005` | `svchost.exe` running from `\Users\Public\` | **TP** |
| **Offensive Tool Binary** | `T1059` | `mimikatz.exe` execution | **TP** |
| **Encoded PowerShell Cradle** | `T1059.001` | `powershell.exe -enc ...` | **TP** |
| **Web Browser Launch** | Benign Baseline | `explorer.exe` launching `chrome.exe` | **TN** |
| **IDE & Dev Tools** | Benign Baseline | `explorer.exe` launching `Code.exe` | **TN** |
| **Legitimate Windows Service** | Benign Baseline | `services.exe` launching `C:\Windows\System32\svchost.exe` | **TN** |
| **Interactive Admin PowerShell** | Benign Baseline | `powershell.exe Get-Process` | **TN** |
| **Text Editor Execution** | Benign Baseline | `notepad.exe notes.txt` | **TN** |
| **Local Dev Web Server** | Benign Baseline | `python.exe manage.py runserver` | **TN** |

---

## 4. Operational Boundaries & False Positive Management

1. **Synthetic vs. Real-World Variance**: While the benchmark demonstrates 100% precision on curated unit test datasets, real-world corporate environments contain proprietary internal administrative tools, custom deployment wrappers, and IT management agents that may share behaviors with LOLBins.
2. **Process Normalization**: All paths are normalized via `os.path.normpath` and `os.path.normcase` to eliminate bypasses based on slash direction or device prefix evasion (`\??\`).
3. **Allowlisting & Suppressions**: False positives for approved enterprise tools can be suppressed without modifying core rule logic by configuring `HostSecuritySensor.PROCESS_SUPPRESSIONS`.
