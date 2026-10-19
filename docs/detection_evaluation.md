# Detection Evaluation & Quality Benchmark

This document provides empirical evaluation evidence, testing methodologies, performance metrics, and documented operational limitations for the behavioral threat detection engine in **SOC Alert Analyzer**.

---

## 1. Evaluation Methodology & Ground Truth

To measure detection fidelity and avoid unverified claims, detection heuristics are evaluated using automated unit evaluation test suites ([`tests/detection_eval/test_eval_host_behavioral.py`](../tests/detection_eval/test_eval_host_behavioral.py)).

> [!IMPORTANT]
> **Evaluation Dataset Scope & Real-World Context**:  
> The benchmark dataset comprises 20 curated synthetic process execution scenarios (10 malicious and 10 benign) along with targeted false-positive edge cases. This dataset serves as a **deterministic regression test harness** to verify that behavioral heuristic rules execute accurately across platforms (Windows, Linux, macOS).  
> **A 100% benchmark score on these curated unit test scenarios does NOT represent 100% accuracy against unknown threats, evasive in-the-wild malware, or complex enterprise environments.**

### Dataset Composition (20 Curated Scenarios)
- **Malicious Scenarios (10)**: Web Shell execution (`w3wp.exe` → `cmd.exe`), malicious Word document macro (`winword.exe` → hidden `powershell.exe`), malicious Excel macro (`excel.exe` → `cmd.exe`), ransomware shadow copy purge (`vssadmin.exe delete shadows`), system binary masquerading (`svchost.exe` outside `System32`), offensive credential dumper (`mimikatz.exe`), network tunneling tool (`chisel.exe`), encoded PowerShell script block (`-enc`), download cradle execution (`Net.WebClient.DownloadString`), and temporary writable directory payload execution.
- **Benign Baseline Scenarios (10)**: Web browser launch (`chrome.exe`), developer IDE (`Code.exe`), legitimate Windows core service (`System32\svchost.exe`), interactive administrative command (`Get-Process`), text editor (`notepad.exe`), development runtime server (`python.exe runserver`), benign temporary updater (`Teams_updater.exe`), administrative PowerShell script with execution policy bypass, legitimate security subsystem (`System32\lsass.exe`), and backend Node.js runtime (`node.exe`).

---

## 2. Benchmark Results & Confusion Matrix

The following metrics are derived directly from the automated execution of `tests/detection_eval/test_eval_host_behavioral.py`:

| Metric | Measured Value | Formulation | Operational Meaning |
| :--- | :---: | :--- | :--- |
| **True Positives (TP)** | 10 | Correctly flagged malicious processes | All 10 curated attack signatures successfully detected |
| **False Positives (FP)** | 0 | Benign processes incorrectly flagged | Zero false alarms triggered on standard benign workflows |
| **True Negatives (TN)** | 10 | Correctly ignored benign processes | Normal developer and administrative activity permitted |
| **False Negatives (FN)** | 0 | Malicious processes missed | No missed detections within the defined test scenarios |
| **Precision** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | High fidelity on evaluated behavioral signatures |
| **Recall (Sensitivity)** | **1.00 (100%)** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | Full coverage of targeted MITRE ATT&CK techniques in suite |
| **Accuracy** | **1.00 (100%)** | $\frac{\text{TP} + \text{TN}}{\text{Total}}$ | 20 / 20 correct classifications in curated suite |

---

## 3. Per-Scenario Evaluation Breakdown

| Scenario ID | Category | MITRE Technique | Process Name & Indicator | Detection Engine Result |
| :--- | :--- | :---: | :--- | :---: |
| `web_shell_w3wp` | Malicious | `T1505.003` | `w3wp.exe` spawning `cmd.exe /c whoami` | **TP** |
| `maldoc_word` | Malicious | `T1204.002` | `winword.exe` spawning hidden `powershell.exe` | **TP** |
| `maldoc_excel` | Malicious | `T1204.002` | `excel.exe` spawning `cmd.exe /c calc.exe` | **TP** |
| `shadow_purge` | Malicious | `T1490` | `vssadmin.exe delete shadows /all /quiet` | **TP** |
| `masquerading_svchost` | Malicious | `T1036.005` | `svchost.exe` running from `C:\Users\Public\` | **TP** |
| `offensive_mimikatz` | Malicious | `T1059` | `mimikatz.exe` standalone execution | **TP** |
| `tunneling_chisel` | Malicious | `T1059` | `chisel.exe client 10.0.0.1:8000` | **TP** |
| `encoded_ps` | Malicious | `T1059.001` | `powershell.exe -enc SQBFAFgA...` | **TP** |
| `cradle_download` | Malicious | `T1059.001` | `powershell.exe -nop -c downloadstring` | **TP** |
| `temp_execution` | Malicious | `T1036` | `payload.exe` executed from `\AppData\Local\Temp\` | **TP** |
| `browser` | Benign | N/A | `explorer.exe` launching `chrome.exe` | **TN** |
| `ide` | Benign | N/A | `explorer.exe` launching `Code.exe` | **TN** |
| `legitimate_svchost` | Benign | N/A | `services.exe` launching `C:\Windows\System32\svchost.exe` | **TN** |
| `legitimate_ps` | Benign | N/A | `powershell.exe Get-Process` | **TN** |
| `text_editor` | Benign | N/A | `notepad.exe notes.txt` | **TN** |
| `dev_server` | Benign | N/A | `python.exe manage.py runserver` | **TN** |
| `benign_temp_updater` | Benign | N/A | `Teams_updater.exe` running from `\Temp\` | **TN** |
| `admin_ps_script` | Benign | N/A | `powershell.exe -ExecutionPolicy Bypass -File backup.ps1` | **TN** |
| `legitimate_lsass` | Benign | N/A | `wininit.exe` launching `C:\Windows\System32\lsass.exe` | **TN** |
| `node_runtime` | Benign | N/A | `node.exe server.js` from `Program Files\nodejs` | **TN** |

---

## 4. False-Positive Edge Cases & Allowlist Verification

Automated regression tests ([`test_eval_false_positive_edge_cases_and_suppression`](../tests/detection_eval/test_eval_host_behavioral.py)) specifically verify edge cases to prevent alert fatigue:

1. **Alternate Valid Windows Subsystems**: `C:\Windows\SysWOW64\svchost.exe` is recognized as a valid 32-bit compatibility path and does not trigger masquerading alerts.
2. **Ambiguous Keyword Overlaps**: Non-malicious commands containing keywords in benign contexts (e.g., `powershell.exe Get-ChildItem C:\ShadowBackups`) do not trigger ransomware defense evasion rules.
3. **Legitimate User-Space Software**: Desktop tools installed in `%LOCALAPPDATA%\Programs\` (e.g., Slack, VS Code) are not confused with temporary folder malware.
4. **Configurable Suppressions**: Enterprise software or authorized administrative scripts can be added to `HostSecuritySensor.PROCESS_SUPPRESSIONS` to bypass detection without modifying rule logic.

---

## 5. Documented Operational Boundaries & Limitations

1. **User-Space EDR-Lite**: The host sensor runs as a user-space monitoring process (`psutil`, socket inspection, and OS event logs). It does not deploy kernel drivers (ELAM, minifilters, or eBPF).
2. **Memory Injection & Direct Syscalls**: Attack techniques that do not spawn new processes, do not create listening sockets, or execute directly via reflective DLL injection or direct unhooked syscalls in existing trusted processes cannot be observed by user-space process polling alone.
3. **LOLBin Behavioral Thresholding**: PowerShell heuristics use a weighted scoring system (`lolbin_weight >= 3`). A single flag (such as `-ExecutionPolicy Bypass` used by legitimate backup scripts) does not trigger an alert by itself. Highly obfuscated cradles that evade string matching may require deeper script block logging (Event ID 4104) enabled on the host.
4. **Cross-Platform Parity**: The sensor normalizes process paths across Windows, Linux, and macOS. Process masquerading rules for Windows core binaries execute consistently regardless of the host OS, supporting multi-platform backend deployments and containerized testing.
