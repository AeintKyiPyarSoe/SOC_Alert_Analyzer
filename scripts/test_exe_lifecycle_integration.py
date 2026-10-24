#!/usr/bin/env python3
"""
scripts/test_exe_lifecycle_integration.py
SOC Alert Analyzer - Real Executable / Subprocess Lifecycle Integration Test

Exercises Tests A through G across process restarts:
  Test A: Process Spawn & Readiness Check on dynamic port in isolated DATA_DIR.
  Test B: Pause Host Monitoring via API and verify preferences persisted to disk.
  Test C: Clear Alerts while paused; verify quiescence (no resurrection/rescan).
  Test D: Process Kill & Restart; verify PAUSED preference survived reboot without rescan.
  Test E: Trigger Manual Host Audit; verify it completes while monitoring remains PAUSED.
  Test F: Resume Host Monitoring via API; verify ACTIVE and task RUNNING.
  Test G: Process Restart; verify ACTIVE preference restored across reboot. Clean shutdown.
"""

import os
import sys
import time
import json
import socket
import shutil
import tempfile
import argparse
import subprocess
import urllib.request
import urllib.error

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def make_request(method: str, url: str, headers: dict = None, data: dict = None, timeout: float = 10.0):
    req_headers = headers.copy() if headers else {}
    body = None
    if data is not None:
        body = json.dumps(data).encode('utf-8')
        req_headers['Content-Type'] = 'application/json'

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode('utf-8')
            try:
                return resp.status, json.loads(resp_body)
            except Exception:
                return resp.status, resp_body
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(err_body)
        except Exception:
            return e.code, err_body

def wait_for_ready(base_url: str, max_wait: float = 30.0) -> bool:
    start = time.time()
    url = f"{base_url}/api/v1/stream/status"
    while time.time() - start < max_wait:
        try:
            status, data = make_request("GET", url, timeout=2.0)
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

def run_lifecycle_integration_tests(cmd_prefix: list, data_dir: str):
    print("=" * 70)
    print("SOC Alert Analyzer: Lifecycle Integration Test Across Process Restarts")
    print(f"Target Command: {' '.join(cmd_prefix)}")
    print(f"Isolated Data Dir: {data_dir}")
    print("=" * 70)

    admin_key = "test_admin_key_super_secret_123"
    analyst_key = "test_analyst_key_super_secret_456"
    secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    base_env = os.environ.copy()
    base_env["DATA_DIR"] = data_dir
    base_env["ADMIN_API_KEY"] = admin_key
    base_env["ANALYST_API_KEY"] = analyst_key
    base_env["SECRET_KEY"] = secret_key
    base_env["ENVIRONMENT"] = "development"
    base_env["AUTH_ENABLED"] = "true"
    base_env["ALLOW_INSECURE_AUTH_DISABLED"] = "false"
    base_env["NO_BROWSER"] = "1"

    admin_headers = {"X-API-Key": admin_key}
    analyst_headers = {"X-API-Key": analyst_key}

    # ---------------------------------------------------------
    # TEST A: Process Spawn & Readiness Check
    # ---------------------------------------------------------
    port_a = find_free_port()
    print(f"\n[TEST A] Starting initial process on port {port_a}...")
    run_cmd_a = cmd_prefix + ["--port", str(port_a), "--no-browser"]
    proc_a = subprocess.Popen(run_cmd_a, env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        base_url_a = f"http://127.0.0.1:{port_a}"
        if not wait_for_ready(base_url_a, max_wait=30.0):
            stdout, stderr = proc_a.communicate(timeout=5)
            print(f"Server failed to start:\nSTDOUT:\n{stdout.decode()}\nSTDERR:\n{stderr.decode()}")
            raise RuntimeError("Test A Failed: Server readiness check timed out.")

        status_code, st_data = make_request("GET", f"{base_url_a}/api/v1/stream/status")
        assert status_code == 200, f"Unexpected status code: {status_code}"
        assert st_data["host_monitoring_active"] is True, f"Expected default ACTIVE, got {st_data}"
        assert st_data["task_status"] == "RUNNING", f"Expected RUNNING, got {st_data}"
        print("  [+] TEST A PASSED: Server online, default monitoring ACTIVE, task RUNNING.")

        # ---------------------------------------------------------
        # TEST B: Pause Host Monitoring
        # ---------------------------------------------------------
        print("\n[TEST B] Pausing host monitoring via API...")
        status_code, toggle_data = make_request("POST", f"{base_url_a}/api/v1/host/monitor/toggle?active=false", headers=analyst_headers)
        assert status_code == 200, f"Toggle failed with code {status_code}: {toggle_data}"
        assert toggle_data["host_monitoring_active"] is False
        assert toggle_data["task_status"] == "PAUSED"
        assert toggle_data["persisted"] is True

        # Verify disk preference file
        pref_file = os.path.join(data_dir, "monitoring_preferences.json")
        assert os.path.exists(pref_file), f"Preferences file not found at {pref_file}"
        with open(pref_file, "r", encoding="utf-8") as f:
            disk_prefs = json.load(f)
        assert disk_prefs["host_monitoring_active"] is False
        print("  [+] TEST B PASSED: Host monitoring paused and persisted to disk.")

        # ---------------------------------------------------------
        # TEST C: Clear Alerts & Verify Quiescence
        # ---------------------------------------------------------
        print("\n[TEST C] Clearing alerts while paused and verifying no background rescan...")
        status_code, clear_data = make_request("POST", f"{base_url_a}/api/v1/alerts/clear", headers=admin_headers)
        assert status_code == 200, f"Clear failed: {clear_data}"
        assert "paused" in clear_data.get("message", "").lower()

        status_code, alerts_data = make_request("GET", f"{base_url_a}/api/v1/alerts", headers=analyst_headers)
        assert status_code == 200
        assert len(alerts_data) == 0, f"Expected 0 alerts, got {len(alerts_data)}"

        # Wait 3 seconds to guarantee background loop tick does not create alerts
        time.sleep(3.0)
        status_code, alerts_after = make_request("GET", f"{base_url_a}/api/v1/alerts", headers=analyst_headers)
        assert status_code == 200
        assert len(alerts_after) == 0, f"Alerts resurrected while paused! Got {len(alerts_after)}"
        print("  [+] TEST C PASSED: Alerts cleared; verified zero alerts and no background rescan.")

    finally:
        print("  [*] Terminating Process A...")
        proc_a.terminate()
        try:
            proc_a.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_a.kill()

    # ---------------------------------------------------------
    # TEST D: Process Kill & Restart; Verify PAUSED Persisted
    # ---------------------------------------------------------
    port_d = find_free_port()
    print(f"\n[TEST D] Rebooting process on port {port_d} with same DATA_DIR to verify persistence...")
    run_cmd_d = cmd_prefix + ["--port", str(port_d), "--no-browser"]
    proc_d = subprocess.Popen(run_cmd_d, env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        base_url_d = f"http://127.0.0.1:{port_d}"
        if not wait_for_ready(base_url_d, max_wait=30.0):
            stdout, stderr = proc_d.communicate(timeout=5)
            print(f"Server D failed to start:\nSTDOUT:\n{stdout.decode()}\nSTDERR:\n{stderr.decode()}")
            raise RuntimeError("Test D Failed: Server D readiness check timed out.")

        status_code, st_data_d = make_request("GET", f"{base_url_d}/api/v1/stream/status")
        assert status_code == 200
        assert st_data_d["host_monitoring_active"] is False, f"Expected PAUSED on reboot, got {st_data_d}"
        assert st_data_d["task_status"] == "PAUSED", f"Expected task PAUSED on reboot, got {st_data_d}"

        # Baseline audit should NOT have run
        status_code, alerts_reboot = make_request("GET", f"{base_url_d}/api/v1/alerts", headers=analyst_headers)
        assert status_code == 200
        assert len(alerts_reboot) == 0, f"Baseline scan executed on reboot despite PAUSED state! Found {len(alerts_reboot)} alerts."
        print("  [+] TEST D PASSED: Monitoring remained PAUSED across reboot without baseline audit.")

        # ---------------------------------------------------------
        # TEST E: Manual Host Audit During Paused State
        # ---------------------------------------------------------
        print("\n[TEST E] Executing manual host audit while monitoring is paused...")
        status_code, audit_data = make_request("POST", f"{base_url_d}/api/v1/host/audit", headers=analyst_headers)
        assert status_code == 200, f"Manual audit failed: {audit_data}"

        # Monitoring MUST remain PAUSED
        status_code, st_data_e = make_request("GET", f"{base_url_d}/api/v1/stream/status")
        assert status_code == 200
        assert st_data_e["host_monitoring_active"] is False
        assert st_data_e["task_status"] == "PAUSED"
        print("  [+] TEST E PASSED: Manual audit executed successfully while monitoring state stayed PAUSED.")

        # ---------------------------------------------------------
        # TEST F: Resume Host Monitoring
        # ---------------------------------------------------------
        print("\n[TEST F] Resuming host monitoring via API...")
        status_code, resume_data = make_request("POST", f"{base_url_d}/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)
        assert status_code == 200, f"Resume failed: {resume_data}"
        assert resume_data["host_monitoring_active"] is True
        assert resume_data["task_status"] == "RUNNING"

        with open(pref_file, "r", encoding="utf-8") as f:
            disk_prefs_f = json.load(f)
        assert disk_prefs_f["host_monitoring_active"] is True
        print("  [+] TEST F PASSED: Host monitoring resumed to ACTIVE and task RUNNING.")

    finally:
        print("  [*] Terminating Process D...")
        proc_d.terminate()
        try:
            proc_d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_d.kill()

    # ---------------------------------------------------------
    # TEST G: Process Restart; Verify ACTIVE Restored
    # ---------------------------------------------------------
    port_g = find_free_port()
    print(f"\n[TEST G] Rebooting process on port {port_g} to verify ACTIVE restored...")
    run_cmd_g = cmd_prefix + ["--port", str(port_g), "--no-browser"]
    proc_g = subprocess.Popen(run_cmd_g, env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        base_url_g = f"http://127.0.0.1:{port_g}"
        if not wait_for_ready(base_url_g, max_wait=30.0):
            stdout, stderr = proc_g.communicate(timeout=5)
            print(f"Server G failed to start:\nSTDOUT:\n{stdout.decode()}\nSTDERR:\n{stderr.decode()}")
            raise RuntimeError("Test G Failed: Server G readiness check timed out.")

        status_code, st_data_g = make_request("GET", f"{base_url_g}/api/v1/stream/status")
        assert status_code == 200
        assert st_data_g["host_monitoring_active"] is True, f"Expected ACTIVE on reboot, got {st_data_g}"
        print("  [+] TEST G PASSED: ACTIVE monitoring verified across restart.")
    finally:
        print("  [*] Terminating Process G...")
        proc_g.terminate()
        try:
            proc_g.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_g.kill()

    print("\n" + "=" * 70)
    print("ALL TESTS (A through G) PASSED SUCCESSFULLY!")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="Test SOC Alert Analyzer process lifecycle integration across restarts.")
    parser.add_argument("--exe", type=str, default=None, help="Path to standalone compiled executable (e.g. dist/SOC_Alert_Analyzer.exe)")
    args = parser.parse_args()

    temp_dir = tempfile.mkdtemp(prefix="soc_test_data_")
    try:
        if args.exe:
            if not os.path.exists(args.exe):
                print(f"[!] Executable not found at {args.exe}")
                sys.exit(1)
            cmd_prefix = [os.path.abspath(args.exe)]
        else:
            cmd_prefix = [sys.executable, "launcher.py"]

        run_lifecycle_integration_tests(cmd_prefix, temp_dir)
    finally:
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

if __name__ == "__main__":
    main()
