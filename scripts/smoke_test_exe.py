"""Smoke test the compiled Windows executable by launching it and querying endpoints."""
import subprocess
import time
import json
import urllib.request
import sys

def test_exe():
    print("Launching dist/SOC_Alert_Analyzer.exe on port 8099...")
    proc = subprocess.Popen(
        ["dist\\SOC_Alert_Analyzer.exe", "--port", "8099", "--no-browser"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    print(f"Launched with PID: {proc.pid}")
    
    # Wait for startup with polling up to 30s
    connected = False
    start_time = time.time()
    while time.time() - start_time < 30:
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            print(f"Process exited early with return code {proc.returncode}!")
            print(f"STDOUT:\n{stdout}")
            print(f"STDERR:\n{stderr}")
            sys.exit(1)
        try:
            req = urllib.request.Request("http://127.0.0.1:8099/api/v1/stream/status")
            with urllib.request.urlopen(req, timeout=2) as response:
                if response.getcode() == 200:
                    connected = True
                    body = response.read().decode("utf-8")
                    print(f"Server responded after {time.time() - start_time:.1f}s!")
                    print(f"/api/v1/stream/status: {body}")
                    data = json.loads(body)
                    assert "simulation_active" in data
                    assert "host_monitoring_active" in data
                    break
        except Exception:
            time.sleep(1)

    if not connected:
        print("Failed to connect within 30 seconds.")
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=5)
        print(f"STDOUT:\n{stdout}")
        print(f"STDERR:\n{stderr}")
        sys.exit(1)

    try:
        # Check /api/v1/auth/me (expected 200 in dev or default mode)
        req_auth = urllib.request.Request("http://127.0.0.1:8099/api/v1/auth/me")
        with urllib.request.urlopen(req_auth, timeout=5) as response:
            status_code = response.getcode()
            body = response.read().decode("utf-8")
            print(f"/api/v1/auth/me: HTTP {status_code} -> {body}")
            assert status_code == 200

        # Check root page
        req_root = urllib.request.Request("http://127.0.0.1:8099/")
        with urllib.request.urlopen(req_root, timeout=5) as response:
            status_code = response.getcode()
            print(f"Root URL (/): HTTP {status_code}")
            assert status_code == 200

        print("\n=== EXE SMOKE TEST COMPLETED SUCCESSFULLY! ===")
    finally:
        print("Terminating process...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("Process terminated cleanly.")

if __name__ == "__main__":
    test_exe()
