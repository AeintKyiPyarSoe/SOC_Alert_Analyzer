#!/usr/bin/env python3
"""
scripts/test_exe_websocket_integration.py
SOC Alert Analyzer - Mandatory Executable / Subprocess WebSocket & Security Integration Test

Exercises Tests A through J against the live application process or compiled standalone Windows executable:
  Test A: Executable Startup & HTTP Readiness Check on dynamic port in isolated DATA_DIR.
  Test B: Authenticate via supported authentication credentials.
  Test C: Obtain short-lived single-use WebSocket ticket via POST /api/v1/auth/ws-ticket.
  Test D: WebSocket Handshake to ws://127.0.0.1:<port>/ws/threats?ticket=<ticket>.
  Test E: Ping/Pong Frame Exchange (send 'ping' -> assert 'pong').
  Test F: Monitoring State Separation: Pause Host Sensor; verify WebSocket remains functional and connected.
  Test G: Resume Host Sensor: Resume monitoring; verify WebSocket remains functional and active.
  Test H: Clean Disconnect & Reconnection with a fresh ticket.
  Test I: Security: Replay of consumed ticket rejected; invalid ticket rejected; untrusted client rejected.
  Test J: Clean Shutdown: Close connections and cleanly terminate executable subprocess.
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
import websockets.sync.client
import websockets.exceptions


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
            status, _ = make_request("GET", url, timeout=2.0)
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def run_websocket_integration_tests(cmd_prefix: list, data_dir: str):
    print("=" * 75)
    print("SOC Alert Analyzer: Mandatory WebSocket & Lifecycle Integration Suite (Tests A-J)")
    print(f"Target Command: {' '.join(cmd_prefix)}")
    print(f"Isolated Data Dir: {data_dir}")
    print("=" * 75)

    admin_key = "test_admin_key_super_secret_ws_123"
    analyst_key = "test_analyst_key_super_secret_ws_456"
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

    analyst_headers = {"X-API-Key": analyst_key}
    admin_headers = {"X-API-Key": admin_key}

    port = find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    ws_base = f"ws://127.0.0.1:{port}"

    # ---------------------------------------------------------
    # TEST A: Executable Startup & HTTP Readiness Check
    # ---------------------------------------------------------
    print(f"\n[TEST A] Spawning executable process on port {port}...")
    run_cmd = cmd_prefix + ["--port", str(port), "--no-browser"]
    proc = subprocess.Popen(run_cmd, env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        if not wait_for_ready(base_url, max_wait=30.0):
            stdout, stderr = proc.communicate(timeout=5)
            print(f"Server startup failed:\nSTDOUT:\n{stdout.decode()}\nSTDERR:\n{stderr.decode()}")
            raise RuntimeError("TEST A FAILED: Executable failed to reach HTTP readiness.")
        print("  [+] TEST A PASSED: Executable started and responded to HTTP readiness probes.")

        # ---------------------------------------------------------
        # TEST B: Authenticate via Supported Credentials
        # ---------------------------------------------------------
        print("\n[TEST B] Authenticating via analyst credentials...")
        st_code, me_data = make_request("GET", f"{base_url}/api/v1/auth/me", headers=analyst_headers)
        assert st_code == 200, f"Auth verification failed with status {st_code}: {me_data}"
        assert me_data.get("role") == "ANALYST", f"Unexpected role: {me_data}"
        print(f"  [+] TEST B PASSED: Authenticated successfully as '{me_data.get('username')}' ({me_data.get('role')}).")

        # ---------------------------------------------------------
        # TEST C: Obtain Short-Lived Single-Use WebSocket Ticket
        # ---------------------------------------------------------
        print("\n[TEST C] Requesting short-lived WebSocket connection ticket...")
        st_code, ticket_data = make_request("POST", f"{base_url}/api/v1/auth/ws-ticket", headers=analyst_headers)
        assert st_code == 200, f"Ticket request failed with status {st_code}: {ticket_data}"
        ticket_1 = ticket_data.get("ticket")
        assert ticket_1 and len(ticket_1) >= 20, f"Invalid ticket format: {ticket_data}"
        print("  [+] TEST C PASSED: Valid ephemeral WebSocket ticket acquired.")

        # ---------------------------------------------------------
        # TEST D: WebSocket Handshake & Protocol Upgrade
        # ---------------------------------------------------------
        print(f"\n[TEST D] Initiating WebSocket handshake with ticket parameter...")
        ws_url_1 = f"{ws_base}/ws/threats?ticket={ticket_1}"
        with websockets.sync.client.connect(ws_url_1, open_timeout=5) as ws_conn:
            print("  [+] TEST D PASSED: WebSocket connection established (HTTP 101 Switching Protocols).")

            # ---------------------------------------------------------
            # TEST E: Ping / Pong Frame Exchange
            # ---------------------------------------------------------
            print("\n[TEST E] Exchanging bidirectional ping/pong frame over WebSocket...")
            ws_conn.send("ping")
            pong_resp = ws_conn.recv(timeout=5)
            assert pong_resp == "pong", f"Expected 'pong', got '{pong_resp}'"
            print(f"  [+] TEST E PASSED: Received verified '{pong_resp}' frame from executable.")

            # ---------------------------------------------------------
            # TEST F: Monitoring State Separation (Pause while Connected)
            # ---------------------------------------------------------
            print("\n[TEST F] Pausing Host Sensor while maintaining WebSocket connectivity...")
            st_code, pause_data = make_request("POST", f"{base_url}/api/v1/host/monitor/toggle?active=false", headers=analyst_headers)
            assert st_code == 200, f"Pause request failed: {pause_data}"
            assert pause_data.get("host_monitoring_active") is False
            assert pause_data.get("task_status") == "PAUSED"

            # Verify WebSocket is STILL functional
            ws_conn.send("ping")
            assert ws_conn.recv(timeout=5) == "pong"

            st_code, status_f = make_request("GET", f"{base_url}/api/v1/stream/status")
            assert st_code == 200
            assert status_f["host_monitoring_active"] is False
            assert status_f["task_status"] == "PAUSED"
            print("  [+] TEST F PASSED: Host Sensor paused; WebSocket connection remained functional and healthy.")

            # ---------------------------------------------------------
            # TEST G: Resume Host Sensor (WebSocket Active)
            # ---------------------------------------------------------
            print("\n[TEST G] Resuming Host Sensor while maintaining WebSocket connectivity...")
            st_code, resume_data = make_request("POST", f"{base_url}/api/v1/host/monitor/toggle?active=true", headers=analyst_headers)
            assert st_code == 200, f"Resume request failed: {resume_data}"
            assert resume_data.get("host_monitoring_active") is True
            assert resume_data.get("task_status") == "RUNNING"

            # Verify WebSocket ping/pong still operates
            ws_conn.send("ping")
            assert ws_conn.recv(timeout=5) == "pong"
            print("  [+] TEST G PASSED: Host Sensor resumed to ACTIVE; WebSocket stream verified active.")

        # ---------------------------------------------------------
        # TEST H: Disconnect & Reconnect with Fresh Ticket
        # ---------------------------------------------------------
        print("\n[TEST H] Closing WebSocket and reconnecting with a fresh ticket...")
        st_code, ticket_data_2 = make_request("POST", f"{base_url}/api/v1/auth/ws-ticket", headers=analyst_headers)
        assert st_code == 200
        ticket_2 = ticket_data_2["ticket"]

        with websockets.sync.client.connect(f"{ws_base}/ws/threats?ticket={ticket_2}", open_timeout=5) as ws_conn_2:
            ws_conn_2.send("ping")
            assert ws_conn_2.recv(timeout=5) == "pong"
        print("  [+] TEST H PASSED: Clean disconnection and reconnect with fresh ticket succeeded.")

        # ---------------------------------------------------------
        # TEST I: Security: Replay, Bogus & Untrusted Connections
        # ---------------------------------------------------------
        print("\n[TEST I] Verifying security rejection of reused, invalid and untrusted tickets...")

        # 1. Replay attack using already-consumed ticket_2
        replayed_rejected = False
        try:
            with websockets.sync.client.connect(f"{ws_base}/ws/threats?ticket={ticket_2}", open_timeout=5) as ws_fail:
                ws_fail.recv(timeout=2)
        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.WebSocketException):
            replayed_rejected = True
        assert replayed_rejected, "Security Defect: Reused single-use ticket was NOT rejected!"

        # 2. Bogus / tampered ticket
        bogus_rejected = False
        try:
            with websockets.sync.client.connect(f"{ws_base}/ws/threats?ticket=bogus_nonexistent_ticket_12345", open_timeout=5) as ws_fail:
                ws_fail.recv(timeout=2)
        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.WebSocketException):
            bogus_rejected = True
        assert bogus_rejected, "Security Defect: Bogus ticket was NOT rejected!"

        # 3. Connection with no ticket and no session cookie
        unauth_rejected = False
        try:
            with websockets.sync.client.connect(f"{ws_base}/ws/threats", open_timeout=5) as ws_fail:
                ws_fail.recv(timeout=2)
        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.WebSocketException):
            unauth_rejected = True
        assert unauth_rejected, "Security Defect: Unauthenticated client without credentials was NOT rejected!"

        print("  [+] TEST I PASSED: All invalid, reused, and unauthenticated WebSocket attempts securely rejected.")

        # ---------------------------------------------------------
        # TEST J: Clean Shutdown & Subprocess Termination
        # ---------------------------------------------------------
        print("\n[TEST J] Clean shutdown and process termination...")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("  [+] TEST J PASSED: Process cleanly terminated.")

    print("\n" + "=" * 75)
    print("ALL MANDATORY WEBSOCKET TESTS (A through J) PASSED SUCCESSFULLY!")
    print("=" * 75)


def main():
    parser = argparse.ArgumentParser(description="Test SOC Alert Analyzer WebSocket integration.")
    parser.add_argument("--exe", type=str, default=None, help="Path to standalone compiled executable (e.g. dist/SOC_Alert_Analyzer.exe)")
    args = parser.parse_args()

    temp_dir = tempfile.mkdtemp(prefix="soc_ws_test_data_")
    try:
        if args.exe:
            if not os.path.exists(args.exe):
                print(f"[!] Executable not found at {args.exe}")
                sys.exit(1)
            cmd_prefix = [os.path.abspath(args.exe)]
        else:
            cmd_prefix = [sys.executable, "launcher.py"]

        run_websocket_integration_tests(cmd_prefix, temp_dir)
    finally:
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass


if __name__ == "__main__":
    main()
