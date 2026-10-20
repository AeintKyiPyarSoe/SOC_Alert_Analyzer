import os
import sys
import time
import socket
import argparse
import webbrowser
import threading
import multiprocessing
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add base directory to sys.path
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).resolve().parent

sys.path.insert(0, str(BASE_DIR))

import uvicorn
from app.config import settings
from app.main import app

def is_port_available(host: str, port: int) -> bool:
    """Checks whether a TCP port is open and available for binding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        # 127.0.0.1 check for local connections
        check_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        return s.connect_ex((check_host, port)) != 0

def find_available_port(host: str, start_port: int = 8000, max_attempts: int = 100) -> int:
    """Finds an available TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(host, port):
            return port
    return start_port

def wait_for_server_and_open_browser(host: str, port: int, max_wait: float = 10.0):
    """
    Polls the server until it is accepting TCP connections,
    then launches the system's default web browser.
    """
    check_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{check_host}:{port}"
    start_time = time.time()

    while time.time() - start_time < max_wait:
        if not is_port_available(host, port):
            # Port is now bound and listening
            time.sleep(0.3)
            print(f"[+] Server confirmed active. Opening web browser at {url} ...")
            try:
                webbrowser.open(url)
            except Exception as e:
                print(f"[!] Note: Automatic browser launch failed: {e}. Please open {url} manually.")
            return
        time.sleep(0.2)

    print(f"[!] Server readiness check timed out. Please navigate to {url} manually.")

def print_banner(host: str, port: int):
    check_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{check_host}:{port}"
    docs_url = f"{url}/docs"

    db_type = "PostgreSQL" if "postgresql" in settings.DATABASE_URL.lower() else "SQLite (Local File)"
    auth_status = "ENABLED (RBAC)" if settings.AUTH_ENABLED else "DISABLED (Dev Mode)"

    creds_notice = ""
    if getattr(settings, "FIRST_RUN_GENERATED", False):
        creds_notice = rf"""
================================================================
  [!] FIRST-RUN LOCAL CREDENTIALS GENERATED:
  [!] Admin API Key   : {settings.ADMIN_API_KEY}
  [!] Analyst API Key : {settings.ANALYST_API_KEY}
  Credentials securely stored with restricted permissions in:
  {settings.DATA_DIR / ".auth_credentials"}
================================================================
"""

    banner = rf"""
================================================================
   ____   ___   ____     _    _           _       
  / ___| / _ \ / ___|   / \  | | ___ _ __| |_ ___ 
  \___ \| | | | |      / _ \ | |/ _ \ '__| __/ __|
   ___) | |_| | |___  / ___ \| |  __/ |  | |_\__ \\
  |____/ \___/ \____|/_/   \_\_|\___|_|   \__|___/
                     
  Defensive Security Operations Center & Real-Time EDR Analyzer
  Version: {settings.VERSION}
================================================================
  [+] Web Dashboard  : {url}
  [+] API Swagger UI : {docs_url}
  [+] Data Directory : {settings.DATA_DIR}
  [+] Database Engine: {db_type}
  [+] Authentication : {auth_status}
  [+] Host Sensor    : Native EDR-Lite (Process Trees, Sockets, LOLBins)
  [+] MITRE ATT&CK   : Enterprise v14 Mappings Active
================================================================{creds_notice}
  INFO: Running in standalone defensive mode on local loopback interface.
  Press Ctrl+C to terminate the server.
================================================================
"""
    print(banner)

def parse_arguments():
    """Parses command-line arguments for configurable execution."""
    parser = argparse.ArgumentParser(
        description="SOC Alert Analyzer — Defensive Security Operations Center Launcher"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.getenv("HOST", "127.0.0.1"),
        help="Host interface to bind the web server (default: 127.0.0.1 or env HOST)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8000")),
        help="Port to bind the web server (default: 8000 or env PORT)"
    )
    parser.add_argument(
        "--strict-port",
        action="store_true",
        help="Fail if the designated port is already occupied instead of searching next available"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Disable automatic launch of the web browser (useful for headless, Docker, or CI)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable Uvicorn auto-reload for local code development"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Uvicorn server log level (default: info)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    return parser.parse_args()

def main():
    multiprocessing.freeze_support()
    args = parse_arguments()

    if args.workers > 1:
        print("[!] Error: Multi-worker execution (> 1 worker) is unsupported with in-memory session and WebSocket state.")
        print("[!] Multi-process workers cause split-brain session state and authentication failures.")
        print("[!] Please run with --workers 1 or deploy with a centralized session store.")
        sys.exit(1)

    host = args.host
    requested_port = args.port

    if args.strict_port:
        if not is_port_available(host, requested_port):
            print(f"[!] Error: Port {requested_port} is already occupied on {host}.")
            sys.exit(1)
        port = requested_port
    else:
        port = find_available_port(host, start_port=requested_port)
        if port != requested_port:
            print(f"[*] Port {requested_port} was occupied; dynamically allocated available port {port}.")

    print_banner(host, port)

    # Launch browser only after verified server readiness (unless suppressed)
    if not args.no_browser and not os.getenv("NO_BROWSER"):
        browser_thread = threading.Thread(
            target=wait_for_server_and_open_browser,
            args=(host, port),
            daemon=True
        )
        browser_thread.start()

    try:
        if args.reload:
            uvicorn.run(
                "app.main:app",
                host=host,
                port=port,
                log_level=args.log_level,
                reload=True
            )
        else:
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level=args.log_level,
                workers=args.workers
            )
    except KeyboardInterrupt:
        print("\n[!] Received shutdown signal (Ctrl+C). Terminating SOC Alert Analyzer gracefully...")
    except Exception as e:
        print(f"\n[!] Server error: {e}")
        sys.exit(1)
    finally:
        print("[+] SOC Alert Analyzer stopped.")

if __name__ == "__main__":
    main()
