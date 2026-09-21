import os
import sys
import time
import socket
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
from app.main import app

def find_available_port(start_port: int = 8000) -> int:
    """Find an available port starting from start_port."""
    port = start_port
    while port < start_port + 100:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return start_port

def open_browser_delayed(url: str, delay: float = 1.5):
    """Wait for server to boot then open default web browser."""
    time.sleep(delay)
    print(f"[+] Opening web browser at {url} ...")
    webbrowser.open(url)

def print_banner(url: str):
    banner = f"""
================================================================
   ____   ___   ____     _    _           _       
  / ___| / _ \ / ___|   / \  | | ___ _ __| |_ ___ 
  \___ \| | | | |      / _ \ | |/ _ \ '__| __/ __|
   ___) | |_| | |___  / ___ \| |  __/ |  | |_\__ \\
  |____/ \___/ \____|/_/   \_\_|\___|_|   \__|___/
                     
  Real-World Defensive Security Operations Center & Alert Analyzer
================================================================
  [+] Web Dashboard  : {url}
  [+] Host Sensor    : Native EDR (Windows / Linux / macOS)
  [+] Threat Feed    : Real-Time Host Telemetry Active
  [+] Multi-Source   : Windows Event Logs, Web Access, Firewall,
                       Wazuh, Suricata, Linux Auth, Generic CSV/JSON
  [+] Framework      : MITRE ATT&CK Enterprise Mapping
================================================================
  INFO: Running in standalone real-world mode (no SIEM required).
  Keep this window open while using the application.
  Press Ctrl+C to terminate the server.
================================================================
"""
    print(banner)

def main():
    multiprocessing.freeze_support()
    port = find_available_port(8000)
    url = f"http://127.0.0.1:{port}"

    print_banner(url)

    # Launch browser automatically in background thread
    threading.Thread(target=open_browser_delayed, args=(url,), daemon=True).start()

    # Run Uvicorn server with app instance
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=port,
        log_level="info"
    )

if __name__ == "__main__":
    main()
