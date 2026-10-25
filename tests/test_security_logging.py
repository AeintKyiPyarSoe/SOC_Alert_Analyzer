"""
tests/test_security_logging.py
Security Regression Tests: Credential & WebSocket Ticket Redaction in Server Access Logs

Verifies that:
  1. Ephemeral WebSocket tickets (?ticket=wst_...) are strictly redacted from access logs.
  2. Useful diagnostic telemetry (client IP, endpoint path, status codes, duration) remains intact.
  3. Rejected WebSocket connections do not leak tickets or tokens.
  4. HTTP Authorization headers, Bearer tokens, and session cookies are sanitized.
  5. Reconnection attempts with fresh tickets never expose tokens.
  6. Direct and formatted LogRecord mutations strictly redact credentials.
"""

import io
import logging
import pytest
from starlette.testclient import TestClient
from app.main import app
from app.security.session import session_manager
from app.security.auth import Role
from app.security.logging_filter import (
    SensitiveDataRedactionFilter,
    redact_sensitive_string,
    setup_security_logging,
    get_secure_uvicorn_log_config,
)


@pytest.fixture(autouse=True)
def ensure_logging_configured():
    setup_security_logging()


def test_redact_sensitive_string_unit():
    """Unit test for string redaction utility across diverse parameter formats."""
    # 1. WebSocket ticket parameter
    raw_ws = '127.0.0.1:50000 - "WebSocket /ws/threats?ticket=wst_98a7bc65fe43210fedcba98765432101" [accepted]'
    redacted_ws = redact_sensitive_string(raw_ws)
    assert "wst_98a7bc65fe43210fedcba98765432101" not in redacted_ws
    assert 'WebSocket /ws/threats?ticket=[REDACTED]' in redacted_ws
    assert "[accepted]" in redacted_ws
    assert "127.0.0.1:50000" in redacted_ws

    # 2. Multiple parameters with ticket
    raw_multi = '/ws/threats?client=web&ticket=wst_abc1234567890abcdef1234567890&debug=true'
    redacted_multi = redact_sensitive_string(raw_multi)
    assert "wst_abc1234567890abcdef1234567890" not in redacted_multi
    assert "client=web" in redacted_multi
    assert "ticket=[REDACTED]" in redacted_multi
    assert "debug=true" in redacted_multi

    # 3. API key and token parameters
    raw_api = 'GET /api/v1/alerts?api_key=soc_adm_secretkey12345&token=tok_998877 HTTP/1.1'
    redacted_api = redact_sensitive_string(raw_api)
    assert "soc_adm_secretkey12345" not in redacted_api
    assert "tok_998877" not in redacted_api
    assert "api_key=[REDACTED]" in redacted_api
    assert "token=[REDACTED]" in redacted_api

    # 4. Bearer token
    raw_bearer = 'Header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID'
    redacted_bearer = redact_sensitive_string(raw_bearer)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted_bearer
    assert "Bearer [REDACTED]" in redacted_bearer

    # 5. Session cookie
    raw_cookie = 'Cookie: soc_session=ses_a1b2c3d4e5f67890abcdef12345678; Path=/'
    redacted_cookie = redact_sensitive_string(raw_cookie)
    assert "ses_a1b2c3d4e5f67890abcdef12345678" not in redacted_cookie
    assert "soc_session=[REDACTED]" in redacted_cookie


def test_logging_filter_record_arguments_redaction():
    """Verify that SensitiveDataRedactionFilter mutates record.args and record.msg in-place."""
    filt = SensitiveDataRedactionFilter()

    # LogRecord with tuple args (standard uvicorn format)
    record = logging.LogRecord(
        name="uvicorn.error",
        level=logging.INFO,
        pathname="uvicorn/protocols/websockets.py",
        lineno=100,
        msg='%s - "WebSocket %s" [accepted]',
        args=("127.0.0.1:61234", "/ws/threats?ticket=wst_secret_ticket_12345678901234567890"),
        exc_info=None
    )

    filt.filter(record)
    formatted = record.getMessage()

    assert "wst_secret_ticket_12345678901234567890" not in formatted
    assert "ticket=[REDACTED]" in formatted
    assert "127.0.0.1:61234" in formatted
    assert "[accepted]" in formatted


def test_websocket_accepted_handshake_log_redaction():
    """Capture real uvicorn log stream during authenticated WebSocket handshake and verify redaction."""
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.INFO)
    handler.addFilter(SensitiveDataRedactionFilter())

    target_loggers = [
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
    ]
    for l in target_loggers:
        l.addHandler(handler)

    try:
        # Create user session and issue a short-lived ticket
        token, _ = session_manager.create_session("analyst_test", Role.ANALYST)
        ticket = session_manager.create_ws_ticket("analyst_test", Role.ANALYST)
        assert ticket.startswith("wst_")

        client = TestClient(app)
        # Establish legitimate WebSocket connection with ticket
        with client.websocket_connect(f"/ws/threats?ticket={ticket}") as ws:
            ws.send_text("ping")
            resp = ws.receive_text()
            assert resp == "pong"

        # Check captured logs
        log_output = log_capture.getvalue()
        # Verify complete raw ticket never leaked into log output
        assert ticket not in log_output, f"Raw WebSocket ticket leaked in logs: {log_output}"

    finally:
        for l in target_loggers:
            l.removeHandler(handler)


def test_websocket_rejected_connection_log_redaction():
    """Capture logs during rejected WebSocket attempt and verify invalid ticket is not leaked."""
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.INFO)
    handler.addFilter(SensitiveDataRedactionFilter())

    target_loggers = [
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
    ]
    for l in target_loggers:
        l.addHandler(handler)

    try:
        invalid_ticket = "wst_INVALID_EXPIRED_MALICIOUS_TICKET_998877665544332211"
        client = TestClient(app)

        # Attempt WebSocket connection with invalid ticket; expect policy violation 1008
        try:
            with client.websocket_connect(f"/ws/threats?ticket={invalid_ticket}"):
                pass
        except Exception:
            pass  # Expected disconnect/rejection

        log_output = log_capture.getvalue()
        assert invalid_ticket not in log_output, f"Invalid ticket leaked in logs: {log_output}"

    finally:
        for l in target_loggers:
            l.removeHandler(handler)


def test_secure_uvicorn_log_config_structure():
    """Verify get_secure_uvicorn_log_config includes redaction filters on all required handlers."""
    cfg = get_secure_uvicorn_log_config("info")
    assert "filters" in cfg
    assert "security_redaction" in cfg["filters"]
    assert cfg["filters"]["security_redaction"]["()"] == "app.security.logging_filter.SensitiveDataRedactionFilter"

    assert "security_redaction" in cfg["handlers"]["access"]["filters"]
    assert "security_redaction" in cfg["handlers"]["default"]["filters"]
    assert "security_redaction" in cfg["loggers"]["uvicorn.access"]["filters"]
    assert "security_redaction" in cfg["loggers"]["uvicorn.error"]["filters"]


def test_real_uvicorn_process_ticket_redaction():
    """Verify that a live Uvicorn server subprocess strictly redacts WebSocket tickets in its stdout."""
    import os
    import time
    import socket
    import subprocess
    import sys
    import tempfile
    import urllib.request
    import json
    import websockets.sync.client

    def _find_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    port = _find_free_port()
    temp_dir = tempfile.mkdtemp(prefix="soc_uvicorn_log_test_")
    env = os.environ.copy()
    env["DATA_DIR"] = temp_dir
    env["NO_BROWSER"] = "1"
    admin_key = "admin_uvicorn_test_key_1234567890"
    analyst_key = "analyst_uvicorn_test_key_1234567890"
    secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    env["ADMIN_API_KEY"] = admin_key
    env["ANALYST_API_KEY"] = analyst_key
    env["SECRET_KEY"] = secret_key
    env["ENVIRONMENT"] = "development"

    cmd = [sys.executable, "launcher.py", "--port", str(port), "--no-browser"]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        # Wait for server readiness
        start_wait = time.time()
        ready = False
        while time.time() - start_wait < 15:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/stream/status", timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.2)
        assert ready, "Server failed to start within timeout"

        # Obtain WebSocket ticket
        ticket_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/v1/auth/ws-ticket",
            headers={"X-API-Key": analyst_key},
            method="POST"
        )
        with urllib.request.urlopen(ticket_req, timeout=3.0) as resp:
            ticket_data = json.loads(resp.read().decode())
            ticket = ticket_data["ticket"]
            assert ticket.startswith("wst_")

        # Connect over WebSocket with ticket
        with websockets.sync.client.connect(f"ws://127.0.0.1:{port}/ws/threats?ticket={ticket}") as ws:
            ws.send("ping")
            assert ws.recv() == "pong"

    finally:
        proc.terminate()
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Assert raw ticket never appears in Uvicorn output
    assert ticket not in stdout, f"Raw WebSocket ticket leaked into live Uvicorn output: {stdout}"
    # Assert redacted ticket parameter appears in stdout
    assert "ticket=[REDACTED]" in stdout or "ticket=wst_[REDACTED]" in stdout, (
        f"Expected redacted ticket parameter in Uvicorn log output, got:\n{stdout}"
    )
