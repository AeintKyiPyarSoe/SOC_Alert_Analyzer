import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from app.security.auth import is_local_client, get_current_user, authenticate_websocket, Role
from app.config import Settings, settings
from app.main import app

def test_is_local_client_unit():
    # Valid loopback addresses
    assert is_local_client("127.0.0.1") is True
    assert is_local_client("127.0.0.2") is True
    assert is_local_client("::1") is True
    assert is_local_client("localhost") is True
    assert is_local_client("testclient") is True

    # Untrusted / Remote network IPs
    assert is_local_client("192.168.1.100") is False
    assert is_local_client("10.0.0.1") is False
    assert is_local_client("172.16.0.5") is False
    assert is_local_client("203.0.113.1") is False
    assert is_local_client("8.8.8.8") is False
    assert is_local_client("") is False
    assert is_local_client(None) is False
    assert is_local_client("evil.com") is False

def test_auth_disabled_mode_rejects_non_local_client():
    """Verify that when AUTH_ENABLED=False, external/remote IPs are rejected with 403."""
    mock_request = MagicMock(spec=Request)
    mock_request.client.host = "192.168.1.50"
    mock_request.headers = {}

    with patch.object(settings, "AUTH_ENABLED", False):
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(mock_request, api_key_header=None, bearer_auth=None)
        assert exc_info.value.status_code == 403
        assert "strictly restricted to verified local loopback" in exc_info.value.detail

def test_auth_disabled_mode_does_not_trust_forwarded_headers():
    """Verify that forged X-Forwarded-For or Host headers do not fool the local check."""
    mock_request = MagicMock(spec=Request)
    # The actual network socket is remote
    mock_request.client.host = "203.0.113.55"
    # Forged headers attempting to spoof loopback
    mock_request.headers = {
        "x-forwarded-for": "127.0.0.1",
        "host": "localhost:8000"
    }

    with patch.object(settings, "AUTH_ENABLED", False):
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(mock_request, api_key_header=None, bearer_auth=None)
        assert exc_info.value.status_code == 403

def test_auth_disabled_mode_allows_verified_local():
    """Verify that genuine local connections succeed in auth-disabled mode."""
    mock_request = MagicMock(spec=Request)
    mock_request.client.host = "127.0.0.1"
    mock_request.headers = {}

    with patch.object(settings, "AUTH_ENABLED", False):
        user = get_current_user(mock_request, api_key_header=None, bearer_auth=None)
        assert user.username == "admin_local"
        assert user.role == Role.ADMIN
        assert user.auth_type == "local"

def test_auth_disabled_startup_rejected_in_production():
    """Verify that setting AUTH_ENABLED=False in production raises RuntimeError."""
    with patch.dict("os.environ", {
        "ENVIRONMENT": "production",
        "AUTH_ENABLED": "false",
        "SECRET_KEY": "a" * 32,
        "ADMIN_API_KEY": "secure_admin_key_12345"
    }):
        with pytest.raises(RuntimeError) as exc_info:
            Settings()
        assert "AUTH_ENABLED cannot be disabled" in str(exc_info.value)

def test_auth_disabled_startup_requires_explicit_opt_in_dev():
    """Verify that disabling auth in development requires ALLOW_INSECURE_AUTH_DISABLED=true."""
    with patch.dict("os.environ", {
        "ENVIRONMENT": "development",
        "AUTH_ENABLED": "false",
        "ALLOW_INSECURE_AUTH_DISABLED": "false"
    }):
        with pytest.raises(RuntimeError) as exc_info:
            Settings()
        assert "ALLOW_INSECURE_AUTH_DISABLED=true" in str(exc_info.value)
