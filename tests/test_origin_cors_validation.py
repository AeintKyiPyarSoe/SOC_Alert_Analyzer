import pytest
from app.security.auth import is_allowed_origin
from app.config import Settings

def test_origin_validation_positive_allowed():
    """Verify that legitimate desktop launcher and default loopback origins are accepted."""
    assert is_allowed_origin("http://127.0.0.1:8000") is True
    assert is_allowed_origin("http://localhost:8000") is True
    assert is_allowed_origin("http://127.0.0.1:8080") is True
    assert is_allowed_origin("http://localhost:8080") is True
    assert is_allowed_origin("http://localhost:8055") is True  # launcher dynamic range [8000..8099]
    assert is_allowed_origin(None) is True  # RFC 6455 native clients without Origin header

def test_origin_validation_negative_untrusted_domains():
    """Verify that foreign cross-origin domains are rejected."""
    assert is_allowed_origin("https://evil-attacker.com") is False
    assert is_allowed_origin("http://attacker.com:8000") is False
    assert is_allowed_origin("https://subdomain.localhost.evil.com") is False
    assert is_allowed_origin("http://localhost.evil.com:8000") is False
    assert is_allowed_origin("http://192.168.1.100:8000") is False
    assert is_allowed_origin("http://10.0.0.1:8000") is False

def test_origin_validation_negative_arbitrary_localhost_ports():
    """Verify that arbitrary localhost ports outside launcher range are rejected."""
    assert is_allowed_origin("http://localhost:3000") is False
    assert is_allowed_origin("http://localhost:5000") is False
    assert is_allowed_origin("http://127.0.0.1:9000") is False
    assert is_allowed_origin("http://127.0.0.1:9999") is False
    assert is_allowed_origin("http://localhost:1337") is False

def test_origin_validation_negative_malformed_origins():
    """Verify that malformed origins with userinfo, paths, queries, or invalid schemes are rejected."""
    assert is_allowed_origin("") is False
    assert is_allowed_origin("null") is False
    assert is_allowed_origin("javascript:alert(1)") is False
    assert is_allowed_origin("file:///etc/passwd") is False
    assert is_allowed_origin("ftp://localhost:8000") is False
    assert is_allowed_origin("ws://localhost:8000") is False
    assert is_allowed_origin("http://admin:secret@localhost:8000") is False
    assert is_allowed_origin("http://localhost:8000/api/v1/auth") is False
    assert is_allowed_origin("http://localhost:8000?query=param") is False
    assert is_allowed_origin("http://localhost:8000#fragment") is False

def test_production_cors_wildcard_prohibited():
    """Verify that wildcard '*' in ALLOWED_ORIGINS raises an error in production."""
    with pytest.raises(RuntimeError) as exc_info:
        from unittest.mock import patch
        with patch.dict("os.environ", {
            "ENVIRONMENT": "production",
            "SECRET_KEY": "a" * 32,
            "ADMIN_API_KEY": "admin_key_production_123456",
            "ALLOWED_ORIGINS": "*"
        }):
            Settings()
    assert "Wildcard '*' in ALLOWED_ORIGINS is prohibited in production" in str(exc_info.value)
