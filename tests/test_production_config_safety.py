import os
import pytest
from app.config import Settings


def test_production_fails_when_auth_disabled(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_key_12345")

    with pytest.raises(RuntimeError, match="AUTH_ENABLED cannot be disabled"):
        Settings()


def test_production_fails_when_allow_insecure_auth_disabled_set(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("ALLOW_INSECURE_AUTH_DISABLED", "true")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_key_12345")

    with pytest.raises(RuntimeError, match="ALLOW_INSECURE_AUTH_DISABLED cannot be enabled"):
        Settings()


def test_production_fails_when_secret_key_weak_or_short(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_key_12345")

    # Short secret
    monkeypatch.setenv("SECRET_KEY", "short_secret")
    with pytest.raises(RuntimeError, match="SECRET_KEY must be set to a secure string"):
        Settings()

    # Secret containing change-me
    monkeypatch.setenv("SECRET_KEY", "change-me-to-a-secure-string-that-is-long-enough")
    with pytest.raises(RuntimeError, match="SECRET_KEY must be set to a secure string"):
        Settings()


def test_production_fails_when_admin_key_is_default(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("ADMIN_API_KEY", "default_admin_key")

    with pytest.raises(RuntimeError, match="ADMIN_API_KEY must be set to a secure value"):
        Settings()


def test_production_fails_when_wildcard_cors_configured(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_key_12345")
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")

    with pytest.raises(RuntimeError, match="Wildcard '\\*' in ALLOWED_ORIGINS is prohibited"):
        Settings()


def test_production_defaults_cookie_secure_to_true(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_key_12345")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    s = Settings()
    assert s.COOKIE_SECURE is True


def test_development_defaults_cookie_secure_to_false(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    s = Settings()
    assert s.COOKIE_SECURE is False
