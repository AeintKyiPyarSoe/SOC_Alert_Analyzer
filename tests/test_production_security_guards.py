"""
Regression tests verifying production security guards and prohibiting known default keys.
Proves that known default, placeholder, or weak keys CANNOT be used in a production deployment.
"""

import os
import pytest
from unittest.mock import patch
from app.config import Settings


def test_production_fails_when_secret_key_missing(monkeypatch):
    """Production mode must raise RuntimeError if SECRET_KEY is not set."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_production_key_length_32_plus_chars")
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set to a secure string"):
        Settings()


def test_production_fails_when_secret_key_too_short(monkeypatch):
    """Production mode must raise RuntimeError if SECRET_KEY is under 32 characters."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "too_short_secret_key")
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_production_key_length_32_plus_chars")
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set to a secure string"):
        Settings()


@pytest.mark.parametrize("prohibited_key", [
    "soc_analyzer_secret_session_key_32bytes_long",
    "soc-analyzer-super-secret-production-key-change-me",
    "generate_and_insert_a_random_32_character_secret_here",
    "insecure-test-secret-key-for-testing-only-32bytes",
    "this_secret_key_contains_change-me_flag_12345",
    "my_placeholder_secret_key_with_changeme_long",
    "my_production_default_secret_key_32_characters",
])
def test_production_fails_on_prohibited_secret_keys(monkeypatch, prohibited_key):
    """Production mode must reject known default or placeholder SECRET_KEYs."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", prohibited_key)
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_production_key_length_32_plus_chars")
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set to a secure string"):
        Settings()


@pytest.mark.parametrize("prohibited_admin_key", [
    "admin_soc_analyzer_key_secure_2026",
    "admin-prod-secret-change-in-production-minimum-32-chars",
    "admin_generate_a_strong_random_key_here",
    "admin-insecure-test-key-32chars-minimum",
    "admin_with_default_word_in_the_key_string_32",
    "admin_with_placeholder_string_32_characters_long",
])
def test_production_fails_on_prohibited_admin_keys(monkeypatch, prohibited_admin_key):
    """Production mode must reject known default or placeholder ADMIN_API_KEYs."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "production_valid_secure_secret_key_32_bytes_random_hex_abc")
    monkeypatch.setenv("ADMIN_API_KEY", prohibited_admin_key)
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="ADMIN_API_KEY must be set to a secure value"):
        Settings()


@pytest.mark.parametrize("prohibited_analyst_key", [
    "analyst_soc_analyzer_key_secure_2026",
    "analyst-prod-secret-change-in-production-minimum-32-chars",
    "analyst_generate_a_strong_random_key_here",
    "analyst-insecure-test-key-32chars-minimum",
    "analyst_with_changeme_keyword_in_string_32",
])
def test_production_fails_on_prohibited_analyst_keys(monkeypatch, prohibited_analyst_key):
    """Production mode must reject known default or placeholder ANALYST_API_KEYs."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "production_valid_secure_secret_key_32_bytes_random_hex_abc")
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_production_key_length_32_plus_chars")
    monkeypatch.setenv("ANALYST_API_KEY", prohibited_analyst_key)
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="ANALYST_API_KEY must be set to a secure value"):
        Settings()


def test_production_fails_on_duplicate_keys(monkeypatch):
    """Production mode must enforce cryptographic isolation: keys cannot be identical."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    same_key = "shared_identical_production_key_string_32_characters_length"
    monkeypatch.setenv("COOKIE_SECURE", "true")

    # Case 1: ADMIN_API_KEY == SECRET_KEY
    monkeypatch.setenv("SECRET_KEY", same_key)
    monkeypatch.setenv("ADMIN_API_KEY", same_key)
    monkeypatch.delenv("ANALYST_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ADMIN_API_KEY cannot be identical to SECRET_KEY"):
        Settings()

    # Case 2: ANALYST_API_KEY == ADMIN_API_KEY
    monkeypatch.setenv("SECRET_KEY", "production_valid_secure_secret_key_32_bytes_random_hex_abc")
    monkeypatch.setenv("ADMIN_API_KEY", same_key)
    monkeypatch.setenv("ANALYST_API_KEY", same_key)
    with pytest.raises(RuntimeError, match="ANALYST_API_KEY cannot be identical to ADMIN_API_KEY"):
        Settings()


@pytest.mark.parametrize("prohibited_db_pass", [
    "soc_secure_db_pass_2026",
    "soc_dev_local_only_insecure_db_pass",
    "replace_with_strong_database_password",
    "password",
    "postgres",
    "short_pass",
])
def test_production_fails_on_insecure_postgres_password(monkeypatch, prohibited_db_pass):
    """Production mode must reject insecure or default database passwords."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "production_valid_secure_secret_key_32_bytes_random_hex_abc")
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_production_key_length_32_plus_chars")
    monkeypatch.setenv("POSTGRES_USER", "soc_prod_user")
    monkeypatch.setenv("POSTGRES_PASSWORD", prohibited_db_pass)
    monkeypatch.setenv("POSTGRES_HOST", "db.internal")
    monkeypatch.setenv("POSTGRES_DB", "soc_prod_db")
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="POSTGRES_PASSWORD must be"):
        Settings()


def test_production_fails_when_postgres_host_has_missing_password(monkeypatch):
    """Production mode must fail when POSTGRES_HOST is configured without POSTGRES_PASSWORD."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "production_valid_secure_secret_key_32_bytes_random_hex_abc")
    monkeypatch.setenv("ADMIN_API_KEY", "admin_secure_production_key_length_32_plus_chars")
    monkeypatch.setenv("POSTGRES_HOST", "db.prod.internal")
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
    monkeypatch.setenv("COOKIE_SECURE", "true")

    with pytest.raises(RuntimeError, match="POSTGRES_PASSWORD must be configured"):
        Settings()


def test_production_succeeds_with_strong_distinct_keys(monkeypatch):
    """Production mode initializes smoothly when distinct, strong, random keys are provided."""
    import secrets
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("ADMIN_API_KEY", f"admin_{secrets.token_urlsafe(32)}")
    monkeypatch.setenv("ANALYST_API_KEY", f"analyst_{secrets.token_urlsafe(32)}")
    monkeypatch.setenv("POSTGRES_USER", "soc_prod_user")
    monkeypatch.setenv("POSTGRES_PASSWORD", secrets.token_urlsafe(24))
    monkeypatch.setenv("POSTGRES_HOST", "db.prod.internal")
    monkeypatch.setenv("POSTGRES_DB", "soc_prod_db")
    monkeypatch.setenv("COOKIE_SECURE", "true")

    s = Settings()
    assert s.ENVIRONMENT == "production"
    assert len(s.SECRET_KEY) >= 32
    assert s.ADMIN_API_KEY != s.ANALYST_API_KEY
    assert s.FIRST_RUN_GENERATED is False
