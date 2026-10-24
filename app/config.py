import os
import sys
import json
import secrets
from pathlib import Path
from typing import List, Optional

# Determine base and writable data directories
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running inside a PyInstaller standalone bundle - resources extracted to _MEIPASS (read-only)
    BASE_DIR = Path(sys._MEIPASS)

    # Writable user data directory (never store databases or credentials in temporary _MEIPASS)
    data_dir_env = os.getenv("DATA_DIR")
    if data_dir_env:
        DATA_DIR = Path(data_dir_env)
    elif sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if local_app_data:
            DATA_DIR = Path(local_app_data) / "SOC_Alert_Analyzer"
        else:
            DATA_DIR = Path.home() / ".soc_alert_analyzer"
    else:
        DATA_DIR = Path.home() / ".soc_alert_analyzer"

    DATA_DIR.mkdir(parents=True, exist_ok=True)
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
    data_dir_env = os.getenv("DATA_DIR")
    if data_dir_env:
        DATA_DIR = Path(data_dir_env)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    else:
        DATA_DIR = BASE_DIR


def _load_or_generate_local_credentials(data_dir: Path) -> dict:
    """
    Safely loads or auto-generates cryptographically random keys for local standalone use.
    Prevents using publicly known default keys while ensuring standalone desktop portability.
    """
    creds_file = data_dir / ".auth_credentials"
    if creds_file.exists():
        try:
            with open(creds_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("admin_key") and data.get("secret_key"):
                    return data
        except Exception:
            pass

    data_dir.mkdir(parents=True, exist_ok=True)
    # Generate new random keys
    generated = {
        "admin_key": f"admin_{secrets.token_urlsafe(24)}",
        "analyst_key": f"analyst_{secrets.token_urlsafe(24)}",
        "secret_key": secrets.token_hex(32),
        "is_first_run": True
    }
    try:
        with open(creds_file, "w", encoding="utf-8") as f:
            json.dump(generated, f, indent=2)
        # Attempt to restrict file permissions on POSIX
        if hasattr(os, "chmod"):
            try:
                os.chmod(creds_file, 0o600)
            except Exception:
                pass
        # Restrict file permissions on Windows NTFS via icacls
        if sys.platform == "win32":
            try:
                import subprocess
                user = os.environ.get("USERNAME")
                domain = os.environ.get("USERDOMAIN")
                principal = f"{domain}\\{user}" if domain and user else user
                if principal:
                    subprocess.run(
                        ["icacls", str(creds_file), "/inheritance:r", "/grant:r", f"{principal}:(F)"],
                        capture_output=True,
                        check=False
                    )
            except Exception:
                pass
    except Exception:
        pass

    return generated


def load_monitoring_preferences(data_dir: Optional[Path] = None) -> dict:
    """
    Loads saved runtime monitoring preferences from the persistent application data directory.
    Precedence:
      1. Saved preference file (monitoring_preferences.json)
      2. Explicit environment variable overrides (HOST_MONITORING_ENABLED / SIMULATION_ENABLED)
      3. Secure defaults (Host Monitoring: True, Simulation: False)
    """
    target_dir = data_dir or DATA_DIR
    pref_file = target_dir / "monitoring_preferences.json"
    saved = {}
    if pref_file.exists():
        try:
            with open(pref_file, "r", encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, dict):
                    saved = content
        except Exception:
            pass

    env_host = os.getenv("HOST_MONITORING_ENABLED")
    env_sim = os.getenv("SIMULATION_ENABLED")

    host_monitoring = saved.get("host_monitoring_active")
    if host_monitoring is None:
        if env_host is not None:
            host_monitoring = env_host.lower() in ("true", "1", "yes")
        else:
            host_monitoring = True

    simulation = saved.get("simulation_active")
    if simulation is None:
        if env_sim is not None:
            simulation = env_sim.lower() in ("true", "1", "yes")
        else:
            simulation = False

    return {
        "host_monitoring_active": bool(host_monitoring),
        "simulation_active": bool(simulation)
    }


def save_monitoring_preferences(
    host_monitoring: bool,
    simulation: Optional[bool] = None,
    data_dir: Optional[Path] = None,
    raise_on_error: bool = False
) -> dict:
    """
    Atomically persists user monitoring preferences to persistent data directory.
    Guarantees state is preserved across Windows EXE restarts, local runs, and Docker volume mounts.
    Never stores sensitive credentials in this file.
    Returns dictionary with preference state, 'persisted' (bool), and 'persistence_error' (Optional[str]).
    """
    target_dir = data_dir or DATA_DIR
    pref_file = target_dir / "monitoring_preferences.json"
    temp_file = target_dir / f".monitoring_preferences_{secrets.token_hex(4)}.tmp"

    current = load_monitoring_preferences(target_dir)
    current["host_monitoring_active"] = bool(host_monitoring)
    if simulation is not None:
        current["simulation_active"] = bool(simulation)

    persisted = False
    persistence_error = None

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "host_monitoring_active": current["host_monitoring_active"],
                    "simulation_active": current["simulation_active"]
                },
                f,
                indent=2
            )
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(temp_file, pref_file)
        persisted = True
    except Exception as exc:
        persistence_error = f"{type(exc).__name__}: {str(exc)}"
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass
        if raise_on_error:
            raise

    return {
        "host_monitoring_active": current["host_monitoring_active"],
        "simulation_active": current["simulation_active"],
        "persisted": persisted,
        "persistence_error": persistence_error
    }


class Settings:
    PROJECT_NAME: str = "SOC Alert Analyzer"
    VERSION: str = "1.2.13"
    API_V1_STR: str = "/api/v1"
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR

    PROHIBITED_PRODUCTION_KEYS = {
        # Known default docker-compose keys and previous placeholders
        "soc_analyzer_secret_session_key_32bytes_long",
        "admin_soc_analyzer_key_secure_2026",
        "analyst_soc_analyzer_key_secure_2026",
        "viewer_soc_analyzer_key_secure_2026",
        "soc_secure_db_pass_2026",
        "soc_dev_local_only_insecure_db_pass",
        "soc-analyzer-super-secret-production-key-change-me",
        "admin-prod-secret-change-in-production-minimum-32-chars",
        "analyst-prod-secret-change-in-production-minimum-32-chars",
        "viewer-prod-secret-change-in-production-minimum-32-chars",
        "generate_and_insert_a_random_32_character_secret_here",
        "admin_generate_a_strong_random_key_here",
        "analyst_generate_a_strong_random_key_here",
        "replace_with_strong_database_password",
        # Common insecure / test placeholders
        "insecure-test-secret-key-for-testing-only-32bytes",
        "admin-insecure-test-key-32chars-minimum",
        "analyst-insecure-test-key-32chars-minimum",
        "admin",
        "analyst",
        "password",
        "secret",
        "changeme",
        "change-me",
        "default",
        "12345678",
        "admin123",
        "root",
        "postgres",
    }

    PROHIBITED_SUBSTRINGS = (
        "change-me",
        "changeme",
        "default",
        "placeholder",
        "test-key",
        "secret-key",
        "admin_soc_analyzer_key",
        "analyst_soc_analyzer_key",
        "soc_analyzer_secret",
        "soc_secure_db_pass",
        "replace_with_",
        "generate_a_",
    )

    def __init__(self):
        self.ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()
        _demo_mode_env = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")
        if self.ENVIRONMENT == "production" and _demo_mode_env:
            raise RuntimeError(
                "CRITICAL SECURITY ERROR: DEMO_MODE cannot be enabled when ENVIRONMENT is 'production'."
            )
        self.DEMO_MODE: bool = _demo_mode_env

        # Session & Cookie Security
        self.SESSION_EXPIRY_SECONDS: int = int(os.getenv("SESSION_EXPIRY_SECONDS", "43200"))
        self.WS_TICKET_EXPIRY_SECONDS: int = int(os.getenv("WS_TICKET_EXPIRY_SECONDS", "60"))
        _cookie_secure_env = os.getenv("COOKIE_SECURE")
        if self.ENVIRONMENT == "production":
            if _cookie_secure_env is not None and _cookie_secure_env.lower() in ("false", "0", "no"):
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: COOKIE_SECURE cannot be disabled when ENVIRONMENT is 'production'."
                )
            self.COOKIE_SECURE: bool = True
        else:
            self.COOKIE_SECURE: bool = _cookie_secure_env.lower() in ("true", "1", "yes") if _cookie_secure_env else False

        # Database Configuration
        _pg_user = os.getenv("POSTGRES_USER")
        _pg_pass = os.getenv("POSTGRES_PASSWORD")
        _pg_host = os.getenv("POSTGRES_HOST")
        _pg_port = os.getenv("POSTGRES_PORT", "5432")
        _pg_db = os.getenv("POSTGRES_DB")

        if _pg_user and _pg_pass and _pg_host and _pg_db:
            self.DATABASE_URL: str = f"postgresql://{_pg_user}:{_pg_pass}@{_pg_host}:{_pg_port}/{_pg_db}"
        else:
            self.DATABASE_URL: str = os.getenv(
                "DATABASE_URL",
                f"sqlite:///{self.DATA_DIR / 'soc_alerts.db'}"
            )

        # Security & Authentication Configuration
        self.AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "true").lower() in ("true", "1", "yes")
        self.ALLOW_INSECURE_AUTH_DISABLED: bool = os.getenv("ALLOW_INSECURE_AUTH_DISABLED", "false").lower() in ("true", "1", "yes")

        # Environment secrets
        _env_secret = os.getenv("SECRET_KEY")
        _env_admin_key = os.getenv("ADMIN_API_KEY")
        _env_analyst_key = os.getenv("ANALYST_API_KEY")

        if self.ENVIRONMENT == "production":
            # Strict validation: require explicit non-default secrets in production
            if not _env_secret or len(_env_secret) < 32:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: SECRET_KEY must be set to a secure string (≥ 32 chars) in production."
                )
            _secret_lower = _env_secret.lower()
            if _secret_lower in self.PROHIBITED_PRODUCTION_KEYS or any(sub in _secret_lower for sub in self.PROHIBITED_SUBSTRINGS):
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: SECRET_KEY must be set to a secure string (≥ 32 chars) in production (cannot use a known default or placeholder)."
                )
            if not self.AUTH_ENABLED:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: AUTH_ENABLED cannot be disabled when ENVIRONMENT is set to 'production'."
                )
            if self.ALLOW_INSECURE_AUTH_DISABLED:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: ALLOW_INSECURE_AUTH_DISABLED cannot be enabled when ENVIRONMENT is 'production'."
                )
            if not _env_admin_key or len(_env_admin_key) < 16:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: ADMIN_API_KEY must be set to a secure value in production."
                )
            _admin_lower = _env_admin_key.lower()
            if _admin_lower in self.PROHIBITED_PRODUCTION_KEYS or any(sub in _admin_lower for sub in self.PROHIBITED_SUBSTRINGS):
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: ADMIN_API_KEY must be set to a secure value in production (cannot use a known default key)."
                )
            if _env_analyst_key:
                if len(_env_analyst_key) < 16:
                    raise RuntimeError(
                        "CRITICAL SECURITY ERROR: ANALYST_API_KEY must be set to a secure value in production."
                    )
                _analyst_lower = _env_analyst_key.lower()
                if _analyst_lower in self.PROHIBITED_PRODUCTION_KEYS or any(sub in _analyst_lower for sub in self.PROHIBITED_SUBSTRINGS):
                    raise RuntimeError(
                        "CRITICAL SECURITY ERROR: ANALYST_API_KEY must be set to a secure value in production (cannot use a known default key)."
                    )
                if _env_analyst_key == _env_admin_key:
                    raise RuntimeError(
                        "CRITICAL SECURITY ERROR: ANALYST_API_KEY cannot be identical to ADMIN_API_KEY in production."
                    )
                if _env_analyst_key == _env_secret:
                    raise RuntimeError(
                        "CRITICAL SECURITY ERROR: ANALYST_API_KEY cannot be identical to SECRET_KEY in production."
                    )

            if _env_admin_key == _env_secret:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: ADMIN_API_KEY cannot be identical to SECRET_KEY in production."
                )

            # Database password validation if PostgreSQL is configured
            if _pg_host:
                if (
                    not _pg_pass
                    or len(_pg_pass) < 12
                    or _pg_pass.lower() in self.PROHIBITED_PRODUCTION_KEYS
                    or any(sub in _pg_pass.lower() for sub in self.PROHIBITED_SUBSTRINGS)
                ):
                    raise RuntimeError(
                        "CRITICAL SECURITY ERROR: POSTGRES_PASSWORD must be configured with a strong non-default password (≥ 12 chars) in production when using PostgreSQL."
                    )

            self.SECRET_KEY: str = _env_secret
            self.ADMIN_API_KEY: Optional[str] = _env_admin_key
            self.ANALYST_API_KEY: Optional[str] = _env_analyst_key
            self.FIRST_RUN_GENERATED: bool = False
        else:
            # Development / Standalone Desktop: if auth is disabled, require explicit opt-in
            if not self.AUTH_ENABLED and not self.ALLOW_INSECURE_AUTH_DISABLED:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: Disabling authentication requires explicit configuration with ALLOW_INSECURE_AUTH_DISABLED=true."
                )

            # If not set in env, auto-generate local credentials
            if not _env_secret or not _env_admin_key:
                _local_creds = _load_or_generate_local_credentials(self.DATA_DIR)
                self.SECRET_KEY: str = _env_secret or _local_creds["secret_key"]
                self.ADMIN_API_KEY: str = _env_admin_key or _local_creds["admin_key"]
                self.ANALYST_API_KEY: str = _env_analyst_key or _local_creds["analyst_key"]
                self.FIRST_RUN_GENERATED: bool = _local_creds.get("is_first_run", False)
            else:
                self.SECRET_KEY: str = _env_secret
                self.ADMIN_API_KEY: str = _env_admin_key
                self.ANALYST_API_KEY: str = _env_analyst_key or f"analyst_{secrets.token_urlsafe(16)}"
                self.FIRST_RUN_GENERATED: bool = False

        # Ingestion & Upload Restrictions
        self.MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))
        self.MAX_UPLOAD_SIZE_BYTES: int = self.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        self.MAX_EVENTS_PER_UPLOAD: int = int(os.getenv("MAX_EVENTS_PER_UPLOAD", "5000"))
        self.DB_BATCH_SIZE: int = int(os.getenv("DB_BATCH_SIZE", "250"))
        self.UPLOAD_DIR: Path = self.DATA_DIR / "uploads"
        self.ALLOWED_EXTENSIONS: set = {".json", ".log", ".txt", ".eve", ".xml", ".csv"}

        # Correlation & Deduplication Engine Configuration
        self.CORRELATION_WINDOW_SECONDS: int = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
        self.DEDUP_WINDOW_SECONDS: int = int(os.getenv("DEDUP_WINDOW_SECONDS", "300"))
        self.MAX_ALERTS_PER_INCIDENT: int = int(os.getenv("MAX_ALERTS_PER_INCIDENT", "1000"))

        # Real Host Monitoring & Demonstration Simulation Controls (hydrated from persisted preferences)
        _saved_prefs = load_monitoring_preferences(self.DATA_DIR)
        self.HOST_MONITORING_ENABLED: bool = _saved_prefs["host_monitoring_active"]
        self.SIMULATION_ENABLED: bool = _saved_prefs["simulation_active"]

        # CORS Settings: strictly configured allowed origins.
        _allowed_origins_env = os.getenv("ALLOWED_ORIGINS")
        if _allowed_origins_env:
            self.ALLOWED_ORIGINS: List[str] = [
                origin.strip() for origin in _allowed_origins_env.split(",") if origin.strip()
            ]
        else:
            self.ALLOWED_ORIGINS: List[str] = [
                "http://127.0.0.1:8000",
                "http://localhost:8000",
                "http://127.0.0.1:8080",
                "http://localhost:8080",
            ]

        if self.ENVIRONMENT == "production" and ("*" in self.ALLOWED_ORIGINS):
            raise RuntimeError(
                "CRITICAL SECURITY ERROR: Wildcard '*' in ALLOWED_ORIGINS is prohibited in production when credentials are enabled."
            )


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
