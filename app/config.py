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
    if sys.platform == "win32":
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
                if user:
                    subprocess.run(
                        ["icacls", str(creds_file), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                        capture_output=True,
                        check=False
                    )
            except Exception:
                pass
    except Exception:
        pass

    return generated


class Settings:
    PROJECT_NAME: str = "SOC Alert Analyzer"
    VERSION: str = "1.2.2"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR

    # Session & Cookie Security
    SESSION_EXPIRY_SECONDS: int = int(os.getenv("SESSION_EXPIRY_SECONDS", "43200"))
    WS_TICKET_EXPIRY_SECONDS: int = int(os.getenv("WS_TICKET_EXPIRY_SECONDS", "60"))
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1", "yes")

    # Database Configuration
    _pg_user = os.getenv("POSTGRES_USER")
    _pg_pass = os.getenv("POSTGRES_PASSWORD")
    _pg_host = os.getenv("POSTGRES_HOST")
    _pg_port = os.getenv("POSTGRES_PORT", "5432")
    _pg_db = os.getenv("POSTGRES_DB")

    if _pg_user and _pg_pass and _pg_host and _pg_db:
        DATABASE_URL: str = f"postgresql://{_pg_user}:{_pg_pass}@{_pg_host}:{_pg_port}/{_pg_db}"
    else:
        DATABASE_URL: str = os.getenv(
            "DATABASE_URL",
            f"sqlite:///{DATA_DIR / 'soc_alerts.db'}"
        )

    # Security & Authentication Configuration
    AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "true").lower() in ("true", "1", "yes")
    
    # Environment secrets
    _env_secret = os.getenv("SECRET_KEY")
    _env_admin_key = os.getenv("ADMIN_API_KEY")
    _env_analyst_key = os.getenv("ANALYST_API_KEY")

    if ENVIRONMENT == "production":
        # Strict validation: require explicit non-default secrets in production
        if not _env_secret or len(_env_secret) < 32 or "change-me" in _env_secret.lower():
            raise RuntimeError(
                "CRITICAL SECURITY ERROR: SECRET_KEY must be set to a secure string (≥ 32 chars) in production."
            )
        if AUTH_ENABLED and (not _env_admin_key or "default" in _env_admin_key.lower()):
            raise RuntimeError(
                "CRITICAL SECURITY ERROR: ADMIN_API_KEY must be set to a secure value in production."
            )
        SECRET_KEY: str = _env_secret
        ADMIN_API_KEY: Optional[str] = _env_admin_key
        ANALYST_API_KEY: Optional[str] = _env_analyst_key
        FIRST_RUN_GENERATED: bool = False
    else:
        # Development / Standalone Desktop: if not set in env, auto-generate local credentials
        if not _env_secret or not _env_admin_key:
            _local_creds = _load_or_generate_local_credentials(DATA_DIR)
            SECRET_KEY: str = _env_secret or _local_creds["secret_key"]
            ADMIN_API_KEY: str = _env_admin_key or _local_creds["admin_key"]
            ANALYST_API_KEY: str = _env_analyst_key or _local_creds["analyst_key"]
            FIRST_RUN_GENERATED: bool = _local_creds.get("is_first_run", False)
        else:
            SECRET_KEY: str = _env_secret
            ADMIN_API_KEY: str = _env_admin_key
            ANALYST_API_KEY: str = _env_analyst_key or f"analyst_{secrets.token_urlsafe(16)}"
            FIRST_RUN_GENERATED: bool = False

    # Ingestion & Upload Restrictions
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))
    MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    MAX_EVENTS_PER_UPLOAD: int = int(os.getenv("MAX_EVENTS_PER_UPLOAD", "5000"))
    DB_BATCH_SIZE: int = int(os.getenv("DB_BATCH_SIZE", "250"))
    UPLOAD_DIR: Path = DATA_DIR / "uploads"
    ALLOWED_EXTENSIONS: set = {".json", ".log", ".txt", ".eve", ".xml", ".csv"}

    # Correlation Engine Configuration
    CORRELATION_WINDOW_SECONDS: int = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
    MAX_ALERTS_PER_INCIDENT: int = int(os.getenv("MAX_ALERTS_PER_INCIDENT", "1000"))

    # CORS Settings
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    ]


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

