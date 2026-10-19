import os
import sys
from pathlib import Path
from typing import List

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running inside a PyInstaller standalone bundle
    BASE_DIR = Path(sys._MEIPASS)
    # Target data dir alongside the executable
    target_data_dir = Path(sys.executable).parent
    try:
        # Test write permission for portable running
        test_file = target_data_dir / ".perm_check"
        test_file.touch()
        test_file.unlink()
        DATA_DIR = target_data_dir
    except Exception:
        # Fallback to user home directory if executable parent is read-only
        DATA_DIR = Path.home() / ".soc_alert_analyzer"
        DATA_DIR.mkdir(parents=True, exist_ok=True)
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_DIR = BASE_DIR

class Settings:
    PROJECT_NAME: str = "SOC Alert Analyzer"
    VERSION: str = "1.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR

    # Database Configuration
    # If individual POSTGRES_* environment variables are set, construct URL dynamically;
    # otherwise fallback to DATABASE_URL env var or local SQLite.
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

    # Security & Authentication
    # Default API keys can be used for local testing, but overridden in production via environment
    AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "true").lower() in ("true", "1", "yes")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "soc-insecure-secret-key-change-in-production-2026")
    ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "soc-admin-key-default-2026")
    ANALYST_API_KEY: str = os.getenv("ANALYST_API_KEY", "soc-analyst-key-default-2026")

    # Ingestion & Upload Restrictions
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))
    MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    UPLOAD_DIR: Path = DATA_DIR / "uploads"
    ALLOWED_EXTENSIONS: set = {".json", ".log", ".txt", ".eve", ".xml", ".csv"}

    # Correlation Engine Configuration
    CORRELATION_WINDOW_SECONDS: int = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))

    # CORS Settings
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    ]

settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
