import os
import sys
from pathlib import Path

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
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{DATA_DIR / 'soc_alerts.db'}"
    )
    
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
    UPLOAD_DIR: Path = DATA_DIR / "uploads"
    CORRELATION_WINDOW_SECONDS: int = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))

settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
