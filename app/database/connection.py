import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings

logger = logging.getLogger(__name__)

# Engine configuration
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from app.models.alert import Alert
    from app.models.incident import Incident, IncidentAlert
    Base.metadata.create_all(bind=engine)

    # Lightweight migration check for existing SQLite databases
    if settings.DATABASE_URL.startswith("sqlite"):
        try:
            with engine.begin() as conn:
                # Check columns in alerts table
                res = conn.execute(text("PRAGMA table_info(alerts)")).fetchall()
                existing_cols = {row[1] for row in res}
                
                if "is_valid_timestamp" not in existing_cols and len(existing_cols) > 0:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN is_valid_timestamp BOOLEAN DEFAULT 1"))
                    logger.info("Migrated SQLite: added column 'is_valid_timestamp' to alerts.")

                if "telemetry_origin" not in existing_cols and len(existing_cols) > 0:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN telemetry_origin VARCHAR(32) DEFAULT 'HISTORICAL_LOG'"))
                    logger.info("Migrated SQLite: added column 'telemetry_origin' to alerts.")
        except Exception as e:
            logger.debug(f"Migration check skipped: {e}")
