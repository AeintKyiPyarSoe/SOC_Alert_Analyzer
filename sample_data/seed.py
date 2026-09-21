import os
import sys
import uuid
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Ensure UTF-8 stdout for Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.database.connection import SessionLocal, init_db
from app.models.alert import Alert
from app.parsers.wazuh import WazuhParser
from app.parsers.suricata import SuricataParser
from app.parsers.linux_auth import LinuxAuthParser
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator

def seed_database():
    print("[+] Initializing Database tables...")
    init_db()
    db = SessionLocal()

    try:
        sample_dir = BASE_DIR / "sample_data"
        
        # 1. Wazuh
        wazuh_file = sample_dir / "wazuh" / "wazuh_alerts.json"
        if wazuh_file.exists():
            print(f"[*] Ingesting sample Wazuh alerts from {wazuh_file.name}...")
            content = wazuh_file.read_text(encoding="utf-8")
            parser = WazuhParser()
            raw_events = parser.parse(content)
            for ev in raw_events:
                norm = AlertNormalizer.normalize(ev)
                alert = Alert(id=uuid.uuid4(), **norm)
                db.add(alert)

        # 2. Suricata
        suricata_file = sample_dir / "suricata" / "suricata_eve.json"
        if suricata_file.exists():
            print(f"[*] Ingesting sample Suricata events from {suricata_file.name}...")
            content = suricata_file.read_text(encoding="utf-8")
            parser = SuricataParser()
            raw_events = parser.parse(content)
            for ev in raw_events:
                norm = AlertNormalizer.normalize(ev)
                alert = Alert(id=uuid.uuid4(), **norm)
                db.add(alert)

        # 3. Linux Auth
        linux_file = sample_dir / "linux" / "auth.log"
        if linux_file.exists():
            print(f"[*] Ingesting sample Linux Auth logs from {linux_file.name}...")
            content = linux_file.read_text(encoding="utf-8")
            parser = LinuxAuthParser()
            raw_events = parser.parse(content)
            for ev in raw_events:
                norm = AlertNormalizer.normalize(ev)
                alert = Alert(id=uuid.uuid4(), **norm)
                db.add(alert)

        db.commit()
        total_alerts = db.query(Alert).count()
        print(f"[+] Successfully inserted {total_alerts} canonical alerts.")

        # Correlate
        print("[*] Correlating alerts into incidents...")
        incidents = IncidentCorrelator.correlate_alerts(db)
        print(f"[+] Successfully generated {len(incidents)} correlated security incidents!")

    except Exception as e:
        db.rollback()
        print(f"[-] Seeding error: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
