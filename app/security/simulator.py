import asyncio
import random
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any

from app.database.connection import SessionLocal
from app.models.alert import Alert
from app.models.incident import Incident
from app.security.normalizer import AlertNormalizer
from app.security.correlator import IncidentCorrelator
from app.security.stream import stream_manager

logger = logging.getLogger(__name__)

# Pool of realistic threat templates for live streaming
SIMULATED_ATTACKS = [
    {
        "source_type": "Wazuh",
        "event_type": "ssh_authentication_failure",
        "description": "sshd: Failed SSH login attempt for user root",
        "source_ip": "185.220.101.5",
        "destination_ip": "192.168.1.10",
        "source_port": 51234,
        "destination_port": 22,
        "username": "root",
        "rule_level": 10
    },
    {
        "source_type": "Suricata",
        "event_type": "network_scan",
        "description": "ET SCAN Aggressive SYN Port Scan across range 1-1024",
        "source_ip": "194.26.29.112",
        "destination_ip": "192.168.1.10",
        "source_port": 49152,
        "destination_port": 443,
        "suricata_severity": 2
    },
    {
        "source_type": "Suricata",
        "event_type": "exploit_attempt",
        "description": "ET EXPLOIT Log4j Remote Code Execution CVE-2021-44228 JNDI lookup attempt",
        "source_ip": "45.155.205.233",
        "destination_ip": "192.168.1.10",
        "source_port": 38921,
        "destination_port": 8080,
        "suricata_severity": 1
    },
    {
        "source_type": "Linux_Auth",
        "event_type": "ssh_invalid_user",
        "description": "Failed password for invalid user 'oracle' from remote scanner",
        "source_ip": "185.220.101.5",
        "destination_ip": "192.168.1.10",
        "source_port": 51238,
        "destination_port": 22,
        "username": "oracle"
    },
    {
        "source_type": "Wazuh",
        "event_type": "suspicious_command",
        "description": "Suspicious PowerShell base64 encoded execution detected in user profile",
        "source_ip": "192.168.1.88",
        "destination_ip": "192.168.1.10",
        "source_port": 5985,
        "destination_port": 5985,
        "username": "guest",
        "rule_level": 12
    },
    {
        "source_type": "Suricata",
        "event_type": "denial_of_service",
        "description": "ET DOS Inbound SYN Flood Traffic Anomaly Exceeding Baseline",
        "source_ip": "198.51.100.99",
        "destination_ip": "192.168.1.10",
        "source_port": 80,
        "destination_port": 80,
        "suricata_severity": 1
    }
]

def generate_and_save_live_threat() -> Dict[str, Any]:
    """Generates one real-time threat, normalizes, stores, correlates, and returns broadcast payload."""
    db = SessionLocal()
    try:
        template = random.choice(SIMULATED_ATTACKS).copy()
        template["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        # Occasionally vary source port
        if "source_port" in template:
            template["source_port"] = random.randint(30000, 65000)

        # Normalize
        norm = AlertNormalizer.normalize(template)
        alert = Alert(id=uuid.uuid4(), **norm)
        db.add(alert)
        db.commit()

        # Correlate
        new_incidents = IncidentCorrelator.correlate_alerts(db)

        # Recalculate stats
        all_alerts = db.query(Alert).all()
        stats = {
            "total_alerts": len(all_alerts),
            "critical_count": sum(1 for a in all_alerts if a.severity == "CRITICAL"),
            "high_count": sum(1 for a in all_alerts if a.severity == "HIGH"),
            "medium_count": sum(1 for a in all_alerts if a.severity == "MEDIUM"),
            "low_count": sum(1 for a in all_alerts if a.severity == "LOW"),
            "open_count": sum(1 for a in all_alerts if a.status == "OPEN"),
            "investigating_count": sum(1 for a in all_alerts if a.status == "INVESTIGATING"),
            "resolved_count": sum(1 for a in all_alerts if a.status == "RESOLVED"),
            "total_incidents": db.query(Incident).count()
        }

        alert_dict = {
            "id": str(alert.id),
            "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "event_type": alert.event_type,
            "description": alert.description,
            "source_type": alert.source_type,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "mitre_technique": alert.mitre_technique,
            "status": alert.status
        }

        incidents_data = []
        for inc in new_incidents:
            incidents_data.append({
                "id": str(inc.id),
                "title": inc.title,
                "description": inc.description,
                "risk_score": inc.risk_score,
                "alert_count": inc.alert_count,
                "mitre_technique": inc.mitre_technique,
                "status": inc.status
            })

        return {
            "type": "LIVE_THREAT",
            "alert": alert_dict,
            "stats": stats,
            "new_incidents": incidents_data
        }
    finally:
        db.close()

async def live_threat_simulator_loop():
    """Background loop that emits live threats periodically to active WebSocket clients."""
    logger.info("Real-time Threat Simulator loop started.")
    # Initial sleep to let app boot
    await asyncio.sleep(5)
    
    while True:
        try:
            if stream_manager.simulation_active and stream_manager.active_connections:
                # Generate a live threat every 10 to 18 seconds
                payload = generate_and_save_live_threat()
                await stream_manager.broadcast(payload)
                logger.info(f"Broadcasted live threat: {payload['alert']['description']}")
        except Exception as e:
            logger.error(f"Error in live threat generator: {e}", exc_info=True)
            
        await asyncio.sleep(random.uniform(10.0, 16.0))
