import uuid
from datetime import timedelta
from typing import List, Dict
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.security.risk_engine import RiskEngine
from app.config import settings

class IncidentCorrelator:
    """
    Correlates individual security alerts into consolidated incident cases.
    Grouping criteria:
      1. Matching Source IP (or Destination if source is absent)
      2. Matching Event Type
      3. Proximity within a sliding time window (default: 5 minutes)
    """

    @classmethod
    def correlate_alerts(cls, db: Session, window_seconds: int = None) -> List[Incident]:
        if window_seconds is None:
            window_seconds = settings.CORRELATION_WINDOW_SECONDS

        # Query all alerts sorted chronologically
        alerts = db.query(Alert).order_by(Alert.timestamp.asc()).all()
        if not alerts:
            return []

        # Find alerts that are not yet linked to an incident
        unlinked_alerts = [a for a in alerts if not a.incidents]
        if not unlinked_alerts:
            return []

        # Group by (source_ip, event_type)
        grouped: Dict[str, List[Alert]] = {}
        for alert in unlinked_alerts:
            key = f"{alert.source_ip or 'internal'}:{alert.event_type}"
            grouped.setdefault(key, []).append(alert)

        created_incidents: List[Incident] = []

        for key, group in grouped.items():
            # Sliding time-window clusters
            clusters = cls._cluster_by_time(group, timedelta(seconds=window_seconds))

            for cluster in clusters:
                # If cluster has at least 1 significant alert or multiple events
                incident = cls._create_or_merge_incident(db, cluster)
                if incident:
                    created_incidents.append(incident)

        db.commit()
        return created_incidents

    @staticmethod
    def _cluster_by_time(alerts: List[Alert], max_gap: timedelta) -> List[List[Alert]]:
        clusters = []
        if not alerts:
            return clusters

        current_cluster = [alerts[0]]
        for a in alerts[1:]:
            if a.timestamp - current_cluster[-1].timestamp <= max_gap:
                current_cluster.append(a)
            else:
                clusters.append(current_cluster)
                current_cluster = [a]
        clusters.append(current_cluster)
        return clusters

    @classmethod
    def _create_or_merge_incident(cls, db: Session, cluster: List[Alert]) -> Incident:
        first_alert = cluster[0]
        first_seen = first_alert.timestamp
        last_seen = cluster[-1].timestamp
        count = len(cluster)

        # Re-evaluate compound risk score with cluster frequency
        max_base_risk = max(a.risk_score for a in cluster)
        compound_risk, _, _ = RiskEngine.calculate_risk(
            event_type=first_alert.event_type,
            source_type=first_alert.source_type,
            frequency_count=count,
            is_external_ip=first_alert.source_ip is not None,
            is_known_attack_signature=count > 10
        )
        final_risk = max(max_base_risk, compound_risk)

        # Build Incident Title & Description
        src_label = first_alert.source_ip or "Local Host"
        clean_event = first_alert.event_type.replace("_", " ").title()
        title = f"{clean_event} Incident from {src_label}"
        
        description = (
            f"Detected {count} correlated '{first_alert.event_type}' events "
            f"originating from {src_label} between {first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} "
            f"and {last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}."
        )

        incident = Incident(
            id=uuid.uuid4(),
            title=title,
            description=description,
            risk_score=final_risk,
            mitre_technique=first_alert.mitre_technique,
            status="OPEN",
            first_seen=first_seen,
            last_seen=last_seen,
            alert_count=count
        )
        db.add(incident)
        db.flush()

        # Link alerts
        for a in cluster:
            # Update individual alert risk if cluster frequency escalated it
            if compound_risk > a.risk_score:
                a.risk_score = compound_risk
                a.severity = RiskEngine.get_severity_level(compound_risk)

            link = IncidentAlert(incident_id=incident.id, alert_id=a.id)
            db.add(link)

        return incident
