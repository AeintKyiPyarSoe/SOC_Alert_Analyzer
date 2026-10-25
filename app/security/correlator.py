import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional

def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_

from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.security.risk_engine import RiskEngine
from app.security.ip_utils import IPClassifier
from app.config import settings

class IncidentCorrelator:
    """
    Correlates individual security alerts into consolidated incident cases.
    
    Key capabilities:
      1. Efficient SQL-level filtering: processes only unlinked alerts instead of loading the entire DB.
      2. Cross-upload incident merging: merges new alerts into existing open incidents if matching
         entity signature and within the sliding correlation window.
      3. Deduplication: prevents redundant incident creation and avoids duplicate junction links.
      4. Accurate IP context: properly classifies public vs private network origins.
      5. Out-of-order timestamp resiliency: chronologically sorts alerts before time-window clustering.
    """

    @classmethod
    def correlate_alerts(cls, db: Session, window_seconds: Optional[int] = None, commit: bool = True) -> List[Incident]:
        if window_seconds is None:
            window_seconds = settings.CORRELATION_WINDOW_SECONDS

        # Query ONLY alerts that are not yet linked to any incident
        # Isolate simulated demonstration drills from genuine incident correlation
        filter_expr = [IncidentAlert.incident_id.is_(None)]
        if not settings.DEMO_MODE:
            filter_expr.append(Alert.telemetry_origin != "SIMULATED_DEMO")

        unlinked_alerts = (
            db.query(Alert)
            .outerjoin(IncidentAlert, Alert.id == IncidentAlert.alert_id)
            .filter(*filter_expr)
            .order_by(Alert.timestamp.asc())
            .all()
        )

        if not unlinked_alerts:
            return []

        # Group unlinked alerts by entity key
        # Correlate authentication sequences (failures and successes) from the same IP together
        AUTH_EVENTS = {
            "ssh_authentication_failure", "ssh_invalid_user", "ssh_login_successful",
            "windows_failed_logon", "windows_successful_logon"
        }
        grouped: Dict[str, List[Alert]] = {}
        for alert in unlinked_alerts:
            entity_ip = alert.source_ip or alert.destination_ip or "internal_host"
            if alert.event_type in AUTH_EVENTS:
                key = f"{entity_ip}:auth_sequence"
            else:
                key = f"{entity_ip}:{alert.event_type}"
            grouped.setdefault(key, []).append(alert)

        affected_incidents: Dict[uuid.UUID, Incident] = {}
        active_key_cache: Dict[str, Incident] = {}

        for key, group in grouped.items():
            clusters = cls._cluster_by_time(group, timedelta(seconds=window_seconds))

            for cluster in clusters:
                incident = cls._merge_or_create_incident(
                    db=db,
                    cluster=cluster,
                    window_seconds=window_seconds,
                    correlation_key=key,
                    active_cache=active_key_cache
                )
                if incident:
                    affected_incidents[incident.id] = incident
                    active_key_cache[key] = incident

        if commit:
            db.commit()
        else:
            db.flush()
        return list(affected_incidents.values())

    @staticmethod
    def _cluster_by_time(alerts: List[Alert], max_gap: timedelta) -> List[List[Alert]]:
        clusters = []
        if not alerts:
            return clusters

        # Chronologically sort alerts before clustering to handle out-of-order ingestion
        def _get_ts(a: Alert) -> datetime:
            return _to_utc(a.timestamp) or datetime.min.replace(tzinfo=timezone.utc)

        sorted_alerts = sorted(alerts, key=_get_ts)
        current_cluster = [sorted_alerts[0]]
        for a in sorted_alerts[1:]:
            ts_a = _get_ts(a)
            ts_prev = _get_ts(current_cluster[-1])
            if ts_a - ts_prev <= max_gap:
                current_cluster.append(a)
            else:
                clusters.append(current_cluster)
                current_cluster = [a]
        clusters.append(current_cluster)
        return clusters

    @classmethod
    def _find_matching_open_incident(
        cls,
        db: Session,
        cluster: List[Alert],
        window_seconds: int,
        correlation_key: str,
        active_cache: Optional[Dict[str, Incident]] = None
    ) -> Optional[Incident]:
        """
        Searches for an active OPEN incident matching this cluster's structured correlation key
        whose timeframe is adjacent (within window_seconds).
        """
        window_delta = timedelta(seconds=window_seconds)
        valid_ts = [_to_utc(a.timestamp) for a in cluster if a.is_valid_timestamp and a.timestamp is not None]
        cluster_start = min(valid_ts) if valid_ts else _to_utc(cluster[0].timestamp)
        cluster_end = max(valid_ts) if valid_ts else _to_utc(cluster[-1].timestamp)

        max_cap = getattr(settings, "MAX_ALERTS_PER_INCIDENT", 1000)
        if active_cache and correlation_key in active_cache:
            cached = active_cache[correlation_key]
            if cached.status == "OPEN" and cached.alert_count < max_cap:
                c_last = _to_utc(cached.last_seen)
                c_first = _to_utc(cached.first_seen)
                if (c_last is not None and cluster_start is not None and c_first is not None and cluster_end is not None and
                        c_last >= cluster_start - window_delta and c_first <= cluster_end + window_delta):
                    return cached

        first_alert = cluster[0]
        src_label = first_alert.source_ip or first_alert.destination_ip or "Local Host"
        clean_event = first_alert.event_type.replace("_", " ").title()
        expected_title_prefix = f"{clean_event} Incident"

        candidates = (
            db.query(Incident)
            .filter(
                Incident.status == "OPEN",
                Incident.alert_count < max_cap,
                or_(
                    Incident.correlation_key == correlation_key,
                    and_(
                        Incident.correlation_key.is_(None),
                        Incident.title.ilike(f"{expected_title_prefix}%"),
                        or_(
                            Incident.title.contains(src_label),
                            Incident.description.contains(src_label)
                        )
                    )
                ),
                Incident.last_seen >= cluster_start - window_delta,
                Incident.first_seen <= cluster_end + window_delta
            )
            .order_by(Incident.last_seen.desc())
            .all()
        )

        return candidates[0] if candidates else None

    @classmethod
    def _merge_or_create_incident(
        cls,
        db: Session,
        cluster: List[Alert],
        window_seconds: int,
        correlation_key: str,
        active_cache: Optional[Dict[str, Incident]] = None
    ) -> Incident:
        first_alert = cluster[0]
        
        # Separate event timestamps from ingestion timestamps:
        # Use strictly alerts with valid event timestamps to determine incident boundaries.
        valid_timestamps = [_to_utc(a.timestamp) for a in cluster if a.is_valid_timestamp and a.timestamp is not None]
        if valid_timestamps:
            cluster_first_seen = min(valid_timestamps)
            cluster_last_seen = max(valid_timestamps)
        else:
            cluster_first_seen = min(_to_utc(a.created_at) for a in cluster)
            cluster_last_seen = max(_to_utc(a.created_at) for a in cluster)

        is_external = IPClassifier.is_public_ip(first_alert.source_ip)
        existing_incident = cls._find_matching_open_incident(
            db=db,
            cluster=cluster,
            window_seconds=window_seconds,
            correlation_key=correlation_key,
            active_cache=active_cache
        )

        if existing_incident:
            # -------------------------------------------------------------
            # Merge into existing incident
            # -------------------------------------------------------------
            incident = existing_incident
            if not incident.correlation_key:
                incident.correlation_key = correlation_key

            if valid_timestamps:
                i_first = _to_utc(incident.first_seen)
                if i_first and cluster_first_seen:
                    incident.first_seen = min(i_first, cluster_first_seen)
                elif cluster_first_seen:
                    incident.first_seen = cluster_first_seen

                i_last = _to_utc(incident.last_seen)
                if i_last and cluster_last_seen:
                    incident.last_seen = max(i_last, cluster_last_seen)
                elif cluster_last_seen:
                    incident.last_seen = cluster_last_seen

            new_links = 0
            for a in cluster:
                already_linked = db.query(IncidentAlert).filter(
                    IncidentAlert.incident_id == incident.id,
                    IncidentAlert.alert_id == a.id
                ).first()
                if not already_linked:
                    db.add(IncidentAlert(incident_id=incident.id, alert_id=a.id))
                    new_links += 1

            db.flush()

            total_count = (
                db.query(func.count(IncidentAlert.alert_id))
                .filter(IncidentAlert.incident_id == incident.id)
                .scalar() or incident.alert_count + new_links
            )
            incident.alert_count = total_count

            compound_risk, _, _ = RiskEngine.calculate_risk(
                event_type=first_alert.event_type,
                source_type=first_alert.source_type,
                frequency_count=total_count,
                is_external_ip=is_external,
                is_known_attack_signature=total_count > 10
            )
            incident.risk_score = max(incident.risk_score, compound_risk)

            src_label = first_alert.source_ip or "Local Host"
            incident.description = (
                f"Detected {total_count} correlated '{first_alert.event_type}' events "
                f"originating from {src_label} between "
                f"{incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} and "
                f"{incident.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}."
            )

            for a in cluster:
                if compound_risk > a.risk_score:
                    a.risk_score = compound_risk
                    a.severity = RiskEngine.get_severity_level(compound_risk)

            return incident

        else:
            # -------------------------------------------------------------
            # Create new consolidated incident
            # -------------------------------------------------------------
            count = len(cluster)
            max_base_risk = max(a.risk_score for a in cluster)
            compound_risk, _, _ = RiskEngine.calculate_risk(
                event_type=first_alert.event_type,
                source_type=first_alert.source_type,
                frequency_count=count,
                is_external_ip=is_external,
                is_known_attack_signature=count > 10
            )
            final_risk = max(max_base_risk, compound_risk)

            src_label = first_alert.source_ip or first_alert.destination_ip or "Local Host"
            clean_event = first_alert.event_type.replace("_", " ").title()
            title = f"{clean_event} Incident from {src_label}"
            
            description = (
                f"Detected {count} correlated '{first_alert.event_type}' events "
                f"originating from {src_label} between "
                f"{cluster_first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} and "
                f"{cluster_last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}."
            )

            # Multi-stage attack evaluation: check if cluster has both authentication failures and successful login
            events_set = {a.event_type for a in cluster}
            has_auth_fail = bool(events_set & {"ssh_authentication_failure", "ssh_invalid_user", "windows_failed_logon"})
            has_auth_succ = bool(events_set & {"ssh_login_successful", "windows_successful_logon"})
            if has_auth_fail and has_auth_succ:
                final_risk = max(final_risk, 85)
                title = f"Compromised Account: Brute Force Success Incident from {src_label}"
                description = (
                    f"CRITICAL MULTI-STAGE ATTACK: Repeated authentication failures followed by successful login "
                    f"from {src_label} ({count} correlated events between "
                    f"{cluster_first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} and "
                    f"{cluster_last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')})."
                )

            incident = Incident(
                id=uuid.uuid4(),
                correlation_key=correlation_key,
                title=title,
                description=description,
                risk_score=final_risk,
                mitre_technique=first_alert.mitre_technique,
                status="OPEN",
                first_seen=cluster_first_seen,
                last_seen=cluster_last_seen,
                alert_count=count
            )
            db.add(incident)
            db.flush()

            for a in cluster:
                if compound_risk > a.risk_score:
                    a.risk_score = compound_risk
                    a.severity = RiskEngine.get_severity_level(compound_risk)

                db.add(IncidentAlert(incident_id=incident.id, alert_id=a.id))

            return incident
