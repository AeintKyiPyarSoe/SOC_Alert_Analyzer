import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    String, Integer, Text, DateTime, ForeignKey, CheckConstraint, Uuid
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.connection import Base

class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=1)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationship to member Alerts
    alerts: Mapped[List["Alert"]] = relationship(
        secondary="incident_alerts", back_populates="incidents"
    )

    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="chk_incident_risk_score"),
        CheckConstraint("alert_count >= 1", name="chk_incident_alert_count"),
    )
