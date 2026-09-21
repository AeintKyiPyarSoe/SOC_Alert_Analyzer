import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    String, Integer, Text, DateTime, CheckConstraint, Index, Uuid
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.connection import Base

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    raw_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationship to Incidents via junction table
    incidents: Mapped[List["Incident"]] = relationship(
        secondary="incident_alerts", back_populates="alerts"
    )

    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="chk_alert_risk_score"),
        Index("idx_alerts_correlation", "source_ip", "destination_ip", "event_type", "timestamp"),
    )
