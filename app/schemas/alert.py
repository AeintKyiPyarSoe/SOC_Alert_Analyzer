import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field

class AlertBase(BaseModel):
    timestamp: datetime
    source_type: str
    event_type: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    severity: str = "MEDIUM"
    risk_score: int = Field(default=0, ge=0, le=100)
    mitre_technique: Optional[str] = None
    status: str = "OPEN"
    raw_log: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")

class AlertResponse(AlertBase):
    id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class DashboardStats(BaseModel):
    total_alerts: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    open_count: int
    investigating_count: int
    resolved_count: int
    false_positive_count: int
    total_incidents: int
