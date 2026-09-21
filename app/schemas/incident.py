import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.alert import AlertResponse

class IncidentBase(BaseModel):
    title: str
    description: str
    risk_score: int = Field(default=0, ge=0, le=100)
    mitre_technique: Optional[str] = None
    status: str = "OPEN"
    first_seen: datetime
    last_seen: datetime
    alert_count: int = 1

class IncidentCreate(IncidentBase):
    alert_ids: List[uuid.UUID] = []

class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")

class IncidentResponse(IncidentBase):
    id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class IncidentDetailResponse(IncidentResponse):
    alerts: List[AlertResponse] = []

    model_config = ConfigDict(from_attributes=True)
